use crate::transport::TrStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 双向转发器，支持零拷贝优化
pub struct StreamForwarder;

impl Default for StreamForwarder {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamForwarder {
    pub fn new() -> Self {
        Self
    }

    pub fn forward<'a>(
        &'a self,
        mut local: TrStream,
        mut remote: TrStream,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<(u64, u64)>> + Send + 'a>> {
        Box::pin(async move {
            let result = if let (TrStream::Tcp(local_tcp), TrStream::Tcp(remote_tcp)) = (&mut local, &mut remote) {
                forward_tcp(local_tcp, remote_tcp).await
            } else {
                forward_streams(&mut local, &mut remote).await
            };
            let _ = local.shutdown().await;
            let _ = remote.shutdown().await;
            result
        })
    }
}

async fn forward_streams(local: &mut TrStream, remote: &mut TrStream) -> std::io::Result<(u64, u64)> {
    let mut local_to_remote = 0u64;
    let mut remote_to_local = 0u64;
    let mut local_buf = [0u8; 8192];
    let mut remote_buf = [0u8; 8192];
    let mut local_open = true;
    let mut remote_open = true;

    loop {
        if !local_open && !remote_open {
            return Ok((local_to_remote, remote_to_local));
        }

        tokio::select! {
            result = local.read(&mut local_buf), if local_open => {
                let n = result?;
                if n == 0 {
                    local_open = false;
                    let _ = remote.shutdown().await;
                } else {
                    remote.write_all(&local_buf[..n]).await?;
                    local_to_remote += n as u64;
                }
            }
            result = remote.read(&mut remote_buf), if remote_open => {
                let n = result?;
                if n == 0 {
                    remote_open = false;
                    let _ = local.shutdown().await;
                } else {
                    local.write_all(&remote_buf[..n]).await?;
                    remote_to_local += n as u64;
                }
            }
        }
    }
}

async fn forward_tcp(
    local: &mut tokio::net::TcpStream,
    remote: &mut tokio::net::TcpStream,
) -> std::io::Result<(u64, u64)> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return zerocopy_bidirectional(local, remote).await;
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        tokio_copy_bidirectional(local, remote).await
    }
}

#[allow(dead_code)]
async fn tokio_copy_bidirectional(
    local: &mut tokio::net::TcpStream,
    remote: &mut tokio::net::TcpStream,
) -> std::io::Result<(u64, u64)> {
    let mut local_to_remote = 0u64;
    let mut remote_to_local = 0u64;
    let mut local_buf = [0u8; 8192];
    let mut remote_buf = [0u8; 8192];
    let mut local_open = true;
    let mut remote_open = true;

    loop {
        if !local_open && !remote_open {
            return Ok((local_to_remote, remote_to_local));
        }

        tokio::select! {
            result = local.read(&mut local_buf), if local_open => {
                let n = result?;
                if n == 0 {
                    local_open = false;
                    let _ = remote.shutdown().await;
                } else {
                    remote.write_all(&local_buf[..n]).await?;
                    local_to_remote += n as u64;
                }
            }
            result = remote.read(&mut remote_buf), if remote_open => {
                let n = result?;
                if n == 0 {
                    remote_open = false;
                    let _ = local.shutdown().await;
                } else {
                    local.write_all(&remote_buf[..n]).await?;
                    remote_to_local += n as u64;
                }
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
async fn zerocopy_bidirectional(
    local: &mut tokio::net::TcpStream,
    remote: &mut tokio::net::TcpStream,
) -> std::io::Result<(u64, u64)> {
    use std::os::unix::io::AsRawFd;
    use tokio::io::Interest;

    let (pipe_lr_read, pipe_lr_write) = create_pipe()?;
    let (pipe_rl_read, pipe_rl_write) = create_pipe()?;

    let local_fd = local.as_raw_fd();
    let remote_fd = remote.as_raw_fd();

    let local_to_remote = async {
        let mut total = 0u64;
        loop {
            let n = loop {
                local.ready(Interest::READABLE).await?;

                match local.try_io(Interest::READABLE, || {
                    let n = unsafe {
                        libc::splice(
                            local_fd,
                            std::ptr::null_mut(),
                            pipe_lr_write,
                            std::ptr::null_mut(),
                            65536,
                            libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                        )
                    };

                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n)
                    }
                }) {
                    Ok(n) => break n,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(err) => return Err(err),
                }
            };

            if n == 0 {
                let _ = unsafe { libc::shutdown(remote_fd, libc::SHUT_WR) };
                break;
            }

            let mut spliced = 0;
            while spliced < n {
                let m = loop {
                    remote.ready(Interest::WRITABLE).await?;

                    match remote.try_io(Interest::WRITABLE, || {
                        let m = unsafe {
                            libc::splice(
                                pipe_lr_read,
                                std::ptr::null_mut(),
                                remote_fd,
                                std::ptr::null_mut(),
                                (n - spliced) as usize,
                                libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                            )
                        };

                        if m < 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(m)
                        }
                    }) {
                        Ok(m) => break m,
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(err) => return Err(err),
                    }
                };

                if m == 0 {
                    return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "write zero bytes"));
                }

                spliced += m;
            }

            total += n as u64;
        }
        Ok::<u64, std::io::Error>(total)
    };

    let remote_to_local = async {
        let mut total = 0u64;
        loop {
            let n = loop {
                remote.ready(Interest::READABLE).await?;

                match remote.try_io(Interest::READABLE, || {
                    let n = unsafe {
                        libc::splice(
                            remote_fd,
                            std::ptr::null_mut(),
                            pipe_rl_write,
                            std::ptr::null_mut(),
                            65536,
                            libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                        )
                    };

                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n)
                    }
                }) {
                    Ok(n) => break n,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(err) => return Err(err),
                }
            };

            if n == 0 {
                let _ = unsafe { libc::shutdown(local_fd, libc::SHUT_WR) };
                break;
            }

            let mut spliced = 0;
            while spliced < n {
                let m = loop {
                    local.ready(Interest::WRITABLE).await?;

                    match local.try_io(Interest::WRITABLE, || {
                        let m = unsafe {
                            libc::splice(
                                pipe_rl_read,
                                std::ptr::null_mut(),
                                local_fd,
                                std::ptr::null_mut(),
                                (n - spliced) as usize,
                                libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                            )
                        };

                        if m < 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(m)
                        }
                    }) {
                        Ok(m) => break m,
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(err) => return Err(err),
                    }
                };

                if m == 0 {
                    return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "write zero bytes"));
                }

                spliced += m;
            }

            total += n as u64;
        }
        Ok::<u64, std::io::Error>(total)
    };

    let result = tokio::try_join!(local_to_remote, remote_to_local);

    unsafe {
        libc::close(pipe_lr_read);
        libc::close(pipe_lr_write);
        libc::close(pipe_rl_read);
        libc::close(pipe_rl_write);
    }

    result
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
async fn zerocopy_bidirectional(
    local: &mut tokio::net::TcpStream,
    remote: &mut tokio::net::TcpStream,
) -> std::io::Result<(u64, u64)> {
    tokio_copy_bidirectional(local, remote).await
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn create_pipe() -> std::io::Result<(i32, i32)> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn test_stream_forwarder_basic() {
        let (stream1, mut peer1) = tcp_pair().await;
        let (stream2, mut peer2) = tcp_pair().await;

        let forwarder = StreamForwarder::new();
        let forward_task =
            tokio::spawn(async move { forwarder.forward(TrStream::Tcp(stream1), TrStream::Tcp(stream2)).await });

        peer1.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        peer2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        peer2.write_all(b"pong").await.unwrap();
        peer1.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        drop(peer1);
        drop(peer2);
        let _ = forward_task.await.unwrap();
    }

    #[test]
    fn test_zerocopy_availability() {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            println!("Zero-copy is available on this platform");
        }

        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            println!("Zero-copy is NOT available, will fallback to user-space copy");
        }
    }
}
