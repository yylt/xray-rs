
## simple listen
```
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use std::env;
use std::error::Error;
use std::process;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <port> <worker_threads>", args[0]);
        process::exit(1);
    }

    let port: u16 = args[1].parse().map_err(|e| format!("Invalid port number: {}", e))?;
    let worker_threads: usize = args[2].parse().map_err(|e| format!("Invalid worker threads count: {}", e))?;
    println!("Starting server on port {} with {} worker threads", port, worker_threads);
    
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all() 
        .build()?; 

    runtime.block_on(async {
        let address = format!("0.0.0.0:{}", port);

        let listener = match TcpListener::bind(&address).await {
            Ok(listener) => listener,
            Err(e) => {
                eprintln!("Failed to bind to {}: {}", address, e);
                return Err(e);
            }
        };
        println!("Listening on {}", address);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    println!("Accepted connection from {}", addr);
                    tokio::spawn( async move {
                        let mut buffer = vec![0; 2048]; 
                        println!("Handling client connection from {}", stream.peer_addr().unwrap());
                        loop {
                            let n = match stream.read(&mut buffer).await {
                                Ok(n) if n == 0 => {
                                    println!("Client disconnected: {}", stream.peer_addr().unwrap());
                                    return;
                                }
                                Ok(n) => n, 
                                Err(e) => {
                                    eprintln!("Failed to read from socket {}: {}", stream.peer_addr().unwrap(), e);
                                    return;
                                }
                            };
                            if let Err(e) = stream.write_all(&buffer[0..n]).await {
                                eprintln!("Failed to write to socket {}: {}", stream.peer_addr().unwrap(), e);
                                return;
                            }
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                    continue;
                }
            }
        }
        #[allow(unreachable_code)]
        Ok(())
    })?; 

    Ok(())
}
```


## simple send
```rust
use tokio::io::AsyncWriteExt; //  AsyncWriteExt for write_all
use tokio::net::TcpStream;
use std::env;
use std::process;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <host> <port>", args[0]);
        process::exit(1);
    }
    let host = &args[1];
    let port_str = &args[2];

    let port: u16 = match port_str.parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Invalid port number: {}", port_str);
            process::exit(1);
        }
    };

    let addr = format!("{}:{}", host, port);
    println!("Attempting to connect to {}", addr);

    let mut stream = match TcpStream::connect(&addr).await {
        Ok(s) => {
            println!("Successfully connected to {}", addr);
            s
        }
        Err(e) => {
            eprintln!("Failed to connect to {}: {}", addr, e);
            return Err(e.into()); 
        }
    };

    match stream.set_nodelay(true) {
        Ok(_) =>  {
            let data = b"hello world\n"; 
            match stream.write_all(data).await {
                Ok(_) => println!("Data sent successfully."),
                Err(e) => {
                    eprintln!("Failed to send data: {}", e);
                    return Err(e.into());
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to set TCP_NODELAY: {}", e);
            return Err(e.into());
        }
    }

    match stream.shutdown().await {
        Ok(_) => println!("Connection shut down."),
        Err(e) => eprintln!("Failed to shut down connection: {}", e),
    }

    Ok(()) 
}
```