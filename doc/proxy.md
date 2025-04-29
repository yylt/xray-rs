# reverse

## introduction

- outbount establish with remote inbound, after that, remote inbound should listen on port which outbound required.

- traffic flow: remote inbound ---(mux/L7 protocol?)--> local outbound -> local/remote host

# forward

## introduction

- inbount listen on port, which is proxy protocol, like socks5/http, etc.

- traffic flow: local inbound ---> remote outbound -> destination host
