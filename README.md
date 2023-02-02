Masquerade is an implementation of [MASQUE](https://ietf-wg-masque.github.io/). For UDP, it implements the `connect-udp` extended HTTP/3 CONNECT method as defined in [RFC 9228](https://www.rfc-editor.org/rfc/rfc9298.html) using QUIC datagrams defined in [RFC 9227](https://www.rfc-editor.org/rfc/rfc9297.html). For TCP, it implements the HTTP/3 CONNECT method as defined in [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html#name-the-connect-method).

For client, it exposes a HTTP/1.1 or SOCKS5 interface for easy connection.

It is built on HTTP/3 and QUIC provided by the library [quiche](https://github.com/cloudflare/quiche).

Very early prototype with no thorough testing, missing a lot of features, poorly documented, and very poor error and edge case handling.

## Examples

Server:
```
# host server on interface with IP 192.168.1.2 port 4433
$ cargo run --bin server -- 192.168.1.2:4433
```

Client: 
```
# connect to server at 192.168.1.2:4433 and host HTTP/1.1 server on localhost port 8989
$ cargo run --bin client -- 192.168.1.2:4433 127.0.0.1:8989 http

# or host a socks server
$ cargo run --bin client -- 192.168.1.2:4433 127.0.0.1:8989 socks
```

