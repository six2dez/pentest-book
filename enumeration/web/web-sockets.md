# Web Sockets

```text
WebSockets are a bi-directional, full duplex communications protocol initiated over HTTP. They are commonly used in modern web applications for streaming data and other asynchronous traffic.

WebSocket connections are normally created using client-side JavaScript like the following:
var ws = new WebSocket("wss://normal-website.com/chat");

To establish the connection, the browser and server perform a WebSocket handshake over HTTP. The browser issues a WebSocket handshake request like the following:
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket

If the server accepts the connection, it returns a WebSocket handshake response like the following:
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=

Several features of the WebSocket handshake messages are worth noting:
• The Connection and Upgrade headers in the request and response indicate that this is a WebSocket handshake.
• The Sec-WebSocket-Version request header specifies the WebSocket protocol version that the client wishes to use. This is typically 13.
• The Sec-WebSocket-Key request header contains a Base64-encoded random value, which should be randomly generated in each handshake request.
• The Sec-WebSocket-Accept response header contains a hash of the value submitted in the Sec-WebSocket-Key request header, concatenated with a specific string defined in the protocol specification. This is done to prevent misleading responses resulting from misconfigured servers or caching proxies.
```

