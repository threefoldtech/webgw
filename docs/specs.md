# Idea

The project is intended to have a `server` and a `client` part. Servers will be
run on the grid, on public nodes (automatically as part of zos). Clients can be
run everywhere, and will primarily be run in (non-public) workloads.

The aim is to support multiple distinct pieces of functionality in the future,
which may or may not be present in both client and server.

## Architecture

Since all components should be relatively separated from one another, they can be
easily modularized, and in the future potential builds could conditionally only implement
required features. This would require a dynamic modular approach in the
implementation, where components are dynamically registered at runtime. Since the
first iteration will not have a lot of functionality, we will leave the dynamic registration
to a later date, and for now work with static full capability only binaries.

### Core

The core will be responsible for communication between entities (where an entity
is either a client or a server). It will also handle API connectivity (where needed).

Ideally the connection between entities would be encrypted. This has 2 potential
candidates, TLS and Noise. Both are not really ideal in this stage. TLS requires
a domain name and certificate serving, while Noise requires some kind of public
key. As such, in this stage we will leave the encryption part out, and use plaintext
connections. No sensitive data should be transmitted on these connections anyway.

Considering data transmission on this connection should be low, it is not necessary
to implement a compact binary format. Therefore, for ease of development and debugging,
as well as interoperability, we will implement communication as JsonRPC over websockets.
Commands of individual modules will be namespaced so that they can later easily be
separated if the application structure is modularized.

### Socket proxy

A tcp proxy module for the web. Through the API, a secret is registered with a
port on the server. A client can connect to the server, and authenticate itself
with the secret. Once a connection comes in, it is sniffed to detect the intended
host, and if one is connected to the server, the server requests a _new_ connection
from the client with an ephemeral secret and the destination port. The client opens
a new connection to the server, sends the secret, and then proxies the incoming data
to the correct local port (and proxies the outgoing data through the same connection).

Overview:

- The server listens on port 80 and 443.
- API is used to register a tuple (`host`, `secret`)
- Client connects to server, sending a subscription command with `secret`.
- New connection comes in on the server on either port. The server identifies
the target host by sniffing the connection.
  - For port 80, HTTP headers are parsed looking for the value of the `host` header.
  - For port 443, the TLS client hello is extracted to identify the `SNI` value.
- If the host is not known, or no client has subscribed for this host, the connection
is immediately closed.
- Otherwise, a notification is sent for the subscription, with a generated ephemeral
secret and the port number for the original connection (on the server).
The port on which the server is listening for client connection is also
included (so that we don't need a static port or to configure this in the
client, and the server can swap these at random).
- The client receives the notification, connects to the server, and sends the ephemeral
secret.
- The client opens a connection to the local port as specified in the notification
- The client starts a bidirectional copy of the 2 connections.
- The server reads the secret from the new client connection. If the secret is not
known, the connection is closed.
- The server sends its internal buffer on the client connection, and then starts
a bidirectional copy of the outside connection and the client connection.

The ephemeral secret will be fixed a fixed 32 bytes.
