# Core protocol

The core protocol is used by 2 instances to communicate. The protocol
itself is [JSON-RPC 2.0] over websockets. The default listening port for
protocol connections is `9080`. A node which is offering some
functionality will be listening for incoming protocol connections, while
a consumer of this functionality will connect to a node. For this
document, we will consider 2 entities communicating. There is the node
which listens for incoming connections, which we will denote as the
`server`, and the node which connects to the previously mentioned node,
which we will denote as the `client`. All communication in the protocol
is initiated by the `client`, and the `server` can only initiate a message
send if the `client` previously subscribed for something on the
`server`.

Note that future additions might make require nodes which act as
`server`s to communicate with one another. In this scenario, both nodes
can connect to the others listening port, effectively making both nodes
both a `server` and a `client`.

## Web proxy

### webgw_registerClient

This is a `subsription` which registers the `client` with the `server` for
the given host and with the provided `secret`. The `secret` is an arbitrary
byte sequence at **least 32 bytes and at most 256 bytes long**. The `secret`
is transmitted as a hex encoded string. On the `server`, the `secret` will
be hashed with `SHA256` (256bit digest). This hashed value must
match the value on the server, or the subscription will be rejected.
Arguments are passed as a map.

#### Arguments

`Host` is the url to listen on in plain form (string), hex_secret is the
hex encoded secret in string form.

```javascript
{
    "host": "www.example.com",
    "hex_secret": "3030303030303030303030303030303030303030303030303030303030303030" 
}
```

#### Returns

On success, a result field is returned which will contain a subscription
`ID`. This `ID` will be passed along with all notifications sent for
this subscription. The type of the `ID` is an implementation detail and
might change in the future.

```javascript
"result": 65464186186
```

#### Subscription item

If the subscription is accepted, the `server` will send a notification
to the `client` for every new connection it receives which is identified
as being for the given host.

The notification contains the port on which the remote connected, the
port on which the client should connect, and an ephemeral secret which
the client must send on the connection so the server can identify the
connection.

The secret is received in hex encoded form, but must be send on the
connection in it's raw byte representation (i.e. it must be hex
encoded). The secret has a fixed size of 32 bytes (64 bytes hex
encoded).

```javascript
{
    "subscription": 65464186186,
    "params": {
        "secret": "371df9d1ac6192c4a2865939101500abdc6397939585ac181442ec166c2453f4", // Hex encoded secret which must be send on the connection
        "port": 80, // port number the remote connected on
        "serverListeningPort": 4658, // Port on which the server listens and to which we need to connect the new proxy connection.
    }
}
```

#### Errors

This subscription defines the following custom error codes, in addition
to the standard reserved error codes defined in [JSON-RPC 2.0]:

- -20000: The specified host name is not registered on the `server`
- -20001: The specified host name is registered, but the secret is wrong

#### Example

```javascript
// Open subscription (client -> server)
{"jsonrpc": "2.0", "method": "webgw_registerClient", "params": {"host": "www.example.com", "hex_secret": "3030303030303030303030303030303030303030303030303030303030303030"}, "id": 1}
// Subscription success result (server -> client)
{"jsonrpc":"2.0","result":6524412139850853,"id":1}
// Notification for new connection (server -> client)
{"jsonrpc":"2.0","method":"webgw_registerClient","params":{"subscription":6524412139850853,"result":{"secret":"371df9d1ac6192c4a2865939101500abdc6397939585ac181442ec166c2453f4","port":80,"serverListeningPort":4658}}}
```

[JSON-RPC 2.0]: https://www.jsonrpc.org/specification
