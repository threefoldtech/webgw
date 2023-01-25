# Web gateway client config

This is an overview of the configuration file used by the web gateway
`client`. [An example is present in the root of the repository](../config.toml).
The config file is in the `TOML` format. Every component has its own
section. Currently there is only the `web proxy`.

## Web proxy

The web proxy configuration is available under the `proxy` key and has 2
fields: the `port_map` list and the `proxies` list.

- `port_map`: This is an _optional_ list of port translations. When a
  connection is identified on the server, it will add the local port of
  the server to the info send to the client. If this list is empty or
  not set, the client will attempt to connect to this port on localhost,
  i.e. it will connect to port 80 for HTTP connections and 443 for TLS
  connections. If an entry is set in the port map, the client will
  override the port to the one specified in the config. This allows a
  remap of ports. This can be useful for debugging/development, as
  otherwise the client would connect to the server again and create an
  endless loop. Additionally, this allows uses to start backend server
  on higher port numbers, which don't require root privilege to bind.
  Thus, with a port map, it is possible to setup a client and backend
  without requiring root access at any stage.

  A port map entry is an object with 2 fields: `proxy_port`, which
  denotes the port on the proxy server on which the connection was
  received, and `local_port`, which denotes the port on the local
  machine to which the client should connect.

  ```toml
  [[proxy.port_map]]
  proxy_port = 80
  local_port = 10080
  ```

  The above example will proxy a connection which came in on port 80 on
  the server, and forward it to port 10080 on the localhost

- `proxies`: A list of webgw `servers` to connect to, and the host along
  with the hex encoded secret (for authentication) to subscribe for on
  that server. Every entry in the list corresponds to 1 subscription on
  1 `server`. If you wish to connect to the same host, with the same
  secret, on 2 `servers`, you will need to add an individual entry for
  each `server`. Likewise, if you wish to proxy 2 hosts from the same
  `server`, you will need to add an individual entry for each host.

  An entry has 3 fields: `host`, which is the domain name for which to
  proxy, `hex_secret`, which is the hex encoded secret for the domain,
  and `address`, which is the IP and port of the `server`. Note that the
  port here is the port the server is listening on for the `core
  protocol` ([documented here](./core_protocol.md)). The port the
  `client` needs to connect to for proxy connections is send as part of
  the notification the `server` sends when a new connection is received,
  so this does not need to be known up front and can change (potentially
  while running)

  ```toml
  [[proxy.proxies]]
  host = "www.example.com"
  hex_secret = "3030303030303030303030303030303030303030303030303030303030303030"
  address = "127.0.0.1:9080"
  ```

  The above example will cause the `client` to connect to a `server` running
  on the same host, listening for protocol connections on port 9080. The
  `client` will then subscribe for connections coming in on the server
  for host `www.example.com`, and will provide the given `secret` to the
  server, which has the hashed version of this secret configured, to
  authenticate itself
