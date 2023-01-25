# Webgw

Web gateway is intended to provide networking related components for the
ThreeFold Grid. Currently a transparent layer 4 proxy is implemented,
which uses HTTP Host header and TLS SNI extension sniffing to identify
the intended target, and proxy the connection there.

For in depth documentation, please check [the documentation
directory](./docs/). Alternatively, if you just want to get up and
running, you can continue with the quick start below.

## Getting started

You can either download the latest release of the client and server, or
build them from source.

### Building from source

#### Prerequisites

In order to build from source, you will need to have the `rust compiler`
installed. This project targets the latest stable version of rust. Older
versions might work, but are not officially supported.

#### Building

First clone this repository locally.

```sh
git clone https://github.com/threefoldtech/webgw
```

Then, standard rust compilation instructions apply

```sh
cd webgw
cargo build
```

This will create a debug build of the binaries in the `./target/debug/`
directory. As with all rust projects, you can add the `--release` flag
to create an optimized build (at the cost of increased compile times),
and add the `--target xxx` flag to cross-compile for different
architectures and/or operating systems.

#### Example setup

With a `client` and `server` binary available, you can run the project
yourself. You will also need a configuration file for the client in TOML
format, [an example one is provided](./config.toml). The following
instruction will work with this example config (and assume you have
`server` and `client` binaries in the current directory).

1. Start the server. Since the server binds port 80 and 443, it will
   require root privileges. If you do not want to do this, you can first
   add the `CAP_NET_BIND_SERVICE` capability to the binary as such:

   ```sh
   sudo setcap CAP_NET_BIND_SERVICE=+eip ./server
   ```

   Start the server (after adding capabilities, or as root user), with
   debug logging enabled

   ```sh
   ./server -d
   ```

1. Register the host (`www.example.com` in this case) on the server via
   the HTTP API. In our example config, you can see that the secret is
   actually 32 '0' characters (if you decode the hex value). When
   hashed, this turns into the hex string `"808fcd161c410acb95dcdf84c7281e9eb4d48163b8e2554d2174e30fcf01da08"`.
   If curl is available, you can add the host with the following command
   line call

   ```sh
   curl -H 'content-type: application/json' -XPOST -d '{"host":"www.example.com", "hexSecretHash":"808fcd161c410acb95dcdf84c7281e9eb4d48163b8e2554d2174e30fcf01da08"}' localhost:8080/api/v1/proxy
   ```

1. Start a server which will act as the backend service. You can use
   anything here, but for this example we will use the python http
   file server on port 10080. You can use a different port, but this
   will require a change in the example config.

   ```sh
   python3 -m http.server 10080
   ```

1. Spawn the client, which will connect to the server, and initiate a
   new proxy connection when the server identifies a new connection for
   the host (`www.example.com`)

   ```sh
   ./client -c config.toml
   ```

You are now able to connect to the server on port 80, and you'll see the
output of your chosen backend. Additionally, if your server listens for
TLS connections, you can also use those by connecting to port 443. The
example config assumes the backend listens for TLS on port 10443, though
this can be changed as desired. An example of using curl to verify the
setup

```sh
curl -H 'Host: www.example.com' localhost:80
```

If you prefer to use your browser, you can modify your host file
(`/etc/hosts` on linux), and add an entry to point `www.example.com` to
`::1`. You can then use your browser and navigate to `www.example.com`
to interact with the backend.

### Developing

Should you wish to modify or extend the current codebase, you can create
a fork, where your changes are implemented, and then create a Pull
Request to merge the changes into the project. All work should have a
tracking issue in this repo, where an issue / feature request is
described, so consensus can be reached on how the solution should be
implemented first. The eventual Pull Request should link to this
tracking issue.

#### Code style

This project aims to be implemented in idiomatic rust. Next to this,
`unsafe` code block should be avoided. If this is not possible, the
`unsafe` block must have a `SAFETY` comment on it, which explains why
the `unsafe` code is needed, and why it is valid.

All code must be formatted (`cargo fmt`). Additionally, code must pass
`clippy` validation.

```sh
cargo fmt
cargo clippy
```

Formatting can generally be done by your editor when saving a file.
Additionally, most lsp plugins can be configured to also run clippy for
additional lints.

Note that if the clippy command fails because it is not installed, you
can do so by running

```sh
rustup component add clippy
```

#### Running tests

Running tests is done in the traditional rust way

```sh
cargo test
```

Additionally, you can use [miri](https://github.com/rust-lang/miri) to
check for unsoundness. This is generally not needed, but is useful to do
should you have no other option than to write an `unsafe` code section.

```sh
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test
```


## License

This project is licensed under [the Apache 2.0 license](./LICENSE). 
