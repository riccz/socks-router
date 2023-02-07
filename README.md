# socks-router #

A CLI app for routing SOCKS5 proxy connections dynamically through different upstream proxies.
For now, the app reads and reloads a TOML config file to determine which upstream proxy to use.

Soon there will be a REST API and a Web UI to change the upstream remotely.

## Installation ##

If you have Rust installed, you can just run the following command

```sh
RUSTFLAGS="--cfg tokio_unstable" cargo install socks-router
```

## Usage ##

```sh
$socks-router --help
A dynamic router for SOCKS5 proxy requests.

Usage: socks-router [OPTIONS]

Options:
  -c, --config-path <CONFIG_PATH>  Path of the config file [env: CONFIG_PATH=] [default: ./config.toml]
  -l, --listen-addr <LISTEN_ADDR>  Address and port to listen on [env: LISTEN_ADDR=] [default: 127.0.0.1:1080]
  -h, --help                       Print help
  -V, --version                    Print version
```

## Configuration ##

The configuration is a TOML file, placed at `./config.toml` by default.
For now it just contains a single upstream, which can be edited and will be used immediately for all new proxy requests.
Open connections will be terminated if the upstream changes.

```toml
upstream_addr = "the_upstream_server.example.com:1080"
```

## License ##

This app is licensed under the MIT License.
