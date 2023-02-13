# socks-router #

A CLI app for routing SOCKS5 proxy connections dynamically through different upstream proxies.
For now, the app uses a single upstream that can be changed via a REST API.

Soon there will also be a Web UI to use the REST API more easily.

## Installation ##

If you have Rust installed, you can just run the following command

```sh
cargo install socks-router
```

## Usage ##

```sh
$socks-router --help
A dynamic router for SOCKS5 proxy requests.

Usage: socks-router [OPTIONS]

Options:
  -c, --config-path <CONFIG_PATH>
          Path of the static config file [env: SOCKS_ROUTER_CONFIG_PATH=]
  -l, --listen <LISTEN>
          Address and port to listen on [env: SOCKS_ROUTER_LISTEN=]
  -v, --log-level <LOG_LEVEL>
          Logging level [env: SOCKS_ROUTER_LOG_LEVEL=]
  -d, --dyn-config-path <DYN_CONFIG_PATH>
          Path of the dynamic config [env: SOCKS_ROUTER_DYN_CONFIG_PATH=]
  -a, --api-listen <API_LISTEN>
          Address and port for the API to listen on [env: SOCKS_ROUTER_API_LISTEN=]
  -h, --help
          Print help
  -V, --version
          Print version
```

## Configuration ##

There are two TOML configuration files:

- The one set by `--config-path` is optional and can be used to set the same
  arguments as the CLI. See [`config.example.toml`](/config.example.toml) for an
  example.
- The other one, set by `--dyn-config-path` is mandatory and contains a list of
  upstreams and the choice of which one to use. This file will be updated
  automatically when the configuration changes via the API. See
  [`dynconfig.example.toml`](/dynconfig.example.toml) for an example.

## License ##

This app is licensed under the MIT License.
