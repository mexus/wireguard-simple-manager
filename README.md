# Wireguard simple manager

A very, very simple wireguard manager that keeps track of peers and their
metainformation for Linux.

## Usage

Root permissions are required to access the wireguard driver, so run the tool
as a root.

This tool doesn't provide any kind of layer on top of the wireguard, and it
only accesses the wireguard kernel driver to add/remove/list peers.

The tool is meant to be run on a "server", though no hard restrictions are
applied. It just won't make much sense to run the tool on a "client" side.

Sine the wireguard itself is not capable of storing any peers meta information
(like name/comments/...), the meta is stored in a separate file, specified by
the `peers` configuration parameter.

When run for the first time, please populate the peers TOML file manually,
otherwise the results might be unreliable.

The main configuration is a simple TOML (`config.toml` by default) with the
following fields:

```toml
# How peers can access this endpoint.
external_address = "vpn.example.com"
external_port = 7031

# Human-readable name of the VPN.
name = "Home Network"

# Path to the peers TOML file.
peers = "peers.toml"

# Wireguard interface operating the VPN.
interface = "wg0"

# Network mask of the VPN
network_mask = "10.0.0.0/16"
```

The peers TOML file is nothing more than a list of peers in the following
format:

```toml
["base64-encoded peer public key"]
# Full name of the peer. Might be a person's name, or a descriptive name of the
# machine.
name = "John Smith"
# Optional comment.
comment = "at home"
# Designated IP address.
ip = "10.17.0.2"
```

For manipulations with the peers please refer to the built-in help.
