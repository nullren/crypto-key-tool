# crypto-key-tool

This is a simple CLI to verify Bitcoin keys and their addresses.

```
Usage: crypto-key-tool [OPTIONS] --private-key <PRIVATE_KEY>

Options:
  -p, --private-key <PRIVATE_KEY>  The private key to parse must be in either WIF format or a raw key in hex
  -c, --compressed                 Whether the public key is compressed or not
  -n, --network <NETWORK>          Which network to generate public address for [default: mainnet] [possible values: mainnet, testnet]
  -h, --help                       Print help
```
