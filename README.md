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

Why would I want this? Well, a few reasons:
- you have a raw private key and want to know the public address
- you have a WIF key in an uncompressed format and want to convert it to a compressed format
- you have a WIF key in a compressed format and want to convert it to an uncompressed format
- you have a key for testnet and want to use it in mainnet or vice versa

Are they good reasons? Maybe not. It's not the most important piece of software.
