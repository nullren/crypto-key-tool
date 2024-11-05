extern crate core;

use base58::ToBase58;
use clap::Parser;
use k256::ecdsa::signature::digest::Digest;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use ripemd::Ripemd160;
use sha2::Sha256;
use std::error::Error;

#[derive(Parser)]
struct Args {
    #[clap(short, long)]
    private_key: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let private_key = parse_wif(&args.private_key)?;
    println!(
        "Private key: {}",
        hex::encode(private_key.private_key_bytes())
    );

    for compressed in [true, false].iter() {
        for network in [Network::Mainnet, Network::Testnet].iter() {
            let wif = private_wif_key(&private_key.private_key_bytes(), network, *compressed);
            println!(
                "Private compressed {} network {}: {}",
                compressed, network, wif
            );

            let public_address = private_key.to_public_address(*compressed, network)?;
            println!(
                "Public compressed {} network {}: {}",
                compressed, network, public_address
            );
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct PrivateKey {
    network: Network,
    compressed: bool,
    secret_key: SecretKey,
}

#[derive(Default, Debug, Clone, Eq, PartialEq, clap::ValueEnum)]
enum Network {
    #[default]
    Mainnet,
    Testnet,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet => write!(f, "testnet"),
        }
    }
}

impl TryFrom<u8> for Network {
    type Error = Box<dyn Error>;
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x80 => Ok(Network::Mainnet),
            0xef => Ok(Network::Testnet),
            _ => Err("Invalid network byte".into()),
        }
    }
}

impl Network {
    fn public_byte(&self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet => 0x6f,
        }
    }
    fn private_byte(&self) -> u8 {
        match self {
            Network::Mainnet => 0x80,
            Network::Testnet => 0xef,
        }
    }
}

impl PrivateKey {
    fn from_slice(
        network: Network,
        compressed: bool,
        bytes: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        let secret_key = SecretKey::from_slice(bytes)?;
        Ok(PrivateKey {
            network,
            compressed,
            secret_key,
        })
    }

    fn public_key_bytes(&self, compressed: bool) -> Vec<u8> {
        public_key(&self.secret_key, compressed)
    }

    fn private_key_bytes(&self) -> Vec<u8> {
        self.secret_key.to_bytes().to_vec()
    }

    fn to_public_address(
        &self,
        compressed: bool,
        network: &Network,
    ) -> Result<String, Box<dyn Error>> {
        let public_key = self.public_key_bytes(compressed);
        Ok(public_address(&public_key, network))
    }
}

fn parse_wif(wif: &str) -> Result<PrivateKey, Box<dyn Error>> {
    match base58::FromBase58::from_base58(wif) {
        Err(_) => Err("Invalid Base58 format".into()),
        Ok(bytes_b58) => {
            let bytes = bytes_b58.as_slice();
            let len = bytes.len();

            if !(37..=38).contains(&len) {
                return Err("Invalid WIF length".into());
            }

            let network = Network::try_from(bytes[0])?;
            let compressed = len == 38;

            if !verify_checksum(bytes) {
                return Err("Invalid checksum".into());
            }

            let private_key = &bytes[1..33];
            PrivateKey::from_slice(network, compressed, private_key)
        }
    }
}

fn make_checksum(data: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(Sha256::digest(data));
    hash[0..4].to_vec()
}

fn verify_checksum(data: &[u8]) -> bool {
    let computed = make_checksum(&data[0..data.len() - 4]);
    let expected = &data[data.len() - 4..data.len()];
    computed == expected
}

fn public_key(secret_key: &SecretKey, compressed: bool) -> Vec<u8> {
    let public_key = secret_key.public_key();
    public_key.to_encoded_point(compressed).as_bytes().to_vec()
}

fn public_address(public_key: &[u8], network: &Network) -> String {
    let sha256_hash = Sha256::digest(public_key);
    let ripemd_hash = Ripemd160::digest(sha256_hash);
    let mut address_bytes = vec![network.public_byte()];
    address_bytes.extend(&ripemd_hash);
    let checksum = make_checksum(&address_bytes);
    address_bytes.extend(checksum);
    address_bytes.to_base58()
}

fn private_wif_key(private_key: &[u8], network: &Network, compressed: bool) -> String {
    let mut wif_bytes = vec![network.private_byte()];
    wif_bytes.extend(private_key);
    if compressed {
        wif_bytes.push(0x01);
    }
    let checksum = make_checksum(&wif_bytes);
    wif_bytes.extend(checksum);
    wif_bytes.to_base58()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // key from https://www.freecodecamp.org/news/how-to-create-a-bitcoin-wallet-address-from-a-private-key-eca3ddd9c05f/
    fn test_convert_to_public_address() {
        let pk = PrivateKey::from_slice(
            Default::default(),
            Default::default(),
            &hex::decode("60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2")
                .unwrap(),
        )
        .unwrap();

        let public_addr = pk.to_public_address(true, &Network::Mainnet);
        assert!(public_addr.is_ok());

        let public_addr = public_addr.unwrap();
        assert_eq!(public_addr, "17JsmEygbbEUEpvt4PFtYaTeSqfb9ki1F1");
    }

    #[test]
    // generated from https://www.bitaddress.org/
    fn another_test() {
        let pk = parse_wif("KxiqmRUoydWhCLACVYF4LQnq2BX6cbRyXh3FLZnUtfrgfi4JFEQ5");
        assert!(pk.is_ok());
        let pk = pk.unwrap();

        let public_addr = pk.to_public_address(true, &Network::Mainnet);
        assert!(public_addr.is_ok());

        let public_addr = public_addr.unwrap();
        assert_eq!(public_addr, "18tWySBE6Ceu6h7zQasvkAEZGb7Cf4qVEx");
    }
}
