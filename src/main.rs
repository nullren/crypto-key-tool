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
    println!("Private key: {}", args.private_key);

    let private_key = PrivateKey::from_wif(&args.private_key)?;
    let public_address = private_key.to_public_address()?;
    println!("Public address: {}", public_address);
    Ok(())
}

#[derive(Debug, Clone)]
struct PrivateKey {
    network: Network,
    compressed: bool,
    secret_key: SecretKey,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum Network {
    Mainnet,
    Testnet,
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

impl From<Network> for u8 {
    fn from(network: Network) -> u8 {
        match network {
            Network::Mainnet => 0x00,
            Network::Testnet => 0x6f,
        }
    }
}

impl PrivateKey {
    fn from_bytes(
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

    fn from_wif(wif: &str) -> Result<Self, Box<dyn Error>> {
        if let Ok(bytes_b58) = base58::FromBase58::from_base58(wif) {
            let bytes = bytes_b58.as_slice();
            let len = bytes.len();

            if !(37..=38).contains(&len) {
                return Err("Invalid WIF length".into());
            }
            let compressed = len == 38;
            let network = bytes[0].try_into()?;
            let private_key = &bytes[1..33];
            let checksum = &bytes[len - 4..len];

            let checksum_hash = Sha256::digest(Sha256::digest(&bytes[0..len - 4]));
            if &checksum_hash[0..4] == checksum {
                return Self::from_bytes(network, compressed, private_key);
            }
            return Err("Invalid checksum".into());
        }
        Err("Invalid Base58 format".into())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        public_key(&self.secret_key, self.compressed)
    }

    fn to_public_address(&self) -> Result<String, Box<dyn Error>> {
        let public_key = self.public_key_bytes();
        Ok(public_address(&public_key, self.network.clone()))
    }
}

fn public_key(secret_key: &SecretKey, compressed: bool) -> Vec<u8> {
    let public_key = secret_key.public_key();
    public_key.to_encoded_point(compressed).as_bytes().to_vec()
}

fn public_address(public_key: &[u8], network: Network) -> String {
    let sha256_hash = Sha256::digest(public_key);
    let ripemd_hash = Ripemd160::digest(sha256_hash);
    let mut address_bytes = vec![network.into()];
    address_bytes.extend(&ripemd_hash);
    let checksum = {
        let hash = Sha256::digest(&address_bytes);
        let hash_of_hash = Sha256::digest(hash);
        hash_of_hash[0..4].to_vec()
    };
    address_bytes.extend(checksum);
    address_bytes.to_base58()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_from_wif() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let result = PrivateKey::from_wif(wif);
        assert!(result.is_ok());
        let private_key = result.unwrap();
        assert_eq!(private_key.network, Network::Mainnet);
        assert_eq!(private_key.compressed, false);
    }

    #[test]
    // key from https://www.freecodecamp.org/news/how-to-create-a-bitcoin-wallet-address-from-a-private-key-eca3ddd9c05f/
    fn test_convert_to_public_address() {
        let pk = PrivateKey::from_bytes(
            Network::Mainnet,
            true,
            &hex::decode("60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2")
                .unwrap(),
        )
        .unwrap();

        let public_addr = pk.to_public_address();
        assert!(public_addr.is_ok());

        let public_addr = public_addr.unwrap();
        assert_eq!(public_addr, "17JsmEygbbEUEpvt4PFtYaTeSqfb9ki1F1");
    }

    #[test]
    // generated from https://www.bitaddress.org/
    fn another_test() {
        let pk = PrivateKey::from_wif("KxiqmRUoydWhCLACVYF4LQnq2BX6cbRyXh3FLZnUtfrgfi4JFEQ5");
        assert!(pk.is_ok());
        let pk = pk.unwrap();

        let public_addr = pk.to_public_address();
        assert!(public_addr.is_ok());

        let public_addr = public_addr.unwrap();
        assert_eq!(public_addr, "18tWySBE6Ceu6h7zQasvkAEZGb7Cf4qVEx");
    }
}
