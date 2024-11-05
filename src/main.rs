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

    let private_key = PrivateKey::from_wif(&args.private_key)
        .or_else(|_| PrivateKey::from_hex(&args.private_key))?;
    let public_address = private_key.to_public_address()?;
    println!("Public address: {}", public_address);
    Ok(())
}

#[derive(Debug, Clone)]
struct PrivateKey {
    network: u8,
    bytes: [u8; 32],
    compression: bool,
    secret_key: SecretKey,
}

impl PrivateKey {
    fn from_hex(bytes: &str) -> Result<Self, Box<dyn Error>> {
        let bytes = hex::decode(bytes)?;
        let bytes: [u8; 32] = bytes.as_slice().try_into()?;
        let secret_key = SecretKey::from_slice(&bytes).unwrap();
        Ok(PrivateKey {
            network: 0x80,
            bytes,
            compression: true,
            secret_key,
        })
    }

    fn from_wif(wif: &str) -> Result<Self, Box<dyn Error>> {
        if let Ok(bytes_b58) = base58::FromBase58::from_base58(wif) {
            let bytes = bytes_b58.as_slice();

            let network = bytes[0];

            let mut private_key = [0u8; 32];
            private_key.copy_from_slice(&bytes[1..33]);

            let len = bytes.len();
            let compression = len == 38;

            let mut checksum = [0u8; 4];
            checksum.copy_from_slice(&bytes[len - 4..len]);

            let checksum_hash = Sha256::digest(Sha256::digest(&bytes[0..len - 4]));
            if checksum_hash[0..4] == checksum {
                let secret_key = SecretKey::from_slice(&private_key).unwrap();
                return Ok(PrivateKey {
                    network,
                    bytes: private_key,
                    compression,
                    secret_key,
                });
            }
            return Err("Invalid checksum".into());
        }
        Err("Invalid WIF format".into())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        let public_key = self.secret_key.public_key();
        public_key
            .to_encoded_point(self.compression)
            .as_bytes()
            .to_vec()
    }

    fn network_byte(&self) -> u8 {
        match self.network {
            0x80 => 0x00,
            0xef => 0x6f,
            _ => 0x00,
        }
    }

    fn to_public_address(&self) -> Result<String, Box<dyn Error>> {
        let public_key = self.public_key_bytes();
        let sha256_hash = Sha256::digest(&public_key);
        let ripemd_hash = Ripemd160::digest(sha256_hash);
        // Add version byte (0x00 for mainnet) and compute checksum
        let mut address_bytes = vec![self.network_byte()];
        address_bytes.extend(&ripemd_hash);
        let checksum = {
            let hash = Sha256::digest(&address_bytes);
            let hash_of_hash = Sha256::digest(hash);
            hash_of_hash[0..4].to_vec()
        };
        address_bytes.extend(checksum);

        // Encode in Base58 to get the public address
        Ok(address_bytes.to_base58())
    }
}

impl From<PrivateKey> for SecretKey {
    fn from(private_key: PrivateKey) -> SecretKey {
        SecretKey::from_bytes(&(private_key.bytes).into()).unwrap()
    }
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
        assert_eq!(private_key.network, 0x80);
        assert_eq!(
            hex::encode(private_key.bytes),
            "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
        );
        assert_eq!(private_key.compression, false);
    }

    #[test]
    fn private_key_to_public_address() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let result = PrivateKey::from_wif(wif);
        assert!(result.is_ok());

        let public_key = result.unwrap().public_key_bytes();
        println!("Public key bytes: {:?}", hex::encode(public_key));
    }

    #[test]
    fn test_convert_to_public_address() {
        let pk = PrivateKey::from_hex(
            "60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2",
        )
        .unwrap();

        let public_addr = pk.to_public_address();
        assert!(public_addr.is_ok());

        let public_addr = public_addr.unwrap();
        assert_eq!(public_addr, "17JsmEygbbEUEpvt4PFtYaTeSqfb9ki1F1");
    }
}
