extern crate core;

use clap::Parser;
use k256::SecretKey;
use std::error::Error;
use base58::ToBase58;
use k256::ecdsa::signature::digest::Digest;
use ripemd::Ripemd160;
use sha2::Sha256;

#[derive(Parser)]
struct Args {
    #[clap(short, long)]
    private_key: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    println!("Private key: {}", args.private_key);
    Ok(())
}

fn convert_to_private_key(private_key: &str) -> Result<SecretKey, Box<dyn Error>> {
    // try as base58
    if let Ok(bytes_b58) = base58::FromBase58::from_base58(private_key) {
        let bytes = bytes_b58.as_slice();
        if bytes.len() == 37 && bytes[0] == 0x80 {
            return Ok(SecretKey::from_bytes(bytes[1..33].into())?);
        }
    }

    // try as hex
    let hex = hex::decode(private_key)?;
    let bytes = hex.as_slice();
    Ok(SecretKey::from_bytes(bytes.into())?)
}

fn convert_to_public_address(private_key: &SecretKey) -> Result<String, Box<dyn Error>> {
    let public_key = private_key.public_key();
    let sha256_hash = Sha256::digest(public_key.to_sec1_bytes());
    let ripemd_hash = Ripemd160::digest(&sha256_hash);
    
    // Add version byte (0x00 for mainnet) and compute checksum
    let mut address_bytes = vec![0x00];
    address_bytes.extend(&ripemd_hash);
    let checksum = {
        let hash = Sha256::digest(&address_bytes);
        let hash_of_hash = Sha256::digest(&hash);
        hash_of_hash[0..4].to_vec()
    };
    address_bytes.extend(checksum);

    // Encode in Base58 to get the public address
    Ok(address_bytes.to_base58())
}

mod tests {
    use super::*;

    #[test]
    fn test_convert_to_private_key() {
        let private_key = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let result = convert_to_private_key(private_key);
        assert!(result.is_ok());
        let private_key = result.unwrap();
        assert_eq!(
            hex::encode(private_key.to_bytes()),
            "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
        );
    }

    #[test]
    fn test_convert_to_public_address() {
        let private_key = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj";
        let secret_key = convert_to_private_key(private_key).unwrap();
        let result = convert_to_public_address(&secret_key);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ".to_string()
        );
    }
}
