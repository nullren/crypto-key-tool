use clap::Parser;
use k256::SecretKey;
use std::error::Error;

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

fn convert_to_public_address(_private_key: &SecretKey) -> Result<String, Box<dyn Error>> {
    todo!()
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
