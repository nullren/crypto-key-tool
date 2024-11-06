use crate::checksum;
use crate::network::Network;
use base58::ToBase58;
use k256::ecdsa::signature::digest::Digest;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use ripemd::Ripemd160;
use sha2::Sha256;
use std::error::Error;

/// A private key. There are a couple options specific to Bitcoin keys and how they are encoded, but
/// they're not necessariy important, ie, `network` and `compressed`. The most important bit is the
/// `secret_key` which is the actual key. Both `network` and `compressed` are only used for encoding
/// and decoding in certain situations.
#[derive(Debug, Clone)]
pub(crate) struct PrivateKey {
    network: Network,
    compressed: bool,
    secret_key: SecretKey,
}

impl PrivateKey {
    pub(crate) fn new(secret_key: SecretKey) -> Self {
        Self {
            network: Default::default(),
            compressed: Default::default(),
            secret_key,
        }
    }

    pub(crate) fn compressed(self, compressed: bool) -> Self {
        Self { compressed, ..self }
    }

    pub(crate) fn network(self, network: Network) -> Self {
        Self { network, ..self }
    }

    pub(crate) fn public_key_bytes(&self) -> Vec<u8> {
        let public_key = self.secret_key.public_key();
        public_key
            .to_encoded_point(self.compressed)
            .as_bytes()
            .to_vec()
    }

    pub(crate) fn private_key_bytes(&self) -> Vec<u8> {
        self.secret_key.to_bytes().to_vec()
    }

    pub(crate) fn public_address(&self) -> Result<String, Box<dyn Error>> {
        // this handles the "compression"
        let public_key = self.public_key_bytes();

        let mut data = vec![self.network.public_byte()];

        // hash the public key
        let hash = Sha256::digest(&public_key);
        let hash = Ripemd160::digest(hash);
        data.extend_from_slice(&hash);

        checksum::append_to(&mut data);
        Ok(ToBase58::to_base58(&*data))
    }

    pub(crate) fn private_key_wif(&self) -> String {
        let mut wif_bytes = vec![self.network.private_byte()];
        wif_bytes.extend(self.private_key_bytes());
        if self.compressed {
            wif_bytes.push(0x01);
        }
        checksum::append_to(&mut wif_bytes);
        ToBase58::to_base58(&*wif_bytes)
    }
}

pub(crate) fn parse_wif(wif: &str) -> Result<PrivateKey, Box<dyn Error>> {
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

            if !checksum::verify(bytes) {
                return Err("Invalid checksum".into());
            }

            let private_key = &bytes[1..33];
            let secret_key = SecretKey::from_slice(private_key)?;
            Ok(PrivateKey::new(secret_key)
                .compressed(compressed)
                .network(network))
        }
    }
}

pub(crate) fn parse_hex(hex: &str) -> Result<PrivateKey, Box<dyn Error>> {
    let bytes = hex::decode(hex)?;
    let secret_key = SecretKey::from_slice(&bytes)?;
    Ok(PrivateKey::new(secret_key))
}

pub(crate) fn parse_mpkf(mpkf: &str) -> Result<PrivateKey, Box<dyn Error>> {
    // verify it's a valid mini private key format
    if mpkf.len() != 30 {
        return Err("Invalid mini private key format".into());
    }
    let test = Sha256::digest(format!("{}?", mpkf));
    if test[0] != 0 {
        return Err("Invalid mini private key format".into());
    }
    let pk_bytes = Sha256::digest(mpkf);
    let secret_key = SecretKey::from_slice(&pk_bytes)?;
    Ok(PrivateKey::new(secret_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // key from https://www.freecodecamp.org/news/how-to-create-a-bitcoin-wallet-address-from-a-private-key-eca3ddd9c05f/
    fn test_convert_to_public_address() {
        let pk = parse_hex("60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2");
        assert!(pk.is_ok());

        let pk = pk.unwrap().compressed(true).network(Network::Mainnet);

        let public_addr = pk.public_address();
        assert!(public_addr.is_ok());

        let public_addr = public_addr.unwrap();
        assert_eq!(public_addr, "17JsmEygbbEUEpvt4PFtYaTeSqfb9ki1F1");
    }

    #[test]
    fn bitcoin_test() {
        let test_cases = vec![
            // generated from https://www.bitaddress.org/
            (
                "KxiqmRUoydWhCLACVYF4LQnq2BX6cbRyXh3FLZnUtfrgfi4JFEQ5",
                "18tWySBE6Ceu6h7zQasvkAEZGb7Cf4qVEx",
            ),
            // copied from https://github.com/bitcoin/bitcoin/blob/master/src/test/key_tests.cpp
            (
                "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj",
                "1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ",
            ),
            (
                "5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3",
                "1F5y5E5FMc5YzdJtB9hLaUe43GDxEKXENJ",
            ),
            (
                "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw",
                "1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs",
            ),
            (
                "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g",
                "1CRj2HyM1CXWzHAXLQtiGLyggNT9WQqsDs",
            ),
        ];

        for (wif, addr) in test_cases {
            let pk = parse_wif(wif);
            assert!(pk.is_ok());

            let pk = pk.unwrap();

            let public_addr = pk.public_address();
            assert!(public_addr.is_ok());

            let public_addr = public_addr.unwrap();
            assert_eq!(public_addr, addr);
        }
    }

    #[test]
    fn test_mini_private_key_format() {
        let pk = parse_mpkf("S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy");
        assert!(pk.is_ok());
        let pk = pk.unwrap();
        let public_addr = pk.public_address();
        assert!(public_addr.is_ok());
        assert_eq!(public_addr.unwrap(), "1CciesT23BNionJeXrbxmjc7ywfiyM4oLW");
    }
}
