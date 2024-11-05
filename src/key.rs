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
    fn new(secret_key: SecretKey) -> Self {
        Self {
            network: Default::default(),
            compressed: Default::default(),
            secret_key,
        }
    }

    fn compressed(self, compressed: bool) -> Self {
        Self { compressed, ..self }
    }

    fn network(self, network: Network) -> Self {
        Self { network, ..self }
    }

    fn public_key(&self) -> Vec<u8> {
        let public_key = self.secret_key.public_key();
        public_key
            .to_encoded_point(self.compressed)
            .as_bytes()
            .to_vec()
    }

    pub(crate) fn private_key(&self) -> Vec<u8> {
        self.secret_key.to_bytes().to_vec()
    }

    fn public_address(&self) -> Result<String, Box<dyn Error>> {
        // this handles the "compression"
        let public_key = self.public_key();

        let mut data = vec![self.network.public_byte()];

        // hash the public key
        let hash = Sha256::digest(&public_key);
        let hash = Ripemd160::digest(&hash);
        data.extend_from_slice(&hash);

        checksum::append_to(&mut data);
        Ok(ToBase58::to_base58(&*data))
    }

    fn export_private_wif_key(self) -> String {
        let mut wif_bytes = vec![self.network.private_byte()];
        wif_bytes.extend(self.private_key());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Network;

    #[test]
    // key from https://www.freecodecamp.org/news/how-to-create-a-bitcoin-wallet-address-from-a-private-key-eca3ddd9c05f/
    fn test_convert_to_public_address() {
        let key_bytes =
            hex::decode("60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2")
                .unwrap();
        let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
        let pk = PrivateKey::new(secret_key)
            .compressed(true)
            .network(Network::Mainnet);

        let public_addr = pk.public_address();
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

        let public_addr = pk.public_address();
        assert!(public_addr.is_ok());

        let public_addr = public_addr.unwrap();
        assert_eq!(public_addr, "18tWySBE6Ceu6h7zQasvkAEZGb7Cf4qVEx");
    }
}
