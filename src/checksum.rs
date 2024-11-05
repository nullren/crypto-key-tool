use k256::ecdsa::signature::digest::Digest;
use sha2::Sha256;

fn digest(data: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(Sha256::digest(data));
    hash[0..4].to_vec()
}

pub(crate) fn verify(data: &[u8]) -> bool {
    let computed = digest(&data[0..data.len() - 4]);
    let expected = &data[data.len() - 4..data.len()];
    computed == expected
}

pub(crate) fn append_to(bytes: &mut Vec<u8>) {
    let checksum = digest(bytes);
    bytes.extend_from_slice(&checksum);
}
