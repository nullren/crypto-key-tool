extern crate core;
mod checksum;
mod key;
mod network;

use clap::Parser;
use std::error::Error;

#[derive(Parser)]
struct Args {
    #[clap(short, long)]
    private_key: String,

    #[clap(short, long)]
    compressed: bool,

    #[clap(short, long, default_value = "mainnet")]
    network: network::Network,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // try from wif, then try from hex
    let pk = key::parse_wif(&args.private_key).or_else(|_| key::parse_hex(&args.private_key))?;
    println!("Private key: {}", hex::encode(pk.private_key_bytes()));
    println!("Private key WIF: {}", pk.private_key_wif());

    let pk = pk.compressed(args.compressed).network(args.network);
    println!("Public address: {}", pk.public_address()?);

    Ok(())
}
