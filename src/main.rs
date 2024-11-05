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
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let private_key = key::parse_wif(&args.private_key)?;
    println!("Private key: {}", hex::encode(private_key.private_key_bytes()));

    Ok(())
}
