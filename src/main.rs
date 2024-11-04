use clap::Parser;

#[derive(Parser)]
struct Args {
    #[clap(short, long)]
    private_key: String,
}

fn main() {
    let args = Args::parse();
    println!("Private key: {}", args.private_key);
}
