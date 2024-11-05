use std::error::Error;

#[derive(Default, Debug, Clone, Eq, PartialEq, clap::ValueEnum)]
pub(crate) enum Network {
    #[default]
    Mainnet,
    Testnet,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet => write!(f, "testnet"),
        }
    }
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

impl Network {
    pub(crate) fn public_byte(&self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet => 0x6f,
        }
    }
    pub(crate) fn private_byte(&self) -> u8 {
        match self {
            Network::Mainnet => 0x80,
            Network::Testnet => 0xef,
        }
    }
}
