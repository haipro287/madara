use mc_eth_client::config::{EthereumProviderConfig, EthereumWalletConfig, StarknetContracts};
use serde::{Deserialize, Serialize};

use crate::DaMode;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AptosDaConfig {
    #[serde(default)]
    pub mode: DaMode,
}
