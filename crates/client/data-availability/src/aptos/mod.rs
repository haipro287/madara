use std::collections::HashMap;
use ethers::prelude::{I256, U256};
use crate::{DaClient, DaMode};

pub mod config;


pub struct AptosClient {
    mode: DaMode,
}

impl DaClient for AptosClient {
    fn get_mode(&self) -> DaMode {
        self.mode
    }

    async fn last_published_state(&self) -> anyhow::Result<I256> {
        todo!()
    }

    async fn publish_state_diff(&self, state_diff: Vec<U256>) -> anyhow::Result<()> {
        todo!()
    }

    fn get_da_metric_labels(&self) -> HashMap<String, String> {
        todo!()
    }
}