pub mod client;
pub mod errors;
pub mod config;

use async_trait::async_trait;
use sp_runtime::traits::Block;
use mp_snos_output::{SnosCodec, StarknetOsOutput};
use crate::aptos::client::AptosClient;
use crate::{Result, SettlementProvider, StarknetSpec, StarknetState};
use crate::ethereum::{convert_felt_to_u256, convert_u256_to_felt};
use ethers::types::U256;

#[async_trait]
impl<B: Block> SettlementProvider<B> for AptosClient {
    async fn is_initialized(&self) -> crate::errors::Result<bool, B> {
        Ok(true)
    }

    async fn get_chain_spec(&self) -> crate::errors::Result<StarknetSpec, B> {
        Ok(StarknetSpec {
            program_hash: convert_u256_to_felt(U256::from_str_radix("0x041fc2a467ef8649580631912517edcab7674173f1dbfa2e9b64fbcd82bc4d79", 16).unwrap())?,
            config_hash: convert_u256_to_felt(U256::from_str_radix("0x05ac6b99d1ab6d37202e29e2c887ace63cc594b40f900cf2c47398272bef412c", 16).unwrap())?,
        })
    }

    async fn get_state(&self) -> crate::errors::Result<StarknetState, B> {
        Ok(StarknetState {
            block_number: convert_u256_to_felt(self.state_block_number().await?)?,
            state_root: convert_u256_to_felt(self.state_root().await?)?,
        })
    }

    async fn update_state(&self, program_output: StarknetOsOutput) -> Result<(), B> {
        let program_output: Vec<U256> =
            program_output.into_encoded_vec().into_iter().map(convert_felt_to_u256).collect();

        let tx_receipt = self.update_state(program_output).await?;
        log::trace!("[settlement] State was successfully updated: {:#?}", tx_receipt);

        Ok(())
    }
}