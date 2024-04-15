pub mod client;
pub mod errors;

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
            program_hash: convert_u256_to_felt(U256::zero())?,
            config_hash: convert_u256_to_felt(U256::zero())?,
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