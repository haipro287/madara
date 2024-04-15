use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use aptos_sdk::crypto::_once_cell::sync::Lazy;
use aptos_sdk::crypto::ed25519::Ed25519PrivateKey;
use aptos_sdk::move_types::identifier::Identifier;
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::move_types::transaction_argument::{convert_txn_args, TransactionArgument};
use aptos_sdk::move_types::u256;
use aptos_sdk::move_types::value::{MoveValue, serialize_values};
use aptos_sdk::rest_client::aptos_api_types::{Address, EntryFunctionId, ViewRequest};
use aptos_sdk::rest_client::{Client, Response, Transaction};
use aptos_sdk::rest_client::error::RestError;
use aptos_sdk::transaction_builder::{TransactionBuilder, TransactionFactory};
use aptos_sdk::types::account_address::AccountAddress;
use aptos_sdk::types::{AccountKey, LocalAccount};
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::transaction::{EntryFunction, TransactionPayload};
use ethers::types::U256;
use ethers::utils::hex;
use url::Url;

use crate::aptos::errors::{Error, Result};

static NODE_URL: Lazy<Url> = Lazy::new(|| {
    Url::from_str(
        std::env::var("APTOS_NODE_URL")
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("http://127.0.0.1:8080/"),
    )
        .unwrap()
});

pub struct AptosClient {
    client: Client,
}

impl AptosClient {
    pub fn new(address: Address) -> Self {
        let client = Client::new(NODE_URL.clone());

        Self {
            client
        }
    }

    pub async fn state_block_number(&self) -> Result<U256> {
        let result = self.client.view(&ViewRequest {
            function: EntryFunctionId::from_str("0x436e0cfb2ded62fcb8838dec11ad1bdb29e6bbd75a184f059e5aded7774b434a::starknet::state_block_number").expect("Invalid function name"),
            type_arguments: vec![],
            arguments: vec![],
        }, None).await.map_err(Into::<RestError>::into)?;


        // TODO: improve error handling
        Ok(U256::from_str(result.into_inner().get(0).unwrap().as_str().unwrap()).unwrap())
    }

    pub async fn state_block_hash(&self) -> Result<U256> {
        let result = self.client.view(&ViewRequest {
            function: EntryFunctionId::from_str("0x436e0cfb2ded62fcb8838dec11ad1bdb29e6bbd75a184f059e5aded7774b434a::starknet::state_block_hash").expect("Invalid function name"),
            type_arguments: vec![],
            arguments: vec![],
        }, None).await.map_err(Into::<RestError>::into)?;


        // TODO: improve error handling
        Ok(U256::from_str(result.into_inner().get(0).unwrap().as_str().unwrap()).unwrap())
    }

    pub async fn state_root(&self) -> Result<U256> {
        let result = self.client.view(&ViewRequest {
            function: EntryFunctionId::from_str("0x436e0cfb2ded62fcb8838dec11ad1bdb29e6bbd75a184f059e5aded7774b434a::starknet::state_root").expect("Invalid function name"),
            type_arguments: vec![],
            arguments: vec![],
        }, None).await.map_err(Into::<RestError>::into)?;


        // TODO: improve error handling
        Ok(U256::from_str(result.into_inner().get(0).unwrap().as_str().unwrap()).unwrap())
    }

    pub async fn update_state(&self, program_output: Vec<U256>) -> Result<Transaction> {

        // self.contract
        //     .update_state(program_output)
        //     .send()
        //     .await?
        //     .inspect(|s| log::debug!("[ethereum client] pending update_state transaction: {:?}", **s))
        //     .await?
        //     .ok_or_else(|| Error::MissingTransactionRecepit)

        let client = self.client.clone();

        let address = AccountAddress::from_str("0x436e0cfb2ded62fcb8838dec11ad1bdb29e6bbd75a184f059e5aded7774b434a").unwrap();

        let result = client.get_account_balance(address).await;

        let key = "1114deb3568058d994e5ac5038c42e041b18ccf87374a848d147a34eec3707e4";

        let private_key = Ed25519PrivateKey::try_from(hex::decode(key).unwrap().as_slice()).expect("Invalid private key");

        let account = LocalAccount::new(address, AccountKey::from_private_key(private_key), 0);

        let chain_id = client
            .get_index()
            .await
            .expect("Failed to get chain ID").into_inner().chain_id;

        let acc = client.get_account(address).await.expect("Failed to get account").into_inner();

        account.set_sequence_number(acc.sequence_number);

        // let tx_factory = TransactionFactory::new(ChainId::new(chain_id));

        // let tx_builder = tx_factory.entry_function()

        let tx_builder = TransactionBuilder::new(
            TransactionPayload::EntryFunction(
                EntryFunction::new(
                    ModuleId::new(
                        address,
                        Identifier::new("starknet").unwrap(),
                    ),
                    Identifier::new("initializeContractState").unwrap(),
                    vec![
                        // TypeTag::Signer,
                        // TypeTag::U256,
                        // TypeTag::Address,
                        // TypeTag::U256,
                        // TypeTag::U256,
                        // TypeTag::U256,
                        // TypeTag::U256
                    ],
                    serialize_values(
                        vec![
                            &MoveValue::U256(u256::U256::from_str_radix("1865367024509426979036104162713508294334262484507712987283009063059134893433", 10).unwrap()),
                            &MoveValue::Address(AccountAddress::ZERO),
                            &MoveValue::U256(u256::U256::from_str_radix("1553709454334774815764988612122634988906525555606597726644370513828557599647", 10).unwrap()),
                            &MoveValue::U256(u256::U256::from_str_radix("0", 10).unwrap()),
                            &MoveValue::U256(u256::U256::from_str_radix("0", 10).unwrap()),
                            &MoveValue::U256(u256::U256::from_str_radix("0", 10).unwrap()),
                        ].into_iter()),
                )
            ),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
            ChainId::new(chain_id),
        )
            .sender(account.address())
            .sequence_number(account.sequence_number())
            .max_gas_amount(5_000)
            .gas_unit_price(100);
        let signed_txn = account.sign_with_transaction_builder(tx_builder);
        let tx = client
            .submit(&signed_txn)
            .await.expect("Failed to submit transfer transaction")
            .into_inner();

        println!("{:?}", tx);

        Ok(client.get_transaction_by_hash(tx.hash.0).await.expect("Failed to get transaction").into_inner())
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use std::time::{SystemTime, UNIX_EPOCH};
    use aptos_sdk::bcs;
    use aptos_sdk::crypto::ed25519::Ed25519PrivateKey;
    use aptos_sdk::crypto::PrivateKey;
    use aptos_sdk::move_types::identifier::Identifier;
    use aptos_sdk::move_types::language_storage::{ModuleId, TypeTag};
    use aptos_sdk::move_types::transaction_argument::convert_txn_args;
    use aptos_sdk::move_types::u256;
    use aptos_sdk::move_types::u256::U256;
    use aptos_sdk::move_types::value::MoveTypeLayout::Address;
    use aptos_sdk::move_types::value::{MoveValue, serialize_values};
    use aptos_sdk::rest_client::aptos_api_types::{EntryFunctionId, ViewRequest};
    use aptos_sdk::rest_client::Client;
    use aptos_sdk::transaction_builder::{TransactionBuilder, TransactionFactory};
    use aptos_sdk::types::account_address::AccountAddress;
    use aptos_sdk::types::chain_id::ChainId;
    use aptos_sdk::types::{AccountKey, LocalAccount};
    use aptos_sdk::types::transaction::{EntryFunction, TransactionArgument, TransactionPayload};
    use ethers::utils::hex;
    use crate::aptos::client::{AptosClient, NODE_URL};

    #[tokio::test]
    async fn get_state() {
        let client = AptosClient::new(AccountAddress::ZERO.into());

        let a = client.state_block_number().await.unwrap();

        print!("{:?}", a)
    }

    #[tokio::test]
    async fn init_state() {
        let client = Client::new(NODE_URL.clone());

        let address = AccountAddress::from_str("0x436e0cfb2ded62fcb8838dec11ad1bdb29e6bbd75a184f059e5aded7774b434a").unwrap();

        let result = client.get_account_balance(address).await;

        let derive_path = "m/44'/637'/0'/0'/0'";
        let mnemonic_phrase =
            "shoot island position soft burden budget tooth cruel issue economy destroy above";

        let key = "1114deb3568058d994e5ac5038c42e041b18ccf87374a848d147a34eec3707e4";

        let private_key = Ed25519PrivateKey::try_from(hex::decode(key).unwrap().as_slice()).expect("Invalid private key");

        let account = LocalAccount::new(address, AccountKey::from_private_key(private_key), 0);

        let chain_id = client
            .get_index()
            .await
            .expect("Failed to get chain ID").into_inner().chain_id;

        let acc = client.get_account(address).await.expect("Failed to get account").into_inner();

        account.set_sequence_number(acc.sequence_number);

        let tx_factory = TransactionFactory::new(ChainId::new(chain_id));

        // let tx_builder = tx_factory.entry_function()

        let tx_builder = TransactionBuilder::new(
            TransactionPayload::EntryFunction(
                EntryFunction::new(
                    ModuleId::new(
                        address,
                        Identifier::new("starknet").unwrap(),
                    ),
                    Identifier::new("initializeContractState").unwrap(),
                    vec![
                        // TypeTag::Signer,
                        // TypeTag::U256,
                        // TypeTag::Address,
                        // TypeTag::U256,
                        // TypeTag::U256,
                        // TypeTag::U256,
                        // TypeTag::U256
                    ],
                    serialize_values(
                        vec![
                            &MoveValue::U256(u256::U256::from_str_radix("1865367024509426979036104162713508294334262484507712987283009063059134893433", 10).unwrap()),
                            &MoveValue::Address(AccountAddress::ZERO),
                            &MoveValue::U256(u256::U256::from_str_radix("1553709454334774815764988612122634988906525555606597726644370513828557599647", 10).unwrap()),
                            &MoveValue::U256(u256::U256::from_str_radix("0", 10).unwrap()),
                            &MoveValue::U256(u256::U256::from_str_radix("0", 10).unwrap()),
                            &MoveValue::U256(u256::U256::from_str_radix("0", 10).unwrap()),
                        ].into_iter()),
                )
            ),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
            ChainId::new(chain_id),
        )
            .sender(account.address())
            .sequence_number(account.sequence_number())
            .max_gas_amount(5_000)
            .gas_unit_price(100);
        let signed_txn = account.sign_with_transaction_builder(tx_builder);
        let tx = client
            .submit(&signed_txn)
            .await.expect("Failed to submit transfer transaction")
            .into_inner();

        println!("{:?}", tx);

        let tx_res = client.get_transaction_by_hash(tx.hash.0).await.expect("Failed to get transaction").into_inner();

        println!("{:?}", tx_res);
    }

    #[tokio::test]
    async fn update_state() {
        let client = Client::new(NODE_URL.clone());

        let address = AccountAddress::from_str("0x436e0cfb2ded62fcb8838dec11ad1bdb29e6bbd75a184f059e5aded7774b434a").unwrap();

        let result = client.get_account_balance(address).await;

        let derive_path = "m/44'/637'/0'/0'/0'";
        let mnemonic_phrase =
            "shoot island position soft burden budget tooth cruel issue economy destroy above";

        let key = "1114deb3568058d994e5ac5038c42e041b18ccf87374a848d147a34eec3707e4";

        let private_key = Ed25519PrivateKey::try_from(hex::decode(key).unwrap().as_slice()).expect("Invalid private key");

        let account = LocalAccount::new(address, AccountKey::from_private_key(private_key), 0);

        let chain_id = client
            .get_index()
            .await
            .expect("Failed to get chain ID").into_inner().chain_id;

        let acc = client.get_account(address).await.expect("Failed to get account").into_inner();

        account.set_sequence_number(acc.sequence_number);

        let tx_factory = TransactionFactory::new(ChainId::new(chain_id));

        // let tx_builder = tx_factory.entry_function()

        let tx_builder = TransactionBuilder::new(
            TransactionPayload::EntryFunction(
                EntryFunction::new(
                    ModuleId::new(
                        address,
                        Identifier::new("starknet").unwrap(),
                    ),
                    Identifier::new("update_state").unwrap(),
                    vec![
                        // TypeTag::Signer,
                        // TypeTag::U256,
                        // TypeTag::Address,
                        // TypeTag::U256,
                        // TypeTag::U256,
                        // TypeTag::U256,
                        // TypeTag::U256
                    ],
                    serialize_values(vec![
                        &MoveValue::Vector(vec![
                            MoveValue::U256(u256::U256::from_str_radix("0", 10).unwrap()),
                            MoveValue::U256(u256::U256::from_str_radix("1", 10).unwrap()),
                            MoveValue::U256(u256::U256::from_str_radix("1", 10).unwrap()),
                            MoveValue::U256(u256::U256::from_str_radix("1234", 16).unwrap()),
                            MoveValue::U256(u256::U256::from_str_radix("1553709454334774815764988612122634988906525555606597726644370513828557599647", 10).unwrap()),
                            MoveValue::U256(u256::U256::from_str_radix("100", 10).unwrap()),
                        ])
                    ].into_iter()),
                )
            ),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
            ChainId::new(chain_id),
        )
            .sender(account.address())
            .sequence_number(account.sequence_number())
            .max_gas_amount(5_000)
            .gas_unit_price(100);
        let signed_txn = account.sign_with_transaction_builder(tx_builder);
        let tx = client
            .submit(&signed_txn)
            .await.expect("Failed to submit transfer transaction")
            .into_inner();

        println!("{:?}", tx);

        let tx_res = client.get_transaction_by_hash(tx.hash.0).await.expect("Failed to get transaction").into_inner();

        println!("{:?}", tx_res);
    }
}

impl TryFrom<AptosClientConfig> for AptosClient {
    type Error = Error;

    fn try_from(config: AptosClientConfig) -> Result<Self> {
        Ok(Self::new(AccountAddress::ZERO.into()))
    }
}

pub struct AptosClientConfig {}
