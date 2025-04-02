use crate::ILayerZeroEndpointV2::ILayerZeroEndpointV2Instance;
use crate::{ILayerZeroEndpointV2, LayerZeroDVNInstance, StoredPacket};

use std::path::PathBuf;
use std::sync::Arc;

use blueprint_sdk as sdk;
use sdk::alloy::network::EthereumWallet;
use sdk::alloy::primitives::Address;
use sdk::alloy::providers::fillers::FillProvider;
use sdk::alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
use sdk::alloy::providers::{Identity, RootProvider};
use sdk::macros::context::{EVMProviderContext, KeystoreContext, TangleClientContext};
use sdk::runner::config::BlueprintEnvironment;
use sdk::stores::local_database::LocalDatabase;
use sdk::{Error, alloy};

pub type WalletProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

#[derive(Debug, Clone, KeystoreContext, TangleClientContext, EVMProviderContext)]
pub struct DvnContext {
    #[config]
    pub config: BlueprintEnvironment,
    pub my_instance: LayerZeroDVNInstance::LayerZeroDVNInstanceInstance<(), WalletProvider>,
    pub store: Arc<LocalDatabase<StoredPacket>>,
    pub origin_endpoint: ILayerZeroEndpointV2Instance<(), WalletProvider>,
    pub dest_endpoint: ILayerZeroEndpointV2Instance<(), WalletProvider>,
    pub default_multiplier_bps: u16,
}

impl DvnContext {
    pub async fn new(
        env: BlueprintEnvironment,
        data_dir: PathBuf,
        my_address: Address,
        wallet: EthereumWallet,
        origin_endpoint: Address,
        dest_endpoint: Address,
    ) -> Result<Self, Error> {
        let provider: WalletProvider = alloy::providers::ProviderBuilder::new()
            .wallet(wallet)
            .connect(&env.http_rpc_endpoint)
            .await
            .unwrap(); // TODO

        let my_instance = LayerZeroDVNInstance::new(my_address, provider.clone());

        let origin_endpoint = ILayerZeroEndpointV2::new(origin_endpoint, provider.clone());
        let dest_endpoint = ILayerZeroEndpointV2::new(dest_endpoint, provider.clone());

        let store = LocalDatabase::open(data_dir.join("store.json"))?;
        Ok(Self {
            config: env,
            my_instance,
            store: Arc::new(store),
            origin_endpoint,
            dest_endpoint,
            default_multiplier_bps: 0,
        })
    }
}
