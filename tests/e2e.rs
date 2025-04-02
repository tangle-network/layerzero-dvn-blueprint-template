use blueprint::IDVN;
use blueprint::LayerZeroDVNInstance;
use blueprint::{DvnContext, WalletProvider};
use blueprint_sdk as sdk;
use color_eyre::Result;
use layerzero_dvn_blueprint_template_lib as blueprint;
use sdk::alloy::network::EthereumWallet;
use sdk::alloy::primitives::Address;
use sdk::alloy::primitives::U256;
use sdk::alloy::primitives::address;
use sdk::alloy::providers::ProviderBuilder;
use sdk::alloy::signers::local::PrivateKeySigner;
use sdk::alloy::sol;
use sdk::alloy::sol_types::SolValue;
use sdk::contexts::instrumented_evm_client::EvmInstrumentedClientContext;
use sdk::crypto::sp_core::SpEcdsa;
use sdk::crypto::sp_core::SpEcdsaPair;
use sdk::crypto::tangle_pair_signer::TanglePairSigner;
use sdk::crypto::tangle_pair_signer::sp_core::{Pair, ecdsa};
use sdk::evm::consumer::EVMConsumer;
use sdk::evm::producer::{PollingConfig, PollingProducer};
use sdk::keystore::backends::Backend;
use sdk::runner::BlueprintConfig;
use sdk::runner::BlueprintRunner;
use sdk::runner::config::BlueprintEnvironment;
use sdk::runner::config::{BlueprintCliCoreSettings, BlueprintSettings, ContextConfig};
use sdk::runner::error::RunnerError;
use sdk::testing::chain_setup::anvil::AnvilTestnet;
use sdk::testing::chain_setup::anvil::start_default_anvil_testnet;
use sdk::testing::tempfile;
use sdk::testing::utils::setup_log;
use sdk::tokio;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn dvn() -> Result<()> {
    setup_log();

    let data_dir = tempfile::tempdir()?;

    let mut config = BlueprintSettings::default();
    config.test_mode = true;
    config.keystore_uri = data_dir.path().to_string_lossy().into_owned();
    config.protocol = None;

    let mut env = BlueprintEnvironment::load_with_config(ContextConfig {
        blueprint_core_settings: BlueprintCliCoreSettings::Run(config),
    })?;

    let keystore = env.keystore();
    keystore.insert::<SpEcdsa>(&SpEcdsaPair(
        Pair::from_string_with_seed(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            None,
        )?
        .0,
    ))?;
    let pair = keystore.get_secret::<SpEcdsa>(&keystore.first_local::<SpEcdsa>()?)?;
    let signer = TanglePairSigner::new(pair.0);
    let alloy_key = signer.alloy_key()?;

    let test_env = spinup_anvil_testnets(alloy_key.clone()).await?;

    env.http_rpc_endpoint = test_env.origin_testnet._container.http_endpoint.clone();
    env.ws_rpc_endpoint = test_env.origin_testnet._container.ws_endpoint.clone();

    let dvn_context = spawn_runner(env, &test_env, data_dir.path().to_path_buf(), signer).await?;

    tokio::time::sleep(Duration::from_secs(4)).await;

    let tx = test_env
        .origin_testnet
        .contracts
        .oapp
        .send(TESTNET2_EID, String::from("Hello, world!"))
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("OAPP registration failed");
    };

    mine_block(&test_env.origin_testnet._container.http_endpoint).await?;

    Ok(())
}

async fn mine_block(rpc_url: &str) -> Result<()> {
    sdk::debug!("Mining a block");
    Command::new("cast")
        .args(["rpc", "anvil_mine", "14", "--rpc-url", rpc_url])
        .output()?;

    // Give the command a few seconds
    tokio::time::sleep(Duration::from_secs(300)).await;

    Ok(())
}

async fn spawn_runner(
    env: BlueprintEnvironment,
    test_env: &DvnTestEnv,
    data_dir: PathBuf,
    signer: TanglePairSigner<ecdsa::Pair>,
) -> Result<DvnContext> {
    let wallet = EthereumWallet::from(signer.alloy_key()?);

    let context = DvnContext::new(
        env.clone(),
        data_dir,
        test_env.origin_testnet.contracts.dvn,
        wallet.clone(),
        test_env.origin_testnet.contracts.endpoint_v2,
        test_env.dest_testnet.contracts.endpoint_v2,
    )
    .await?;

    // Producer
    let provider = Arc::new(context.evm_client().await);
    let config = PollingConfig::from_current();

    let producer = PollingProducer::new(provider.clone(), config).await?;

    // Consumer
    let consumer = EVMConsumer::new(provider, wallet);

    sdk::info!("Starting the event watcher ...");

    let context_clone = context.clone();
    tokio::spawn(async move {
        BlueprintRunner::builder(Config, env)
            .router(
                sdk::Router::new()
                    .always(blueprint::process_packet)
                    .with_context(context_clone),
            )
            .producer(producer)
            .consumer(consumer)
            .run()
            .await
            .unwrap();
    });

    Ok(context)
}
struct Config;

impl BlueprintConfig for Config {
    async fn requires_registration(
        &self,
        _env: &BlueprintEnvironment,
    ) -> std::result::Result<bool, RunnerError> {
        Ok(false)
    }
}

const TESTNET1_EID: u32 = 0;
const TESTNET2_EID: u32 = 1;
const OWNER: Address = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

struct TestNet {
    _container: AnvilTestnet,
    provider: WalletProvider,
    contracts: ContractAddresses,
}

struct DvnTestEnv {
    origin_testnet: TestNet,
    dest_testnet: TestNet,
}

async fn spinup_anvil_testnets(alloy_key: PrivateKeySigner) -> Result<DvnTestEnv> {
    let origin_testnet = start_default_anvil_testnet(false).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let (origin_provider, origin_contracts) =
        setup_origin_chain(&origin_testnet.http_endpoint, alloy_key.clone()).await?;

    let dest_testnet = start_default_anvil_testnet(false).await;
    let (dest_provider, dest_contracts) =
        setup_destination_chain(&dest_testnet.http_endpoint, alloy_key).await?;

    let tx = origin_contracts
        .oapp
        .setPeer(TESTNET2_EID, dest_contracts.oapp.address().into_word())
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("OAPP registration failed");
    };

    Ok(DvnTestEnv {
        origin_testnet: TestNet {
            _container: origin_testnet,
            provider: origin_provider,
            contracts: origin_contracts,
        },
        dest_testnet: TestNet {
            _container: dest_testnet,
            provider: dest_provider,
            contracts: dest_contracts,
        },
    })
}

struct ContractAddresses {
    oapp: ABAMock::ABAMockInstance<(), WalletProvider>,
    endpoint_v2: Address,
    dvn: Address,
}

sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    #[derive(Debug)]
    ILayerZeroEndpointV2,
    "./tests/contracts/out/ILayerZeroEndpointV2.sol/ILayerZeroEndpointV2.json"
);

sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    #[derive(Debug)]
    SendUln302Mock,
    "./tests/contracts/out/SendUln302Mock.sol/SendUln302Mock.json"
);

sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    #[derive(Debug)]
    ReceiveUln302Mock,
    "./tests/contracts/out/ReceiveUln302Mock.sol/ReceiveUln302Mock.json"
);

sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    #[derive(Debug)]
    ABAMock,
    "./tests/contracts/out/ABAMock.sol/ABAMock.json"
);

sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    #[derive(Debug)]
    EndpointV2Mock,
    "./tests/contracts/out/EndpointV2Mock.sol/EndpointV2Mock.json"
);

use crate::blueprint::ILayerZeroEndpointV2::Origin;

sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    #[derive(Debug)]
    ExecutorMock,
    "./tests/contracts/out/ExecutorMock.sol/ExecutorMock.json"
);

mod _fee_lib {
    super::sol!(
        #[allow(missing_docs, clippy::too_many_arguments)]
        #[sol(rpc)]
        #[derive(Debug)]
        ExecutorFeeLibMock,
        "./tests/contracts/out/ExecutorFeeLibMock.sol/ExecutorFeeLibMock.json"
    );
}

sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    #[derive(Debug)]
    PriceFeedMock,
    "./tests/contracts/out/PriceFeedMock.sol/PriceFeedMock.json"
);

mod _dvn_fee_lib {
    super::sol!(
        #[allow(missing_docs, clippy::too_many_arguments)]
        #[sol(rpc)]
        #[derive(Debug)]
        DVNFeeLibMock,
        "./tests/contracts/out/DVNFeeLibMock.sol/DVNFeeLibMock.json"
    );
}

async fn setup_origin_chain(
    http_endpoint: &str,
    alloy_key: PrivateKeySigner,
) -> Result<(WalletProvider, ContractAddresses)> {
    let wallet = EthereumWallet::new(alloy_key.clone());

    let provider: WalletProvider = ProviderBuilder::new()
        .wallet(wallet.clone())
        .on_http(http_endpoint.parse()?);

    // Deploy endpoint
    let endpoint_v2 = EndpointV2Mock::deploy(provider.clone(), TESTNET1_EID, OWNER).await?;

    // Deploy oapp
    let oapp = ABAMock::deploy(provider.clone(), *endpoint_v2.address(), OWNER).await?;

    // Deploy send lib
    let send_lib = SendUln302Mock::deploy(
        provider.clone(),
        *endpoint_v2.address(),
        Default::default(),
        Default::default(),
    )
    .await?;

    // Register send lib
    let tx = endpoint_v2
        .registerLibrary(*send_lib.address())
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("SendUln302Mock registration failed");
    };

    // Deploy receive lib
    let receive_lib = ReceiveUln302Mock::deploy(provider.clone(), *endpoint_v2.address()).await?;

    // Register receive lib
    let tx = endpoint_v2
        .registerLibrary(*receive_lib.address())
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("ReceiveUln302Mock registration failed");
    };

    // Deploy price feed lib
    let price_feed_lib = PriceFeedMock::deploy(provider.clone(), Address::default()).await?;

    // Deploy DVN fee lib
    let dvn_fee_lib =
        _dvn_fee_lib::DVNFeeLibMock::deploy(provider.clone(), TESTNET1_EID, U256::from(0)).await?;

    // Deploy DVN
    let dvn = LayerZeroDVNInstance::deploy(
        provider.clone(),
        *endpoint_v2.address(),
        vec![*send_lib.address(), *receive_lib.address()],
        *price_feed_lib.address(),
        vec![OWNER],
        1,
        vec![OWNER],
    )
    .await?;

    let tx = dvn.setWorkerFeeLib(*dvn_fee_lib.address()).send().await?;
    if !tx.get_receipt().await?.status() {
        panic!("DVN setWorkerFeeLib failed");
    };

    let tx = dvn
        .setDstConfig(vec![IDVN::DstConfigParam {
            dstEid: TESTNET2_EID,
            gas: 1,
            multiplierBps: 0,
            floorMarginUSD: 0,
        }])
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("DVN setDstConfig failed");
    };

    // Deploy executor fee lib
    let executor_fee_lib =
        _fee_lib::ExecutorFeeLibMock::deploy(provider.clone(), TESTNET1_EID).await?;

    // Deploy executor
    let message_libs = vec![*send_lib.address(), *receive_lib.address()];
    let executor = ExecutorMock::deploy(
        provider.clone(),
        *endpoint_v2.address(),
        *receive_lib.address(),
        message_libs,
        *price_feed_lib.address(),
        Address::default(),
        vec![OWNER],
    )
    .await?;

    let tx = executor
        .setDstConfig(vec![IExecutor::DstConfigParam {
            dstEid: TESTNET2_EID,
            lzReceiveBaseGas: 10,
            lzComposeBaseGas: 0,
            multiplierBps: 0,
            floorMarginUSD: 0,
            nativeCap: 0,
        }])
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("Executor setDstConfig failed");
    };

    let tx = executor
        .setWorkerFeeLib(*executor_fee_lib.address())
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("Executor setWorkerFeeLib failed");
    };

    let tx = send_lib
        .setDefaultUlnConfigs(vec![SendUln302Mock::SetDefaultUlnConfigParam {
            eid: TESTNET2_EID,
            config: SendUln302Mock::UlnConfig {
                confirmations: 0,
                requiredDVNCount: 1,
                optionalDVNCount: 0,
                optionalDVNThreshold: 0,
                requiredDVNs: vec![*dvn.address()],
                optionalDVNs: vec![],
            },
        }])
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("SendUln302Mock setDefaultUlnConfigs failed");
    };

    let tx = oapp
        .setConfigs(
            *send_lib.address(),
            vec![ABAMock::SetConfigParam {
                eid: TESTNET2_EID,
                configType: 1,
                config: SendUln302Mock::ExecutorConfig {
                    executor: *executor.address(),
                    maxMessageSize: 500,
                }
                .abi_encode()
                .into(),
            }],
        )
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("ABAMock setConfigs failed");
    }

    let tx = endpoint_v2
        .setDefaultSendLibrary(TESTNET2_EID, *send_lib.address())
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("SendUln302Mock registration failed");
    }

    // Give the tx a few seconds
    tokio::time::sleep(Duration::from_secs(2)).await;

    Ok((
        provider,
        ContractAddresses {
            oapp,
            endpoint_v2: *endpoint_v2.address(),
            dvn: *dvn.address(),
        },
    ))
}

async fn setup_destination_chain(
    http_endpoint: &str,
    alloy_key: PrivateKeySigner,
) -> Result<(WalletProvider, ContractAddresses)> {
    let wallet = EthereumWallet::new(alloy_key.clone());

    let provider: WalletProvider = ProviderBuilder::new()
        .wallet(wallet.clone())
        .on_http(http_endpoint.parse()?);

    // Deploy endpoint
    let endpoint_v2 = EndpointV2Mock::deploy(provider.clone(), TESTNET2_EID, OWNER).await?;

    // Deploy oapp
    let oapp = ABAMock::deploy(provider.clone(), *endpoint_v2.address(), OWNER).await?;
    let tx = oapp
        .setPeer(TESTNET1_EID, oapp.address().into_word())
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("OAPP registration failed");
    };

    // Deploy and register send lib
    let send_lib = SendUln302Mock::deploy(
        provider.clone(),
        *endpoint_v2.address(),
        Default::default(),
        Default::default(),
    )
    .await?;
    let tx = endpoint_v2
        .registerLibrary(*send_lib.address())
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("SendUln302Mock registration failed");
    };

    // Deploy and register receive lib
    let receive_lib = ReceiveUln302Mock::deploy(provider.clone(), *endpoint_v2.address()).await?;
    let tx = endpoint_v2
        .registerLibrary(*receive_lib.address())
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("ReceiveUln302Mock registration failed");
    };

    // Deploy price feed lib
    let price_feed_lib = PriceFeedMock::deploy(provider.clone(), Address::default()).await?;

    // Deploy DVN fee lib
    let dvn_fee_lib =
        _dvn_fee_lib::DVNFeeLibMock::deploy(provider.clone(), TESTNET2_EID, U256::from(0)).await?;

    // Deploy DVN
    let dvn = LayerZeroDVNInstance::deploy(
        provider.clone(),
        *endpoint_v2.address(),
        vec![*send_lib.address(), *receive_lib.address()],
        *price_feed_lib.address(),
        vec![OWNER],
        1,
        vec![OWNER],
    )
    .await?;

    let tx = dvn.setWorkerFeeLib(*dvn_fee_lib.address()).send().await?;
    if !tx.get_receipt().await?.status() {
        panic!("DVN setWorkerFeeLib failed");
    };

    let tx = receive_lib
        .setDefaultUlnConfigs(vec![ReceiveUln302Mock::SetDefaultUlnConfigParam {
            eid: TESTNET1_EID,
            config: ReceiveUln302Mock::UlnConfig {
                confirmations: 0,
                requiredDVNCount: 1,
                optionalDVNCount: 0,
                optionalDVNThreshold: 0,
                requiredDVNs: vec![*dvn.address()],
                optionalDVNs: vec![],
            },
        }])
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("ReceiveUln302Mock setDefaultUlnConfigs failed");
    };

    let tx = endpoint_v2
        .setDefaultReceiveLibrary(TESTNET1_EID, *receive_lib.address(), U256::from(0))
        .send()
        .await?;
    if !tx.get_receipt().await?.status() {
        panic!("ReceiveUln302Mock registration failed");
    }

    Ok((
        provider,
        ContractAddresses {
            oapp,
            endpoint_v2: *endpoint_v2.address(),
            dvn: *dvn.address(),
        },
    ))
}
