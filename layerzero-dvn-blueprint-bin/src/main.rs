use std::sync::Arc;

use blueprint_sdk as sdk;
use layerzero_dvn_blueprint_template_lib as blueprint;
use sdk::Job;
use sdk::alloy::network::EthereumWallet;
use sdk::alloy::primitives::address;
use sdk::contexts::instrumented_evm_client::EvmInstrumentedClientContext;
use sdk::crypto::sp_core::SpEcdsa;
use sdk::crypto::tangle_pair_signer::TanglePairSigner;
use sdk::evm::consumer::EVMConsumer;
use sdk::evm::filters::contract::MatchesContract;
use sdk::evm::producer::{PollingConfig, PollingProducer};
use sdk::keystore::backends::Backend;
use sdk::runner::BlueprintRunner;
use sdk::runner::config::BlueprintEnvironment;
use sdk::runner::tangle::config::TangleConfig;
use tower::filter::FilterLayer;
use tracing_subscriber::filter::LevelFilter;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    setup_log();

    let env = BlueprintEnvironment::load()?;

    let data_dir = env.data_dir.clone().unwrap_or_else(|| {
        sdk::warn!("Data dir not specified, using default");
        blueprint::default_data_dir()
    });

    if !data_dir.exists() {
        sdk::warn!("Data dir does not exist, creating");
        std::fs::create_dir_all(&data_dir)?;
    }

    let keystore = env.keystore();
    let ecdsa_pub = keystore.first_local::<SpEcdsa>()?;
    let pair = keystore.get_secret::<SpEcdsa>(&ecdsa_pub)?;
    let signer = TanglePairSigner::new(pair.0);

    let wallet = EthereumWallet::from(signer.alloy_key()?);

    let endpoint_instance = address!("0000000000000000000000000000000000000000"); // TODO
    let send_uln302_instance = address!("0000000000000000000000000000000000000000"); // TODO

    let context = blueprint::DvnContext::new(
        env.clone(),
        data_dir,
        signer.alloy_address()?,
        wallet.clone(),
        endpoint_instance,
        address!("0000000000000000000000000000000000000000"),
    )
    .await?;

    // Producer
    let provider = Arc::new(context.evm_client().await);
    let config = PollingConfig::default();

    let producer = PollingProducer::new(provider.clone(), config).await?;

    // Consumer
    let consumer = EVMConsumer::new(provider, wallet);

    sdk::info!("Starting the event watcher ...");

    let result = BlueprintRunner::builder(TangleConfig::default(), env)
        .router(
            sdk::Router::new()
                .always(
                    blueprint::process_packet
                        .layer(FilterLayer::new(MatchesContract(send_uln302_instance))),
                )
                .with_context(context),
        )
        .producer(producer)
        .consumer(consumer)
        .run()
        .await;

    if let Err(e) = result {
        sdk::error!("Runner failed! {e:?}");
    }

    Ok(())
}

pub fn setup_log() {
    use tracing_subscriber::util::SubscriberInitExt;

    let _ = tracing_subscriber::fmt::SubscriberBuilder::default()
        .without_time()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NONE)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .finish()
        .try_init();
}
