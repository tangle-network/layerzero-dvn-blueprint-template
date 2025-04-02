use blueprint_sdk as sdk;
use sdk::alloy::sol_types::sol;
use serde::{Deserialize, Serialize};

sol!(
    #![sol(
        alloy_sol_types = sdk::alloy::sol_types,
        alloy_contract = sdk::alloy::contract
    )]
    #[sol(rpc)]
    #[allow(missing_docs)]
    #[derive(Debug, Serialize, Deserialize)]
    ILayerZeroEndpointV2,
    "contracts/out/ILayerZeroEndpointV2.sol/ILayerZeroEndpointV2.json"
);

sol!(
    #![sol(
        alloy_sol_types = sdk::alloy::sol_types,
        alloy_contract = sdk::alloy::contract
    )]
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug, Serialize, Deserialize)]
    SendUln302,
    "contracts/out/SendUln302.sol/SendUln302.json"
);

sol!(
    #![sol(
        alloy_sol_types = sdk::alloy::sol_types,
        alloy_contract = sdk::alloy::contract
    )]
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug, Serialize, Deserialize)]
    ReceiveUln302,
    "contracts/out/ReceiveUln302.sol/ReceiveUln302.json"
);

sol!(
    #![sol(
        alloy_sol_types = sdk::alloy::sol_types,
        alloy_contract = sdk::alloy::contract
    )]
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug, Serialize, Deserialize)]
    LayerZeroDVNInstance,
    "contracts/out/LayerZeroDVNInstance.sol/LayerZeroDVNInstance.json"
);
