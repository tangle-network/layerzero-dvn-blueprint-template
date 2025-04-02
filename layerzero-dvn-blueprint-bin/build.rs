use blueprint_sdk as sdk;
use sdk::build;

fn main() {
    let contract_dirs: Vec<&str> = vec!["../contracts"];
    build::utils::soldeer_install();
    build::utils::soldeer_update();
    build::utils::build_contracts(contract_dirs);
}
