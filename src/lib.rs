use crate::SendUln302::DVNFeePaid;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use blueprint_sdk as sdk;
use sdk::alloy::network::Ethereum;
use sdk::alloy::primitives::keccak256;
use sdk::alloy::primitives::{Address, Bytes};
use sdk::alloy::primitives::{B256, TxHash};
use sdk::alloy::providers::fillers::{FillProvider, JoinFill};
use sdk::alloy::providers::{Identity, RootProvider};
use sdk::alloy::sol_types::SolEvent;
use sdk::error::Error;
use sdk::evm::consumer::RecommendedFillersOf;
use sdk::evm::extract::BlockEvents;
use sdk::extract::Context;
use sdk::job_result::Void;
use serde::{Deserialize, Serialize};

mod bindings;
pub use bindings::*;
mod context;
pub use context::*;

pub fn default_data_dir() -> PathBuf {
    const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(MANIFEST_DIR).join("data")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub version: u8,
    pub nonce: u64,
    pub src_eid: u32,
    pub sender: Address,
    pub dst_eid: u32,
    pub receiver: [u8; 32],
    pub guid: [u8; 32],
    pub message: Bytes,
}

impl Packet {
    /// Decodes an `encodePacked` packet with known offsets
    fn decode(input: &[u8]) -> Result<Packet, String> {
        // Check minimum length (header without message must be at least 113 bytes)
        if input.len() < 113 {
            return Err("Input too short to contain a valid packet".to_string());
        }

        // Offsets based on PacketV1Codec:
        // PACKET_VERSION_OFFSET = 0 (1 byte)
        // NONCE_OFFSET = 1 (8 bytes, [1,9))
        // SRC_EID_OFFSET = 9 (4 bytes, [9,13))
        // SENDER_OFFSET = 13 (32 bytes, [13,45))
        // DST_EID_OFFSET = 45 (4 bytes, [45,49))
        // RECEIVER_OFFSET = 49 (32 bytes, [49,81))
        // GUID_OFFSET = 81 (32 bytes, [81,113))
        // MESSAGE_OFFSET = 113 (rest is message)

        let version = input[0];

        let nonce = u64::from_be_bytes(input[1..9].try_into().unwrap());
        let src_eid = u32::from_be_bytes(input[9..13].try_into().unwrap());

        let sender_bytes: [u8; 32] = input[13..45].try_into().unwrap();
        let sender = Address::from_word(sender_bytes.into());

        let dst_eid = u32::from_be_bytes(input[45..49].try_into().unwrap());

        let receiver: [u8; 32] = input[49..81]
            .try_into()
            .map_err(|_| "Failed to decode receiver")?;

        let guid: [u8; 32] = input[81..113].try_into().unwrap();

        // The remainder is the message.
        let message = Bytes::from(input[113..].to_vec());

        Ok(Packet {
            version,
            nonce,
            src_eid,
            sender,
            dst_eid,
            receiver,
            guid,
            message,
        })
    }

    fn header(&self) -> Bytes {
        let mut header = Vec::with_capacity(113);
        header.push(self.version);
        header.extend_from_slice(&self.nonce.to_be_bytes());
        header.extend_from_slice(&self.src_eid.to_be_bytes());
        header.extend_from_slice(&*self.sender.into_word());
        header.extend_from_slice(&self.dst_eid.to_be_bytes());
        header.extend_from_slice(&self.receiver);
        header.extend_from_slice(&self.guid);
        Bytes::from(header)
    }

    fn payload_hash(&self) -> B256 {
        keccak256(&self.message)
    }

    fn calculate_message_id(&self) -> Result<[u8; 32], Error> {
        let header = self.header();
        let payload_hash = self.payload_hash();

        // Calculate message ID: keccak256(abi.encodePacked(packet_header, payload_hash))
        let mut message_data = Vec::with_capacity(header.len() + 32);
        message_data.extend_from_slice(&header);
        message_data.extend_from_slice(&*payload_hash);

        Ok(*keccak256(&message_data))
    }
}

/// Stored packet information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPacket {
    packet: Packet,
    options: Bytes,
    timestamp: u64,
}

/// A type alias for the Alloy provider
pub type AlloyProvider = FillProvider<
    RecommendedFillersOf<Ethereum>,
    FillProvider<JoinFill<Identity, RecommendedFillersOf<Ethereum>>, RootProvider>,
>;

#[derive(Default)]
struct TxEvents {
    packet_sent: Vec<ILayerZeroEndpointV2::PacketSent>,
    dvn_fee_paid: Vec<DVNFeePaid>,
}

pub async fn process_packet(
    Context(ctx): Context<DvnContext>,
    BlockEvents(events): BlockEvents,
) -> Result<Void, Error> {
    let mut events_by_tx: HashMap<TxHash, TxEvents> = HashMap::new();

    for log in &events {
        let Some(tx_hash) = log.transaction_hash else {
            continue;
        };

        if let Ok(decoded_packet) = ILayerZeroEndpointV2::PacketSent::decode_log(&log.inner, true) {
            let entry = events_by_tx.entry(tx_hash).or_default();
            entry.packet_sent.push(decoded_packet.data);
        }

        if let Ok(decoded_fee) = DVNFeePaid::decode_log(&log.inner, true) {
            let entry = events_by_tx.entry(tx_hash).or_default();
            entry.dvn_fee_paid.push(decoded_fee.data);
        }
    }

    for (_hash, tx_events) in events_by_tx {
        let packet_sents = &tx_events.packet_sent;
        let dvn_fee_paids = &tx_events.dvn_fee_paid;
        if packet_sents.is_empty() || dvn_fee_paids.is_empty() {
            continue;
        }

        'outer: for packet_sent in packet_sents {
            for fee_paid in dvn_fee_paids {
                let my_address = ctx.my_instance.address();
                let is_required = fee_paid.requiredDVNs.contains(my_address);
                let is_optional = fee_paid.optionalDVNs.contains(my_address);

                if !is_required && !is_optional {
                    continue;
                }

                let packet = Packet::decode(packet_sent.encodedPayload.as_ref())
                    .map_err(|e| Error::Other(format!("Failed to decode packet: {e}")))?;

                let message_id = packet.calculate_message_id()?;
                if is_already_verified(&message_id, &ctx).await? {
                    continue 'outer;
                }

                let required_confirmations = 1;

                wait_for_confirmations(packet.dst_eid, required_confirmations).await?;

                let tx = ctx
                    .my_instance
                    .verifyMessageHash(message_id.into(), packet.header(), packet.payload_hash())
                    .send()
                    .await?;
                let Ok(receipt) = tx.get_receipt().await else {
                    return Err(Error::Other(
                        "Failed to get verification receipt".to_string(),
                    ));
                };

                if !dbg!(receipt.status()) {
                    return Err(Error::Other("Failed to verify message".to_string()));
                }
            }
        }
    }

    Ok(Void)
}

async fn is_already_verified(_message_id: &[u8; 32], _ctx: &DvnContext) -> Result<bool, Error> {
    // TODO: Call DVN contract's verifiedMessages mapping
    Ok(false)
}

async fn wait_for_confirmations(dst_eid: u32, required_confirmations: u64) -> Result<(), Error> {
    // TODO
    // const MAX_ATTEMPTS: u32 = 10;
    //
    // let mut current_attempt = 0;
    // let initial_delay = Duration::from_secs(1);
    //
    // loop {
    //     // // Get current block number
    //     // let current_block = get_current_block(dst_eid).await?;
    //     //
    //     // if current_block.confirmations >= required_confirmations {
    //     //     return Ok(());
    //     // }
    //
    //     current_attempt += 1;
    //     if current_attempt >= MAX_ATTEMPTS {
    //         break;
    //     }
    //
    //     // Exponential backoff
    //     let delay = initial_delay * 2u32.pow(current_attempt);
    //     tokio::time::sleep(delay).await;
    // }
    //
    // Err(Error::Other("Max confirmation attempts exceeded".into()))
    Ok(())
}
