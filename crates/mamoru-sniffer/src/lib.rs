mod error;

pub use error::*;

use chrono::{DateTime, Utc};
use fastcrypto::encoding::{Base64, Encoding, Hex};
use mamoru_core::*;
use mamoru_sui_types::{
    CallTrace, CallTraceArgType, CallTraceArgTypeBatch, CallTraceArgValue, CallTraceArgValueBatch,
    CallTraceBatch, CallTraceTypeArg, CallTraceTypeArgBatch, CheckpointEvent, CheckpointEventBatch,
    CoinBalanceChangeEvent, CoinBalanceChangeEventBatch, DeleteObjectEvent, DeleteObjectEventBatch,
    EpochChangeEvent, EpochChangeEventBatch, MoveEvent, MoveEventBatch, MutateObjectEvent,
    MutateObjectEventBatch, NewObjectEvent, NewObjectEventBatch, PublishEvent, PublishEventBatch,
    Transaction, TransactionBatch, TransferObjectEvent, TransferObjectEventBatch,
};
use move_core_types::trace::{CallTrace as MoveCallTrace, CallType as MoveCallType};
use sui_types::batch::TxSequenceNumber;
use sui_types::event::Event;
use sui_types::messages::{SignedTransactionEffects, VerifiedCertificate};
use tracing::{span, Level};

pub const RULES_UPDATE_INTERVAL_SECS: i64 = 120;

pub struct SuiSniffer {
    inner: Sniffer,
    rules_updated_at: DateTime<Utc>,
}

impl SuiSniffer {
    pub async fn new() -> Result<Self, SuiSnifferError> {
        let mut inner = Sniffer::new(SnifferConfig::from_env()).await?;
        inner.register().await?;
        inner.update_rules().await?;

        Ok(Self {
            inner,
            rules_updated_at: Utc::now(),
        })
    }

    pub async fn unregister(&self) -> Result<(), SnifferError> {
        self.inner.unregister().await
    }

    pub async fn update_rules(&mut self, now: DateTime<Utc>) -> Result<(), SuiSnifferError> {
        self.inner.update_rules().await?;
        self.rules_updated_at = now;

        Ok(())
    }

    pub fn should_update_rules(&self, now: DateTime<Utc>) -> bool {
        let interval = now - self.rules_updated_at;

        interval.num_seconds() > RULES_UPDATE_INTERVAL_SECS
    }

    pub async fn observe_transaction(
        &self,
        certificate: &VerifiedCertificate,
        signed_effects: SignedTransactionEffects,
        seq: TxSequenceNumber,
        time: DateTime<Utc>,
    ) -> Result<(), SuiSnifferError> {
        let effects = signed_effects.into_data();
        let tx_data = &certificate.data().data;

        let tx_hash = to_sui_base64(effects.transaction_digest.as_ref());
        let sender = to_sui_hex(certificate.sender_address());

        let ctx = {
            let span = span!(Level::DEBUG, "ctx_builder", ?tx_hash);
            let _guard = span.enter();

            let ctx_builder = BlockchainDataCtxBuilder::new();

            ctx_builder.add_data(TransactionBatch::new(vec![Transaction {
                seq,
                digest: tx_hash.clone(),
                time: time.timestamp(),
                gas_used: tx_data.gas_price,
                gas_computation_cost: effects.gas_used.computation_cost,
                gas_storage_cost: effects.gas_used.storage_cost,
                gas_budget: tx_data.gas_budget,
                sender: sender.clone(),
                kind: tx_data.kind_as_str().to_string(),
            }]))?;

            register_events(&ctx_builder, seq, effects.events)?;
            register_call_traces(&ctx_builder, seq, effects.call_traces)?;

            ctx_builder.finish(format!("{}", seq), tx_hash.clone(), time.naive_utc())
        };

        self.inner.observe_data(ctx).await?;

        Ok(())
    }
}

fn register_call_traces(
    ctx_builder: &BlockchainDataCtxBuilder,
    tx_seq: u64,
    move_call_traces: Vec<MoveCallTrace>,
) -> Result<(), SuiSnifferError> {
    let mut call_traces = vec![];
    let mut type_args = vec![];
    let mut arg_types = vec![];
    let mut arg_values = vec![];

    for (trace, trace_seq) in move_call_traces.into_iter().zip(0u64..) {
        call_traces.push(CallTrace {
            seq: trace_seq,
            tx_seq,
            depth: trace.depth,
            call_type: match trace.call_type {
                MoveCallType::Call => 0,
                MoveCallType::CallGeneric => 1,
            },
            gas_used: trace.gas_used,
            transaction_module: trace.module_id,
            function: trace.function,
        });

        for (arg, seq) in trace.ty_args.into_iter().zip(0u64..) {
            type_args.push(CallTraceTypeArg {
                seq,
                call_trace_seq: trace_seq,
                arg,
            });
        }

        for (arg, seq) in trace.args_types.into_iter().zip(0u64..) {
            arg_types.push(CallTraceArgType {
                seq,
                call_trace_seq: trace_seq,
                arg,
            });
        }

        for (arg, seq) in trace.args_values.into_iter().zip(0u64..) {
            arg_values.push(CallTraceArgValue {
                seq,
                call_trace_seq: trace_seq,
                arg,
            });
        }
    }

    ctx_builder.add_data(CallTraceBatch::new(call_traces))?;
    ctx_builder.add_data(CallTraceTypeArgBatch::new(type_args))?;
    ctx_builder.add_data(CallTraceArgTypeBatch::new(arg_types))?;
    ctx_builder.add_data(CallTraceArgValueBatch::new(arg_values))?;

    Ok(())
}

fn register_events(
    ctx_builder: &BlockchainDataCtxBuilder,
    tx_seq: u64,
    events: Vec<Event>,
) -> Result<(), SuiSnifferError> {
    let mut move_events = vec![];
    let mut publish_events = vec![];
    let mut coin_balance_events = vec![];
    let mut epoch_events = vec![];
    let mut checkpoint_events = vec![];
    let mut transfer_object_events = vec![];
    let mut mutate_object_events = vec![];
    let mut delete_object_events = vec![];
    let mut new_object_events = vec![];

    for event in events {
        match event {
            Event::MoveEvent {
                package_id,
                transaction_module,
                sender,
                type_,
                contents,
            } => move_events.push(MoveEvent {
                tx_seq,
                package_id: to_sui_hex(package_id),
                transaction_module: transaction_module.into_string(),
                sender: to_sui_hex(sender),
                typ: type_.to_canonical_string(),
                contents,
            }),
            Event::Publish { sender, package_id } => publish_events.push(PublishEvent {
                tx_seq,
                package_id: to_sui_hex(package_id),
                sender: to_sui_hex(sender),
            }),
            Event::CoinBalanceChange {
                package_id,
                transaction_module,
                sender,
                change_type,
                owner,
                coin_type,
                coin_object_id,
                version,
                amount,
            } => coin_balance_events.push(CoinBalanceChangeEvent {
                tx_seq,
                package_id: to_sui_hex(package_id),
                transaction_module: transaction_module.into_string(),
                sender: to_sui_hex(sender),
                change_type: change_type.to_string(),
                owner_address: owner.get_owner_address().map(to_sui_hex).ok(),
                coin_type,
                coin_object_id: to_sui_hex(coin_object_id),
                version: version.value(),
                amount: amount.to_le_bytes().to_vec(),
            }),
            Event::EpochChange(epoch_id) => {
                epoch_events.push(EpochChangeEvent { tx_seq, epoch_id })
            }
            Event::Checkpoint(checkpoint_seq) => checkpoint_events.push(CheckpointEvent {
                tx_seq,
                checkpoint_seq,
            }),
            Event::TransferObject {
                package_id,
                transaction_module,
                sender,
                recipient,
                object_type,
                object_id,
                version,
            } => transfer_object_events.push(TransferObjectEvent {
                tx_seq,
                package_id: to_sui_hex(package_id),
                transaction_module: transaction_module.into_string(),
                sender: to_sui_hex(sender),
                recipient_address: recipient.get_owner_address().map(to_sui_hex).ok(),
                object_type,
                object_id: to_sui_hex(object_id),
                version: version.value(),
            }),
            Event::MutateObject {
                package_id,
                transaction_module,
                sender,
                object_type,
                object_id,
                version,
            } => mutate_object_events.push(MutateObjectEvent {
                tx_seq,
                package_id: to_sui_hex(package_id),
                transaction_module: transaction_module.into_string(),
                sender: to_sui_hex(sender),
                object_type,
                object_id: to_sui_hex(object_id),
                version: version.value(),
            }),
            Event::DeleteObject {
                package_id,
                transaction_module,
                sender,
                object_id,
                version,
            } => delete_object_events.push(DeleteObjectEvent {
                tx_seq,
                package_id: to_sui_hex(package_id),
                transaction_module: transaction_module.into_string(),
                sender: to_sui_hex(sender),
                object_id: to_sui_hex(object_id),
                version: version.value(),
            }),
            Event::NewObject {
                package_id,
                transaction_module,
                sender,
                recipient,
                object_type,
                object_id,
                version,
            } => new_object_events.push(NewObjectEvent {
                tx_seq,
                package_id: to_sui_hex(package_id),
                transaction_module: transaction_module.into_string(),
                sender: to_sui_hex(sender),
                recipient_address: recipient.get_owner_address().map(to_sui_hex).ok(),
                object_type,
                object_id: to_sui_hex(object_id),
                version: version.value(),
            }),
        }
    }

    ctx_builder.add_data(MoveEventBatch::new(move_events))?;
    ctx_builder.add_data(PublishEventBatch::new(publish_events))?;
    ctx_builder.add_data(CoinBalanceChangeEventBatch::new(coin_balance_events))?;
    ctx_builder.add_data(EpochChangeEventBatch::new(epoch_events))?;
    ctx_builder.add_data(CheckpointEventBatch::new(checkpoint_events))?;
    ctx_builder.add_data(TransferObjectEventBatch::new(transfer_object_events))?;
    ctx_builder.add_data(MutateObjectEventBatch::new(mutate_object_events))?;
    ctx_builder.add_data(DeleteObjectEventBatch::new(delete_object_events))?;
    ctx_builder.add_data(NewObjectEventBatch::new(new_object_events))?;

    Ok(())
}

fn to_sui_hex<T: AsRef<[u8]>>(data: T) -> String {
    Hex::encode(data)
}

fn to_sui_base64<T: AsRef<[u8]>>(data: T) -> String {
    Base64::from_bytes(data.as_ref()).encoded()
}
