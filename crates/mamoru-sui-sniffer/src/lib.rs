// Not a license :)

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use fastcrypto::encoding::{Base58, Encoding, Hex};
use mamoru_sniffer::core::{BlockchainDataBuilder, StructValue, Value, ValueData};
use mamoru_sniffer::{Sniffer, SnifferConfig};
use mamoru_sui_types::{
    CallTrace, CallTraceArg, CallTraceTypeArg, Event as MamoruEvent, SuiCtx, Transaction,
};
use rayon::prelude::*;
use tracing::{error, info, span, Level};

pub use error::*;
use move_core_types::trace::{CallTrace as MoveCallTrace, CallType as MoveCallType};
use move_core_types::value::{MoveStruct, MoveValue};
use sui_types::effects::{TransactionEffects, TransactionEffectsAPI};
use sui_types::event::Event;
use sui_types::executable_transaction::VerifiedExecutableTransaction;
use sui_types::transaction::TransactionDataAPI;

mod error;

pub struct SuiSniffer {
    inner: Sniffer,
}

impl SuiSniffer {
    pub async fn new() -> Result<Self, SuiSnifferError> {
        let inner =
            Sniffer::new(SnifferConfig::from_env().expect("Missing environment variables")).await?;

        Ok(Self { inner })
    }

    pub async fn observe_transaction(
        &self,
        certificate: VerifiedExecutableTransaction,
        effects: TransactionEffects,
        events: Vec<Event>,
        call_traces: Vec<MoveCallTrace>,
        seq: u64,
        time: DateTime<Utc>,
    ) -> Result<(), SuiSnifferError> {
        let ctx = tokio::task::spawn_blocking(move || {
            let tx_data = certificate.data().transaction_data();
            let tx_hash = format_tx_digest(effects.transaction_digest());

            let span = span!(Level::DEBUG, "ctx_builder", ?tx_hash);
            let _guard = span.enter();

            let mut ctx_builder = BlockchainDataBuilder::<SuiCtx>::new();
            ctx_builder.set_tx_data(format!("{}", seq), tx_hash.clone());

            let gas_cost_summary = effects.gas_cost_summary();

            let events_len = events.len();
            let call_traces_len = call_traces.len();

            ctx_builder.data_mut().set_tx(Transaction {
                seq,
                digest: tx_hash,
                time: time.timestamp(),
                gas_used: gas_cost_summary.gas_used(),
                gas_computation_cost: gas_cost_summary.computation_cost,
                gas_storage_cost: gas_cost_summary.storage_cost,
                gas_budget: tx_data.gas_budget(),
                sender: format_object_id(certificate.sender_address()),
                kind: tx_data.kind().to_string(),
            });

            let before_ms = Utc::now().timestamp_millis();

            register_events(ctx_builder.data_mut(), seq, events);

            let after_ms = Utc::now().timestamp_millis();

            info!(
                "sniffer.register_events() executed in {} ms.",
                after_ms - before_ms,
            );

            let before_ms = Utc::now().timestamp_millis();

            register_call_traces(ctx_builder.data_mut(), seq, call_traces);

            let after_ms = Utc::now().timestamp_millis();

            info!(
                "sniffer.register_call_traces() executed in {} ms.",
                after_ms - before_ms,
            );

            // Set statistics
            ctx_builder.set_statistics(0, 1, events_len as u64, call_traces_len as u64);

            info!(
                "sniffer collected {} events and {} call traces.",
                events_len, call_traces_len,
            );

            let ctx = ctx_builder.build()?;

            Result::<_, SuiSnifferError>::Ok(ctx)
        })
        .await
        .expect("BUG: Tokio join failed.");

        match ctx {
            Ok(ctx) => {
                self.inner.observe_data(ctx).await;
            }
            Err(err) => {
                error!(error = ?err, "Failed to collect BlockchainDataCtx");
            }
        }

        Ok(())
    }
}

fn register_call_traces(ctx: &mut SuiCtx, tx_seq: u64, move_call_traces: Vec<MoveCallTrace>) {
    let call_traces_len = move_call_traces.len();

    let (call_traces, (args, type_args)): (Vec<_>, (Vec<_>, Vec<_>)) = move_call_traces
        .into_par_iter()
        .zip(0..call_traces_len)
        .map(|(trace, trace_seq)| {
            let trace_seq = trace_seq as u64;

            let call_trace = CallTrace {
                seq: trace_seq,
                tx_seq,
                depth: trace.depth,
                call_type: match trace.call_type {
                    MoveCallType::Call => 0,
                    MoveCallType::CallGeneric => 1,
                },
                gas_used: trace.gas_used,
                transaction_module: trace.module_id.map(|module| module.short_str_lossless()),
                function: trace.function.to_string(),
            };

            let mut cta = vec![];
            let mut ca = vec![];

            for (arg, seq) in trace.ty_args.into_iter().zip(0u64..) {
                cta.push(CallTraceTypeArg {
                    seq,
                    call_trace_seq: trace_seq,
                    arg: arg.to_canonical_string(),
                });
            }

            for (arg, seq) in trace.args.into_iter().zip(0u64..) {
                match ValueData::new(to_value(&arg)) {
                    Some(arg) => {
                        ca.push(CallTraceArg {
                            seq,
                            call_trace_seq: trace_seq,
                            arg,
                        });
                    }
                    None => continue,
                }
            }

            (call_trace, (ca, cta))
        })
        .unzip();

    ctx.call_traces.extend(call_traces);
    ctx.call_trace_args.extend(args.into_iter().flatten());
    ctx.call_trace_type_args
        .extend(type_args.into_iter().flatten());
}

fn register_events(data: &mut SuiCtx, tx_seq: u64, events: Vec<Event>) {
    let mamoru_events: Vec<_> = events
        .into_iter()
        .map(|event| MamoruEvent {
            tx_seq,
            package_id: format_object_id(event.package_id),
            transaction_module: event.transaction_module.into_string(),
            sender: format_object_id(event.sender),
            typ: event.type_.to_canonical_string(),
            contents: event.contents,
        })
        .collect();

    data.events.extend(mamoru_events);
}

fn format_object_id<T: AsRef<[u8]>>(data: T) -> String {
    format!("0x{}", Hex::encode(data))
}

fn format_tx_digest<T: AsRef<[u8]>>(data: T) -> String {
    Base58::encode(data.as_ref())
}

fn to_value(data: &MoveValue) -> Value {
    match data {
        MoveValue::Bool(value) => Value::Bool(*value),
        MoveValue::U8(value) => Value::U64(*value as u64),
        MoveValue::U16(value) => Value::U64(*value as u64),
        MoveValue::U32(value) => Value::U64(*value as u64),
        MoveValue::U64(value) => Value::U64(*value),
        MoveValue::U128(value) => Value::String(format!("{:#x}", value)),
        MoveValue::U256(value) => Value::String(format!("{:#x}", value)),
        MoveValue::Address(addr) | MoveValue::Signer(addr) => Value::String(format_object_id(addr)),
        MoveValue::Vector(value) => Value::List(value.iter().map(to_value).collect()),
        MoveValue::Struct(value) => {
            let struct_value = match value {
                MoveStruct::WithTypes { type_, fields } => StructValue::new(
                    type_.to_canonical_string(),
                    fields
                        .iter()
                        .map(|(field, value)| (field.clone().into_string(), to_value(value)))
                        .collect(),
                ),

                _ => {
                    error!("BUG: received undecorated `MoveStruct`.");

                    StructValue::new("unknown".to_string(), HashMap::new())
                }
            };

            Value::Struct(struct_value)
        }
    }
}