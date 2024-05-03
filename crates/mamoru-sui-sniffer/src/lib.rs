// Not a license :)

use std::{collections::HashMap, mem::size_of_val, sync::Arc};

use chrono::{DateTime, Utc};
use fastcrypto::encoding::{Base58, Encoding, Hex};
use itertools::Itertools;
use mamoru_sniffer::core::daemon::wit::component::guest::sui_ctx::{
    SuiCalltrace, SuiCalltraceTypeArg,
};
use mamoru_sniffer::core::BlockchainData;
use mamoru_sniffer::{
    core::{BlockchainDataBuilder, StructValue, Value, ValueData},
    Sniffer, SnifferConfig,
};

use mamoru_sui_types::{CallTrace, CallTraceArg, CallTraceTypeArg, CreatedObject, DTOOwner, DTOOwnerType, DeletedObject, Event as MamoruEvent, MutatedObject, ObjectOwner, ObjectOwnerKind, ProgrammableTransactionCommand, ProgrammableTransactionPublishCommand, ProgrammableTransactionPublishCommandDependency, ProgrammableTransactionPublishCommandModule, ProgrammableTransactionUpgradeCommand, ProgrammableTransactionUpgradeCommandDependency, ProgrammableTransactionUpgradeCommandModule, SuiCalltraceArg, SuiCtx, Transaction, UnwrappedObject, UnwrappedThenDeletedObject, WrappedObject, CommandType, DTOCalltrace, DTOTransaction};

pub use mamoru_sui_types::{SuiEvent, SuiTransaction};

use tokio::time::Instant;
use tracing::{info, span, warn, Level};

pub use error::*;
use move_core_types::{
    annotated_value::{MoveStruct, MoveValue},
    trace::{CallTrace as MoveCallTrace, CallType as MoveCallType},
};
use sui_types::base_types::ObjectRef;
use sui_types::inner_temporary_store::InnerTemporaryStore;
use sui_types::object::{Data, Owner};
use sui_types::storage::ObjectStore;
use sui_types::type_resolver::LayoutResolver;
use sui_types::{
    effects::{TransactionEffects, TransactionEffectsAPI},
    event::Event,
    executable_transaction::VerifiedExecutableTransaction,
    transaction::{Command, ProgrammableTransaction, TransactionDataAPI, TransactionKind},
};

use mamoru_sui_types::{
    DTOCommand, DTOCreatedObject, DTOMutatedObject, DTOObject, DTOObjectType, DTOOtherObject,
};
use mamoru_sui_types::{ValueData as SuiValueData, ValueType};

mod error;

pub struct SuiSniffer {
    inner: Sniffer,
}

const THRESHOLD_OVERFLOW: usize = 50000;

fn inner_into_value_data(data: &MoveValue, stack: &mut Vec<ValueType>) -> Result<ValueType, ()> {
    if stack.len() > THRESHOLD_OVERFLOW {
        return Err(());
    }

    let result = match (*data).clone() {
        MoveValue::Bool(value) => ValueType::Bool(value),
        MoveValue::U8(value) => ValueType::U64(value as u64),
        MoveValue::U16(value) => ValueType::U64(value as u64),
        MoveValue::U32(value) => ValueType::U64(value as u64),
        MoveValue::U64(value) => ValueType::U64(value as u64),
        MoveValue::U128(value) => ValueType::String(format!("{:#x}", value)),
        MoveValue::U256(value) => ValueType::String(format!("{:#x}", value)),
        MoveValue::Address(addr) | MoveValue::Signer(addr) => {
            ValueType::String(format_object_id(addr))
        }
        MoveValue::Vector(list_) => {
            let list_values = list_
                .iter()
                .map(|elem| -> Result<u64, ()> {
                    let parsed_type = inner_into_value_data(elem, stack)?;
                    let index = stack.len();
                    (*stack).push(parsed_type);
                    Ok(index as u64)
                })
                .collect::<Result<Vec<u64>, ()>>()?;
            ValueType::List(list_values)
        }
        MoveValue::Struct(struct_) => {
            let MoveStruct { type_, fields } = struct_;
            let elems: Vec<(String, u64)> = fields
                .iter()
                .map(|(field, value)| {
                    let parsed_type = inner_into_value_data(value, stack)?;
                    let index = stack.len();
                    (*stack).push(parsed_type);
                    Ok((field.clone().into_string(), index as u64))
                })
                .collect::<Result<Vec<(String, u64)>, ()>>()?;
            ValueType::Struct((type_.to_canonical_string(true), elems))
        }
    };
    Ok(result)
}

fn into_value_data(item: MoveValue) -> Result<SuiValueData, ()> {
    let mut stack: Vec<ValueType> = Vec::new();
    let value_data: ValueType = inner_into_value_data(&item, &mut stack)?;
    Ok(SuiValueData {
        value: value_data,
        data: if stack.is_empty() { None } else { Some(stack) },
    })
}

impl SuiSniffer {
    pub async fn new() -> Result<Self, SuiSnifferError> {
        let sniffer =
            Sniffer::new(SnifferConfig::from_env().expect("Missing environment variables")).await?;

        Ok(Self { inner: sniffer })
    }

    pub fn new_transaction(
        &self,
        verified_transaction: &VerifiedExecutableTransaction,
        effects: &TransactionEffects,
        time: DateTime<Utc>,
        inner_temporary_store: &InnerTemporaryStore,
        layout_resolver: &mut dyn LayoutResolver
    ) -> Some<DTOTransaction> {
        let seq = time.timestamp_nanos_opt().unwrap_or_default() as u64;
        let time = time.timestamp();

        let tx_data = verified_transaction.data().transaction_data();
        let tx_hash = format_tx_digest(effects.transaction_digest());
        let sender = format_object_id(verified_transaction.sender_address());
        let gas_cost_summary = effects.gas_cost_summary();

        let sui_transaction = SuiTransaction {
            seq,
            digest: tx_hash,
            time,
            gas_used: gas_cost_summary.gas_used(),
            gas_computation_cost: gas_cost_summary.computation_cost,
            gas_storage_cost: gas_cost_summary.storage_cost,
            gas_budget: tx_data.gas_budget(),
            sender,
            kind: tx_data.kind().to_string(),
            success: effects.status().is_ok(),
        };


        if let TransactionKind::ProgrammableTransaction(programmable_tx) = &tx_data.kind() {
            let commands = self.set_up_programmable_transaction(programmable_tx);
            let objects = self.extract_objects(layout_resolver, effects, inner_temporary_store);
            DTOTransaction { inner_transaction: sui_transaction, inputs: objects, commands };
        }
        None
    }

    fn set_up_programmable_transaction(&self, tx: &ProgrammableTransaction) -> Vec<DTOCommand> {
        let mut commands: Vec<DTOCommand> = Vec::new();
        for (seq, command) in tx.commands.iter().enumerate() {
            //let kind: &'static str = command.into();

            let command = match command {
                Command::Publish(modules, dependencies) => {
                    //modules_for_command.extend(modules.clone());
                    let deps = dependencies
                        .iter()
                        .map(|elem| format_object_id(elem))
                        .collect::<Vec<String>>();
                    DTOCommand {
                        type_: CommandType::Publish,
                        seq: seq as u64,
                        module_contents: modules.clone(),
                        dependencies: deps,
                    }
                }
                Command::Upgrade(modules, dependencies, package_id, _) => {
                    //modules_for_command.extend(modules.clone());
                    let deps = dependencies
                        .iter()
                        .map(|elem| format_object_id(elem))
                        .collect::<Vec<String>>();
                    DTOCommand {
                        type_: CommandType::Upgrade,
                        seq: seq as u64,
                        module_contents: modules.clone(),
                        dependencies: deps,
                    }
                }
                _ => {
                    DTOCommand {
                        type_: CommandType::Other,
                        seq: seq as u64,
                        module_contents: Vec::new(),
                        dependencies: Vec::new(),
                    }
                }
            };
            commands.push(command);
        }
        commands
    }

    fn extract_events(
        &self,
        layout_resolver: &mut dyn LayoutResolver,
        tx_seq: u64,
        events: &[Event],
    ) -> Vec<SuiEvent> {
        let mamoru_events: Vec<_> = events
            .iter()
            .filter_map(|event| {
                let Ok(event_struct_layout) = layout_resolver.get_annotated_layout(&event.type_)
                else {
                    warn!(%event.type_, "Can't fetch layout by type");
                    return None;
                };

                let Ok(event_struct) =
                    Event::move_event_to_move_struct(&event.contents, event_struct_layout)
                else {
                    warn!(%event.type_, "Can't parse event contents");
                    return None;
                };

                let Ok(contents) = into_value_data(MoveValue::Struct(event_struct)) else {
                    warn!(%event.type_, "Can't convert event contents to ValueData");
                    return None;
                };

                Some(SuiEvent {
                    tx_seq,
                    package_id: format_object_id(event.package_id),
                    transaction_module: event.transaction_module.clone().into_string(),
                    sender: format_object_id(event.sender),
                    typ: event.type_.to_canonical_string(true),
                    contents,
                })
            })
            .collect();

        mamoru_events
    }

    pub fn extract_calltraces(tx_seq: u64, move_call_traces: Vec<MoveCallTrace>) -> Vec<DTOCalltrace> {
        let mut call_traces: Vec<SuiCalltrace> = Vec::new();
        let mut call_traces_type_args: Vec<SuiCalltraceTypeArg> = Vec::new();
        let mut call_traces_args: Vec<SuiCalltraceArg> = Vec::new();

        let call_trace_type_args_len = call_traces_type_args.len();
        let call_trace_args_len = call_traces_args.len();

        move_call_traces
            .into_iter()
            .zip(0..)
            .map(|(trace, trace_seq)| {
                let trace_seq = trace_seq as u64;

                let call_trace = SuiCalltrace {
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

                let mut cta: Vec<SuiCalltraceTypeArg> = vec![];
                let mut ca: Vec<SuiCalltraceArg> = vec![];

                for (arg, seq) in trace
                    .ty_args
                    .into_iter()
                    .zip(call_trace_type_args_len as u64..)
                {
                    cta.push(SuiCalltraceTypeArg {
                        seq,
                        calltrace_seq: trace_seq,
                        arg: arg.to_canonical_string(true),
                    });
                }

                for (arg, seq) in trace.args.into_iter().zip(call_trace_args_len as u64..) {
                    match into_value_data(arg.as_ref().clone()) {
                        Ok(arg) => {
                            ca.push(SuiCalltraceArg {
                                seq,
                                calltrace_seq: trace_seq,
                                arg,
                            });
                        }
                        Err(_) => continue,
                    }
                }

                DTOCalltrace {
                    inner_calltrace: call_trace,
                    call_trace_args: ca,
                    call_trace_type_args: cta,
                }
            }).collect()
    }
    fn extract_objects(
        layout_resolver: &mut dyn LayoutResolver,
        effects: &TransactionEffects,
        inner_temporary_store: &InnerTemporaryStore,
    ) -> Vec<DTOObject> {
        let written = &inner_temporary_store.written;

        let mut fetch_move_value = |object_ref: &ObjectRef| {
            let object_id = object_ref.0;

            match written.get_object(&object_id) {
                Ok(Some(object)) => {
                    if let Data::Move(move_object) = &object.as_inner().data {
                        let struct_tag = move_object.type_().clone().into();
                        let Ok(layout) = layout_resolver.get_annotated_layout(&struct_tag) else {
                            warn!(%object_id, "Can't fetch layout by struct tag");
                            return None;
                        };

                        let Ok(move_value) = move_object.to_move_struct(&layout) else {
                            warn!(%object_id, "Can't convert to move value");
                            return None;
                        };

                        return Some((object, MoveValue::Struct(move_value)));
                    }

                    None
                }
                Ok(None) => {
                    warn!(%object_id, "Can't fetch object by object id");

                    None
                }
                Err(err) => {
                    warn!(%err, "Can't fetch object by object id, error");

                    None
                }
            }
        };

        let mut objects: Vec<DTOObject> = Vec::new();
        for (seq, (created, owner)) in effects.created().iter().enumerate() {
            if let Some((object, move_value)) = fetch_move_value(created) {
                let Ok(object_data) = into_value_data(move_value) else {
                    warn!("Can't make ValueData contents to ValueData");
                    continue;
                };
                objects.push(DTOObject {
                    object_id: format_object_id(object.id()),
                    type_: DTOObjectType::Created(DTOCreatedObject {
                        data: object_data,
                        owner: sui_owner_to_wit_mamoru(*owner),
                    }),
                });
            }
        }

        for (seq, (mutated, owner)) in effects.mutated().iter().enumerate() {
            if let Some((object, move_value)) = fetch_move_value(mutated) {
                let Ok(object_data) = into_value_data(move_value) else {
                    warn!("Can't make ValueData contents to ValueData");
                    continue;
                };

                objects.push(DTOObject {
                    object_id: format_object_id(object.id()),
                    type_: DTOObjectType::Mutated(DTOMutatedObject {
                        data: object_data,
                        owner: sui_owner_to_wit_mamoru(*owner),
                    }),
                });
            }
        }

        for (seq, deleted) in effects.deleted().iter().enumerate() {
            objects.push(DTOObject {
                object_id: format_object_id(deleted.0),
                type_: DTOObjectType::Deleted(DTOOtherObject {}),
            });
        }

        for (seq, wrapped) in effects.wrapped().iter().enumerate() {
            objects.push(DTOObject {
                object_id: format_object_id(wrapped.0),
                type_: DTOObjectType::Wrapped(DTOOtherObject {}),
            });
        }

        for (seq, (unwrapped, _)) in effects.unwrapped().iter().enumerate() {
            objects.push(DTOObject {
                object_id: format_object_id(unwrapped.0),
                type_: DTOObjectType::Unwrapped(DTOOtherObject {}),
            });
        }
        for (seq, unwrapped_then_deleted) in effects.unwrapped_then_deleted().iter().enumerate() {
            objects.push(DTOObject {
                object_id: format_object_id(unwrapped_then_deleted.0),
                type_: DTOObjectType::UnwrappedThenDeletedObject(DTOOtherObject {}),
            });
        }
        objects
    }

    pub fn prepare_ctx(
        &self,
        certificate: VerifiedExecutableTransaction,
        effects: TransactionEffects,
        inner_temporary_store: &InnerTemporaryStore,
        call_traces: Vec<MoveCallTrace>,
        time: DateTime<Utc>,
        emit_debug_info: bool,
        layout_resolver: &mut dyn LayoutResolver
    ) -> Result<BlockchainData<SuiCtx>, SuiSnifferError> {
        if emit_debug_info {
            emit_debug_stats(&call_traces);
        }

        // Sui doesn't have a concept of a transaction sequence number, so we use the current
        // time in nanoseconds.
        let seq = time.timestamp_nanos_opt().unwrap_or_default() as u64;

        let tx_data = certificate.data().transaction_data();
        let tx_hash = format_tx_digest(effects.transaction_digest());
        let call_traces_len = call_traces.len();
        let events = &inner_temporary_store.events.data;
        let events_len = events.len();

        let span = span!(Level::DEBUG, "ctx_builder", ?tx_hash);
        let _guard = span.enter();

        let mut ctx_builder = BlockchainDataBuilder::<SuiCtx>::new();
        ctx_builder.set_tx_data(format!("{}", seq), tx_hash.clone());

        //let gas_cost_summary = effects.gas_cost_summary();
        ctx_builder.data_mut().set_dto_tx(self.new_transaction(&certificate, &effects, time, inner_temporary_store, layout_resolver));

        let events_timer = Instant::now();

        ctx_builder.data_mut().dto_events = self.extract_events(layout_resolver, seq, events);
        info!(
            duration_ms = events_timer.elapsed().as_millis(),
            "sniffer.register_events() executed",
        );

        let call_traces_timer = Instant::now();

        ctx_builder.data_mut().dto_calltraces = self.extract_calltraces(seq, call_traces.clone());

        info!(
            duration_ms = call_traces_timer.elapsed().as_millis(),
            "sniffer.register_call_traces() executed",
        );

        ctx_builder.set_statistics(0, 1, events_len as u64, call_traces_len as u64);

        let ctx = ctx_builder.build()?;

        Ok(ctx)
    }

    pub async fn observe_data(&self, data: BlockchainData<SuiCtx>) {
        self.inner.observe_data(data).await;
    }
}


fn sui_owner_to_wit_mamoru(owner: Owner) -> DTOOwner {
    match owner {
        Owner::AddressOwner(address) => DTOOwner {
            typ_: DTOOwnerType::Address(format_object_id(address)),
        },
        Owner::ObjectOwner(address) => DTOOwner {
            typ_: DTOOwnerType::Object(format_object_id(address)),
        },
        Owner::Immutable => DTOOwner {
            typ_: DTOOwnerType::Immutable,
        },
        Owner::Shared {
            initial_shared_version,
        } => DTOOwner {
            typ_: DTOOwnerType::Shared(initial_shared_version.to_string()),
        },
    }
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
            let MoveStruct { type_, fields } = value;
            let struct_value = StructValue::new(
                type_.to_canonical_string(true),
                fields
                    .iter()
                    .map(|(field, value)| (field.clone().into_string(), to_value(value)))
                    .collect(),
            );

            Value::Struct(struct_value)
        }
    }
}

fn emit_debug_stats(call_traces: &[MoveCallTrace]) {
    let cache_hits_count: usize = call_traces
        .iter()
        .map(|trace| {
            trace
                .args
                .iter()
                // If arc has copies, it's one cache hit.
                .map(|a| if Arc::strong_count(a) > 1 { 1 } else { 0 })
                .sum::<usize>()
        })
        .sum();

    let total_size: usize = call_traces
        .iter()
        .map(|trace| trace.args.iter().map(|a| move_value_size(a)).sum::<usize>())
        .sum();

    let total_call_traces = call_traces.len();

    let top_sized_traces = call_traces
        .iter()
        .map(|trace| trace.args.iter().map(|a| move_value_size(a)).sum::<usize>())
        .collect::<Vec<_>>()
        .into_iter()
        .sorted()
        .rev()
        .take(50)
        .map(bytes_to_human_readable)
        .collect::<Vec<_>>();

    let mut function_call_frequency: HashMap<String, usize> = HashMap::new();

    for trace in call_traces {
        let function = trace
            .module_id
            .as_ref()
            .map(|module| format!("{}::{}", module, &trace.function));

        if let Some(function) = function {
            let count = function_call_frequency.entry(function.clone()).or_insert(0);
            *count += 1;
        }
    }

    let mut most_frequent_calls: Vec<(_, _)> = function_call_frequency.into_iter().collect();

    most_frequent_calls.sort_by(|(_, a), (_, b)| b.cmp(a));
    most_frequent_calls.truncate(50);

    info!(
        total_call_traces = total_call_traces,
        cache_hits_count = %cache_hits_count,
        top_sized_traces = ?top_sized_traces,
        most_frequent_calls = ?most_frequent_calls,
        total_size = bytes_to_human_readable(total_size),
        "call traces debug info"
    );
}

fn move_value_size(value: &MoveValue) -> usize {
    let internal_value_size = match value {
        MoveValue::U8(value) => size_of_val(value),
        MoveValue::U64(value) => size_of_val(value),
        MoveValue::U128(value) => size_of_val(value),
        MoveValue::Bool(value) => size_of_val(value),
        MoveValue::Address(value) => size_of_val(value),
        MoveValue::Vector(value) => value.iter().map(move_value_size).sum::<usize>(),
        MoveValue::Struct(MoveStruct { type_, fields }) => {
            size_of_val(type_)
                + fields
                    .iter()
                    .map(|(a, b)| size_of_val(a) + move_value_size(b))
                    .sum::<usize>()
        }
        MoveValue::Signer(value) => size_of_val(value),
        MoveValue::U16(value) => size_of_val(value),
        MoveValue::U32(value) => size_of_val(value),
        MoveValue::U256(value) => size_of_val(value),
    };

    internal_value_size + std::mem::size_of::<MoveValue>()
}

fn bytes_to_human_readable(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;

    if bytes < KB {
        format!("{} B", bytes)
    } else if bytes < MB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_to_string() {
        let command = Command::Publish(vec![], vec![]);
        let value: &'static str = (&command).into();

        assert_eq!(value, String::from("Publish"));
    }
}
