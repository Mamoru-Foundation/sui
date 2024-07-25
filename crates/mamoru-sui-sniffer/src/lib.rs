// Not a license :)

use std::any::Any;
use std::{collections::HashMap, env, mem::size_of_val, sync::Arc};

use chrono::{DateTime, Utc};
use fastcrypto::encoding::{Base58, Encoding, Hex};
use itertools::Itertools;
use mamoru_sniffer::core::BlockchainData;
use mamoru_sniffer::{
    core::{BlockchainDataBuilder, StructValue, Value, ValueData},
    Sniffer, SnifferConfig,
};
use mamoru_sui_types::{
    CallTrace, CallTraceArg, CallTraceTypeArg, CreatedObject, DeletedObject, Event as MamoruEvent,
    MutatedObject, ObjectOwner, ObjectOwnerKind, ProgrammableTransactionCommand,
    ProgrammableTransactionPublishCommand, ProgrammableTransactionPublishCommandDependency,
    ProgrammableTransactionPublishCommandModule, ProgrammableTransactionUpgradeCommand,
    ProgrammableTransactionUpgradeCommandDependency, ProgrammableTransactionUpgradeCommandModule,
    SuiCtx, Transaction, UnwrappedObject, UnwrappedThenDeletedObject, WrappedObject,
};
use tokio::time::Instant;
use tracing::{info, span, warn, Level};

pub use error::*;
use move_core_types::annotated_value::MoveDatatypeLayout;
use move_core_types::{
    annotated_value::{MoveStruct, MoveValue},
    trace::{CallTrace as MoveCallTrace, CallType as MoveCallType},
};
use sui_types::base_types::ObjectRef;
use sui_types::inner_temporary_store::InnerTemporaryStore;
use sui_types::object::{Data, Owner};
use sui_types::storage::ObjectStore;
use sui_types::type_resolver::{into_struct_layout, LayoutResolver};
use sui_types::{
    effects::{TransactionEffects, TransactionEffectsAPI},
    event::Event,
    executable_transaction::VerifiedExecutableTransaction,
    transaction::{Command, ProgrammableTransaction, TransactionDataAPI, TransactionKind},
};

mod error;

pub struct SuiSniffer {
    inner: Sniffer,
    load_patterns: Vec<String>,
    load_modules:  Vec<String>,
    load_tuples: Vec<(String, String)>

}

const FILTERED_ARG_FOR_CALL_TRACES: &[(&str, &str)] = &[
    ("0xb::bridge", "create_token_bridge_message"),
    ("0x2::coin", "create_currency"),
    ("0x2::coin", "create_regulated_currency"),
    ("0x2::coin", "update_name"),
    ("0x2::coin", "update_symbol"),
    ("0xb::message", "create_token_bridge_message"),
];

const FILTERED_MODS: &[&str] = &["0xb::bridge"];

const FILTERER_PATTERN: &[&str] = &["0x103e3d5096f16a7eb45922bf56eab6eab2685701afc15a9c695b9a7d7b249ecf"];




fn remove_whitespace(input: &str) -> String {
    input.chars().filter(|c| !c.is_whitespace()).collect()
}

pub fn load_patterns(env_var: &str) -> Vec<String> {
    let str = remove_whitespace(env::var(env_var).unwrap_or_default().as_str());
    if str.is_empty() {
        return FILTERER_PATTERN.iter().map(|s| s.to_string()).collect();
    }
    str.split(',').map(|s| s.to_string()).collect()
}

pub fn load_modules(env_var: &str) -> Vec<String> {
    let str = remove_whitespace(env::var(env_var).unwrap_or_default().as_str());
    if str.is_empty() {
        return FILTERED_MODS.iter().map(|s| s.to_string()).collect();
    }
    str.split(',').map(|s| s.to_string()).collect()
}

pub fn load_modules_with_functions(env_var: &str) -> Vec<(String, String)>{
    let tuples_str = remove_whitespace(env::var(env_var).unwrap_or_default().as_str());
    if tuples_str.is_empty() {
        return FILTERED_ARG_FOR_CALL_TRACES.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
    }
    // Parse the environment variable value into an array of string tuples
    let tuples: Result<Vec<(String, String)>, String> = tuples_str
        .split("),(") // Split the string into individual tuples
        .map(|s| s.replace("(", "").replace(")", "")) // Remove parentheses
        .map(|s| {
            let parts: Vec<&str> = s.split(',').collect();
            if parts.len() != 2 {
                Err("Invalid tuple format".to_string())
            } else {
               Ok((parts[0].to_string(), parts[1].to_string())) // Convert parts into a tuple
            }
        })
        .collect();
    tuples.unwrap_or_default()
}


impl SuiSniffer {

    pub async fn new() -> Result<Self, SuiSnifferError> {
        let sniffer =
            Sniffer::new(SnifferConfig::from_env().expect("Missing environment variables")).await?;

        // TODO move to sniffer config?
        let load_patterns = load_patterns("FILTERED_ARGS_PATTERNS");
        let load_modules = load_modules("FILTERED_MODULES");
        let load_tuples = load_modules_with_functions("FILTERED_ARGS");


        Ok(Self {
            inner: sniffer,
            load_patterns,
            load_modules,
            load_tuples
        })
    }

    pub fn is_filtered_call_trace(&self, module: &str, function: &str) -> bool {
        self.load_tuples.contains(&(module.to_string(), function.to_string()))
    }

    pub fn is_filtered_modules(&self, module: &str) -> bool {
        self.load_modules.contains(&module.to_string())
    }

    pub fn is_starts_with_module(&self, substring: &str) -> bool {
        self.load_patterns.iter().any(|s| substring.starts_with(s))
    }

    pub async fn observe_data(&self, data: BlockchainData<SuiCtx>) {
        self.inner.observe_data(data).await;
    }

    pub fn prepare_ctx(
        &self,
        certificate: VerifiedExecutableTransaction,
        effects: TransactionEffects,
        inner_temporary_store: &InnerTemporaryStore,
        call_traces: Vec<MoveCallTrace>,
        time: DateTime<Utc>,
        emit_debug_info: bool,
        layout_resolver: &mut dyn LayoutResolver,
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

        let gas_cost_summary = effects.gas_cost_summary();

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
            success: effects.status().is_ok(),
        });

        let events_timer = Instant::now();
        register_events(ctx_builder.data_mut(), layout_resolver, seq, events);

        info!(
            duration_ns = events_timer.elapsed().as_nanos(),
            "sniffer.register_events() executed",
        );

        let call_traces_timer = Instant::now();
        self.register_call_traces(ctx_builder.data_mut(), seq, call_traces.clone());

        info!(
            duration_ns = call_traces_timer.elapsed().as_nanos(),
            "sniffer.register_call_traces() executed",
        );

            let object_changes_timer = Instant::now();
        register_object_changes(
            ctx_builder.data_mut(),
            layout_resolver,
            &effects,
            inner_temporary_store,
        );

        info!(
            duration_ns = object_changes_timer.elapsed().as_nanos(),
            "sniffer.register_object_changes() executed",
        );

        if let TransactionKind::ProgrammableTransaction(programmable_tx) = &tx_data.kind() {
            register_programmable_transaction(ctx_builder.data_mut(), programmable_tx);
        }

        ctx_builder.set_statistics(0, 1, events_len as u64, call_traces_len as u64);

        let ctx = ctx_builder.build()?;

        Ok(ctx)
    }

    fn register_call_traces(&self, ctx: &mut SuiCtx, tx_seq: u64, move_call_traces: Vec<MoveCallTrace>) {
        info!("Starting register calltraces");
        let mut call_trace_args_len = ctx.call_trace_args.len();
        let mut call_trace_type_args_len = ctx.call_trace_type_args.len();

        let mut name_functions = vec![];
        let mut call_trace_info: Vec<(Option<String>, String)> = vec![];

        let start_time = Instant::now();

        let (call_traces, (args, type_args)): (Vec<_>, (Vec<_>, Vec<_>)) = move_call_traces
            .into_iter()
            .zip(0..)
            .map(|(trace, trace_seq)| {
                let loop_start_time = Instant::now();
                let trace_seq = trace_seq as u64;

                let transaction_module: Option<String> =
                    trace.module_id.map(|module| module.short_str_lossless());
                let function = trace.function.to_string();

                let call_trace = CallTrace {
                    seq: trace_seq,
                    tx_seq,
                    depth: trace.depth,
                    call_type: match trace.call_type {
                        MoveCallType::Call => 0,
                        MoveCallType::CallGeneric => 1,
                    },
                    gas_used: trace.gas_used,
                    transaction_module: transaction_module.clone(),
                    function: function.clone(),
                };

                // applying filter, not module, we don t need args
                if transaction_module.is_none() {
                    return (call_trace, (vec![], vec![]));
                }


                // applying filter
                if let Some(trans_module) = transaction_module.clone() {
                    let tuple_to_filter = (trans_module.as_str(), function.as_str());
                    info!(module=tuple_to_filter.0, function=tuple_to_filter.1, "Filtering call trace");
                    if !self.is_filtered_call_trace(tuple_to_filter.0, tuple_to_filter.1)
                        && !self.is_filtered_modules(tuple_to_filter.0)
                        && !self.is_starts_with_module(tuple_to_filter.0)
                    {
                        return (call_trace, (vec![], vec![]));
                    }
                }

                if let Some(trans_module) = transaction_module.clone() {
                    let cloned_trans_module = trans_module.clone();
                    let cloned_function = function.clone();
                    let str_typ = format!("{cloned_trans_module}.{cloned_function}");
                    name_functions.push(str_typ);
                }

                call_trace_info.push((transaction_module.clone(), function.clone()));

                let mut cta = vec![];
                let mut ca = vec![];

                let ty_args_start_time = Instant::now();
                for (arg, seq) in trace
                    .ty_args
                    .into_iter()
                    .zip(call_trace_type_args_len as u64..)
                {
                    cta.push(CallTraceTypeArg {
                        seq,
                        call_trace_seq: trace_seq,
                        arg: arg.to_canonical_string(true),
                    });
                }
                let duration_ns = ty_args_start_time.elapsed().as_nanos();
                info!(duration_ns = duration_ns, "Type args loop duration in  ns");

                call_trace_type_args_len += cta.len();

                let args_start_time = Instant::now();
                for (arg, seq) in trace.args.into_iter().zip(call_trace_args_len as u64..) {
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
                let duration_ns = args_start_time.elapsed().as_nanos();
                info!(duration_ns = duration_ns, "Args loop duration ns");

                call_trace_args_len += ca.len();

                let duration_ns = loop_start_time.elapsed().as_nanos();
                info!(duration_ns = duration_ns, "Loop duration in  ns");

                (call_trace, (ca, cta))
            })
            .unzip();

        let total_duration = start_time.elapsed().as_nanos();
        let call_traces_len = call_traces.len();
        let total_args_len = args.iter().map(|arg| (*arg).len()).sum::<usize>();
        let total_type_args_len = type_args
            .iter()
            .map(|typ_arg| (*typ_arg).len())
            .sum::<usize>();

        let str_name_functions = format!("{:?}", name_functions);
        let str_call_trace_info = format!("{:?}", call_trace_info);

        info!(duration_ns = total_duration, total_call_traces_len=call_traces_len,
        total_args_len=total_args_len, total_type_args_len=total_type_args_len,
        name_functions = str_name_functions,
        call_trace_names = str_call_trace_info
        ,"Total duration (ns), total call traces size, args size and type args size, time for cta and ca loops");

        ctx.call_traces.extend(call_traces);
        ctx.call_trace_args.extend(args.into_iter().flatten());
        ctx.call_trace_type_args
            .extend(type_args.into_iter().flatten());
    }

}

fn register_programmable_transaction(ctx: &mut SuiCtx, tx: &ProgrammableTransaction) {
    let mut publish_command_seq = 0u64;
    let mut publish_command_module_seq = 0u64;
    let mut publish_command_dependency_seq = 0u64;

    let mut upgrade_command_seq = 0u64;
    let mut upgrade_command_module_seq = 0u64;
    let mut upgrade_command_dependency_seq = 0u64;

    for (seq, command) in tx.commands.iter().enumerate() {
        let kind: &'static str = command.into();

        ctx.programmable_transaction_commands
            .push(ProgrammableTransactionCommand {
                seq: seq as u64,
                kind: kind.to_owned(),
            });

        match command {
            Command::Publish(modules, dependencies) => {
                ctx.publish_commands
                    .push(ProgrammableTransactionPublishCommand {
                        seq: publish_command_seq,
                        command_seq: seq as u64,
                    });

                for module in modules {
                    ctx.publish_command_modules
                        .push(ProgrammableTransactionPublishCommandModule {
                            seq: publish_command_module_seq,
                            publish_seq: publish_command_seq,
                            contents: module.clone(),
                        });

                    publish_command_module_seq += 1;
                }

                for dependency in dependencies {
                    ctx.publish_command_dependencies.push(
                        ProgrammableTransactionPublishCommandDependency {
                            seq: publish_command_dependency_seq,
                            publish_seq: publish_command_seq,
                            object_id: format_object_id(dependency),
                        },
                    );

                    publish_command_dependency_seq += 1;
                }

                publish_command_seq += 1;
            }
            Command::Upgrade(modules, dependencies, package_id, _) => {
                ctx.upgrade_commands
                    .push(ProgrammableTransactionUpgradeCommand {
                        seq: upgrade_command_seq,
                        command_seq: seq as u64,
                        package_id: format_object_id(package_id),
                    });

                for module in modules {
                    ctx.upgrade_command_modules
                        .push(ProgrammableTransactionUpgradeCommandModule {
                            seq: upgrade_command_module_seq,
                            upgrade_seq: upgrade_command_seq,
                            contents: module.clone(),
                        });

                    upgrade_command_module_seq += 1;
                }

                for dependency in dependencies {
                    ctx.upgrade_command_dependencies.push(
                        ProgrammableTransactionUpgradeCommandDependency {
                            seq: upgrade_command_dependency_seq,
                            upgrade_seq: upgrade_command_seq,
                            object_id: format_object_id(dependency),
                        },
                    );

                    upgrade_command_dependency_seq += 1;
                }

                upgrade_command_seq += 1;
            }
            _ => continue,
        }
    }
}


fn register_events(
    data: &mut SuiCtx,
    layout_resolver: &mut dyn LayoutResolver,
    tx_seq: u64,
    events: &[Event],
) {
    info!("Starting register events");
    let mamoru_events: Vec<_> = events
        .iter()
        .filter_map(|event| {
            let Ok(move_datatype_layout) = layout_resolver.get_annotated_layout(&event.type_)
            else {
                warn!(%event.type_, "Can't fetch layout by type");
                return None;
            };

            let Ok(event_struct) =
                Event::move_event_to_move_value(&event.contents, move_datatype_layout)
            else {
                warn!(%event.type_, "Can't parse event contents");
                return None;
            };

            let Some(contents) = ValueData::new(to_value(&event_struct)) else {
                warn!(%event.type_, "Can't convert event contents to ValueData");
                return None;
            };

            Some(MamoruEvent {
                tx_seq,
                package_id: format_object_id(event.package_id),
                transaction_module: event.transaction_module.clone().into_string(),
                sender: format_object_id(event.sender),
                typ: event.type_.to_canonical_string(true),
                contents,
            })
        })
        .collect();

    info!(
        mamoru_events_len = mamoru_events.len(),
        "size for extended events"
    );
    data.events.extend(mamoru_events);
}

fn register_object_changes(
    data: &mut SuiCtx,
    layout_resolver: &mut dyn LayoutResolver,
    effects: &TransactionEffects,
    inner_temporary_store: &InnerTemporaryStore,
) {
    info!("Starting object changes");

    let written = &inner_temporary_store.written;

    let mut fetch_move_value = |object_ref: &ObjectRef| {
        let object_id = object_ref.0;

        match written.get_object(&object_id) {
            Ok(Some(object)) => {
                if let Data::Move(move_object) = &object.as_inner().data {
                    let struct_tag = move_object.type_().clone().into();
                    let Ok(datatype_layout) = layout_resolver.get_annotated_layout(&struct_tag)
                    else {
                        warn!(%object_id, "Can't fetch move data type layout");
                        return None;
                    };

                    let MoveDatatypeLayout::Struct(layout) = datatype_layout else {
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

    let created_count = effects.created().len();
    let mut object_owner_seq = 0u64;
    for (seq, (created, owner)) in effects.created().iter().enumerate() {
        if let Some((object, move_value)) = fetch_move_value(created) {
            let Some(object_data) = ValueData::new(to_value(&move_value)) else {
                warn!("Can't make ValueData from move value");
                continue;
            };

            data.object_changes.created.push(CreatedObject {
                seq: seq as u64,
                owner_seq: object_owner_seq,
                id: format_object_id(object.id()),
                data: object_data,
            });

            data.object_changes
                .owners
                .push(sui_owner_to_mamoru(object_owner_seq, *owner));
            object_owner_seq += 1;
        }
    }

    let mutated_count = effects.mutated().len();
    for (seq, (mutated, owner)) in effects.mutated().iter().enumerate() {
        if let Some((object, move_value)) = fetch_move_value(mutated) {
            let Some(object_data) = ValueData::new(to_value(&move_value)) else {
                warn!("Can't make ValueData from move value");
                continue;
            };

            data.object_changes.mutated.push(MutatedObject {
                seq: seq as u64,
                owner_seq: object_owner_seq,
                id: format_object_id(object.id()),
                data: object_data,
            });

            data.object_changes
                .owners
                .push(sui_owner_to_mamoru(object_owner_seq, *owner));
            object_owner_seq += 1;
        }
    }

    let deleted_count = effects.deleted().len();
    for (seq, deleted) in effects.deleted().iter().enumerate() {
        data.object_changes.deleted.push(DeletedObject {
            seq: seq as u64,
            id: format_object_id(deleted.0),
        });
    }

    let wrapped_count = effects.wrapped().len();
    for (seq, wrapped) in effects.wrapped().iter().enumerate() {
        data.object_changes.wrapped.push(WrappedObject {
            seq: seq as u64,
            id: format_object_id(wrapped.0),
        });
    }

    let unwrapped_count = effects.unwrapped().len();
    for (seq, (unwrapped, _)) in effects.unwrapped().iter().enumerate() {
        data.object_changes.unwrapped.push(UnwrappedObject {
            seq: seq as u64,
            id: format_object_id(unwrapped.0),
        });
    }

    let unwrapped_then_deleted_count = effects.unwrapped_then_deleted().len();
    for (seq, unwrapped_then_deleted) in effects.unwrapped_then_deleted().iter().enumerate() {
        data.object_changes
            .unwrapped_then_deleted
            .push(UnwrappedThenDeletedObject {
                seq: seq as u64,
                id: format_object_id(unwrapped_then_deleted.0),
            });
    }

    info!(
        created_count = created_count,
        mutated_count = mutated_count,
        deleted_count = deleted_count,
        wrapped_count = wrapped_count,
        unwrapped_count = unwrapped_count,
        unwrapped_then_deleted_count = unwrapped_then_deleted_count,
        "register object sizes"
    );
}

fn sui_owner_to_mamoru(seq: u64, owner: Owner) -> ObjectOwner {
    match owner {
        Owner::AddressOwner(address) => ObjectOwner {
            seq,
            owner_kind: ObjectOwnerKind::Address as u32,
            owner_address: Some(format_object_id(address)),
            initial_shared_version: None,
        },
        Owner::ObjectOwner(address) => ObjectOwner {
            seq,
            owner_kind: ObjectOwnerKind::Object as u32,
            owner_address: Some(format_object_id(address)),
            initial_shared_version: None,
        },
        Owner::Shared {
            initial_shared_version,
        } => ObjectOwner {
            seq,
            owner_kind: ObjectOwnerKind::Shared as u32,
            owner_address: None,
            initial_shared_version: Some(initial_shared_version.into()),
        },
        Owner::Immutable => ObjectOwner {
            seq,
            owner_kind: ObjectOwnerKind::Immutable as u32,
            owner_address: None,
            initial_shared_version: None,
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
    let start_time = Instant::now();
    let result = inner_to_value(data);
    let duration_ns = start_time.elapsed().as_nanos();
    info!(
        data = data.to_string(),
        duration_ns = duration_ns,
        "to_value duration in ns"
    );
    return result;
}

fn inner_to_value(data: &MoveValue) -> Value {
    match data {
        MoveValue::Bool(value) => Value::Bool(*value),
        MoveValue::U8(value) => Value::U64(*value as u64),
        MoveValue::U16(value) => Value::U64(*value as u64),
        MoveValue::U32(value) => Value::U64(*value as u64),
        MoveValue::U64(value) => Value::U64(*value),
        MoveValue::U128(value) => Value::String(format!("{:#x}", value)),
        MoveValue::U256(value) => Value::String(format!("{:#x}", value)),
        MoveValue::Variant(_) => Value::String("Variant not supported".to_string()), //TODO pending to add variant
        MoveValue::Address(addr) | MoveValue::Signer(addr) => Value::String(format_object_id(addr)),
        MoveValue::Vector(value) => Value::List(value.iter().map(inner_to_value).collect()),
        MoveValue::Struct(value) => {
            let MoveStruct { type_, fields } = value;
            let struct_value = StructValue::new(
                type_.to_canonical_string(true),
                fields
                    .iter()
                    .map(|(field, value)| (field.clone().into_string(), inner_to_value(value)))
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
        MoveValue::Variant(_) => todo!(),
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

    #[test]
    fn test_parse_env_var_to_tuples_from_env() {
        env::set_var("TUPLES", "(foo,bar),(baz,qux),(quux,corge)");
        let tuples_str = env::var("TUPLES").unwrap();
        let expected_output = vec![
            ("foo".to_string(), "bar".to_string()),
            ("baz".to_string(), "qux".to_string()),
            ("quux".to_string(), "corge".to_string()),
        ];
        let output = load_modules_with_functions("TUPLES");
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_parse_env_var_to_tuples_empty_from_env() {
        env::set_var("TUPLES", "");
        let expected_output: Vec<(String, String)> = Vec::new();
        let output = load_modules_with_functions("TUPLES");
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_parse_env_var_to_tuples_single_from_env() {
        env::set_var("TUPLES", "(single,tuple)");
        let expected_output = vec![
            ("single".to_string(), "tuple".to_string()),
        ];
        let output = load_modules_with_functions("TUPLES");
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_parse_env_var_to_tuples_whitespace_from_env() {
        env::set_var("TUPLES", "( with, spaces ),(more,spaces)");
        let expected_output = vec![
            ("with".to_string(), "spaces".to_string()),
            ("more".to_string(), "spaces".to_string()),
        ];
        let output = load_modules_with_functions("TUPLES");
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_parse_env_to_tuples_wrong_info_from_env() {
        env::set_var("TUPLES", "aaaa");
        let filtered_vector = load_modules_with_functions("TUPLES");
        assert_eq!(filtered_vector, vec![]);
    }

    #[test]
    fn test_parse_module_functions() {
        env::set_var("TUPLES", "(single,tuple)");
        let expected_output = vec![
            ("single".to_string(), "tuple".to_string()),
        ];
        let output = load_modules_with_functions("TUPLES");
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_parse_default_module_functions() {
        let output = load_modules_with_functions("TUPLES");
        assert_eq!(output, FILTERED_ARG_FOR_CALL_TRACES.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<(String, String)>>());
    }

    #[test]
    fn test_parse_load_patterns() {
        env::set_var("PATTERNS", "single,second");
        let output = load_patterns("PATTERNS");
        assert_eq!(output, vec![String::from("single"), String::from("second")]);
    }

    #[test]
    fn test_parse_default_load_patterns() {
        let output = load_patterns("PATTERNS");
        assert_eq!(output, FILTERER_PATTERN.iter().map(|s| s.to_string()).collect::<Vec<String>>());
    }
    

    #[test]
    fn test_parse_load_modules() {
        env::set_var("MODS", "single,second");
        let output = load_modules("MODS");
        assert_eq!(output, vec![String::from("single"), String::from("second")]);
    }

    #[test]
    fn test_parse_default_load_modules() {
        let output = load_patterns("MODS");
        assert_eq!(output, FILTERED_MODS.iter().map(|s| s.to_string()).collect::<Vec<String>>());
    }

}
