// Not a license :)

use std::fmt::{Debug, Formatter};
use std::{collections::HashMap, mem::size_of_val, sync::Arc};

use chrono::{DateTime, Utc};
use fastcrypto::encoding::{Base58, Encoding, Hex};
use itertools::Itertools;
use mamoru_sniffer::core::{BlockchainData, CallTraceHandler, ValueData};
use mamoru_sniffer::{core::BlockchainDataBuilder, Sniffer, SnifferConfig};
use mamoru_sui_types::SuiActiveJwk;
use mamoru_sui_types::SuiAuthenticatorStateExpire;
use mamoru_sui_types::SuiAuthenticatorStateUpdate;
use mamoru_sui_types::SuiChangeEpoch;
use mamoru_sui_types::SuiCommand;
use mamoru_sui_types::SuiConsensusCommitPrologue;
use mamoru_sui_types::SuiCreatedObject;
use mamoru_sui_types::SuiCtx;
use mamoru_sui_types::SuiMutatedObject;
use mamoru_sui_types::SuiObjectType;
use mamoru_sui_types::SuiOwner;
use mamoru_sui_types::{Calltrace, CalltraceArg, CalltraceTypeArg};
use mamoru_sui_types::{
    SuiConsensusCommitPrologueV2, SuiEndOfEpochTransactionKind, SuiRandomnessStateUpdate,
};
pub use mamoru_sui_types::{SuiEvent, SuiObject, SuiTransaction};
use mamoru_sui_types::{
    SuiGasData, SuiProgrammableMoveCall, SuiPublishCommand, SuiTransactionExpiration,
    SuiTransactionType, SuiUpgradeCommand,
};
use mamoru_sui_types::{ValueData as SuiValueData, ValueType};
use move_core_types::annotated_value::MoveDatatypeLayout;
use move_core_types::trace::TypeTag;
use move_core_types::{
    annotated_value::{MoveStruct, MoveValue},
    trace::{CallTrace as MoveCallTrace, CallType as MoveCallType},
};
use tokio::time::Instant;
use tracing::{info, span, warn, Level};

pub use error::*;
use sui_types::base_types::ObjectRef;
use sui_types::inner_temporary_store::InnerTemporaryStore;
use sui_types::object::{Data, Owner};
use sui_types::storage::ObjectStore;
use sui_types::transaction::{EndOfEpochTransactionKind, TransactionData, TransactionExpiration};
use sui_types::type_resolver::LayoutResolver;
use sui_types::{
    effects::{TransactionEffects, TransactionEffectsAPI},
    event::Event,
    executable_transaction::VerifiedExecutableTransaction,
    transaction::{Command, ProgrammableTransaction, TransactionDataAPI, TransactionKind},
};

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
        MoveValue::Variant(_) => ValueType::String("Variant not supported".to_string()), //TODO pending to add variant
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
    let start_time = Instant::now();
    let mut stack: Vec<ValueType> = Vec::new();
    let value_data: ValueType = inner_into_value_data(&item, &mut stack)?;
    let duration_ns = start_time.elapsed().as_nanos();
    info!(
        data = format!("{:?}", value_data),
        duration_ns = duration_ns,
        "into_value_data duration in ns"
    );
    Ok(SuiValueData {
        value: value_data,
        data: if stack.is_empty() { None } else { Some(stack) },
    })
}

fn format_object_ref(object_ref: &ObjectRef) -> String {
    let object_id = object_ref.0;
    let seq = object_ref.1;
    let digest = object_ref.2;
    format!(
        "0x{}-{}-{}",
        Hex::encode(object_id),
        seq.to_string(),
        digest.to_string()
    )
}

fn into_sui_gas_data(gas_data: &sui_types::transaction::GasData) -> SuiGasData {
    SuiGasData {
        payment: gas_data
            .payment
            .iter()
            .map(|elem| format_object_ref(elem))
            .collect(),
        owner: gas_data.owner.to_string(),
        price: gas_data.price,
        budget: gas_data.budget,
    }
}

pub struct SuiTransactionBuilder {}

impl SuiTransactionBuilder {
    pub fn new() -> Self {
        Self {}
    }

    pub fn new_transaction(
        &mut self,
        verified_transaction: &VerifiedExecutableTransaction,
        effects: &TransactionEffects,
        time: DateTime<Utc>,
        inner_temporary_store: &InnerTemporaryStore,
        layout_resolver: &mut dyn LayoutResolver,
    ) -> Option<SuiTransaction> {
        //TODO move this in the builder?
        let seq = time.timestamp_nanos_opt().unwrap_or_default() as u64;
        let time = time.timestamp();
        let tx_data: &TransactionData = verified_transaction.data().transaction_data();

        let TransactionData::V1(info) = tx_data;
        let expiration = match info.expiration() {
            TransactionExpiration::None => SuiTransactionExpiration::None,
            TransactionExpiration::Epoch(val) => SuiTransactionExpiration::Epoch((*val).into()),
        };
        let gas_cost_summary = effects.gas_cost_summary();

        let mut sui_transaction = SuiTransaction {
            seq,
            digest: format_tx_digest(effects.transaction_digest()),
            time,
            gas_used: gas_cost_summary.gas_used(),
            gas_computation_cost: gas_cost_summary.computation_cost,
            gas_storage_cost: gas_cost_summary.storage_cost,
            gas_budget: tx_data.gas_budget(),
            gas_price: info.gas_price(),
            sender: format_object_id(verified_transaction.sender_address()),
            kind: tx_data.kind().to_string(),
            success: effects.status().is_ok(),
            inputs: Vec::new(),
            objects: Vec::new(),
            commands: Vec::new(),
            expiration,
            gas_data: into_sui_gas_data(info.gas_data()).clone().into(),
            gas_owner: info.gas_owner().to_string(),
            is_end_of_epoch: info.is_end_of_epoch_tx(),
            is_genesis_tx: info.is_genesis_tx(),
            is_sponsored_tx: info.is_sponsored_tx(),
            is_system_tx: info.is_system_tx(),
            receiving_objects: info
                .receiving_objects()
                .iter()
                .map(|elem| format_object_ref(elem))
                .collect(),
            signers: info
                .signers()
                .iter()
                .map(|signer| signer.to_string())
                .collect::<Vec<String>>(),
        };

        if let TransactionKind::ProgrammableTransaction(programmable_tx) = &tx_data.kind() {
            let commands = self.build_programmable_transactions(programmable_tx);
            let objects = self.build_objects(layout_resolver, effects, inner_temporary_store);
            let inputs = Vec::new();
            sui_transaction.commands = commands;
            sui_transaction.objects = objects;
            sui_transaction.inputs = inputs;
            return Some(sui_transaction);
        }

        if let TransactionKind::ChangeEpoch(change) = &tx_data.kind() {
            SuiChangeEpoch {
                epoch: change.epoch,
                protocol_version: change.protocol_version.as_u64(),
                storage_charge: change.storage_charge,
                computation_charge: change.computation_charge,
                storage_rebate: change.storage_rebate,
                non_refundable_storage: change.non_refundable_storage_fee,
                epoch_start_timestamp_ms: change.epoch_start_timestamp_ms,
                system_packages: change
                    .system_packages
                    .iter()
                    .map(|(seq_num, modules, object_ids)| {
                        (
                            seq_num.value(), // TODO it is necessary to grant the  permissions
                            modules.clone(),
                            object_ids
                                .iter()
                                .map(|elem| elem.to_string().clone())
                                .collect::<Vec<String>>(),
                        )
                    })
                    .collect::<Vec<(u64, Vec<Vec<u8>>, Vec<String>)>>(),
            };
        }

        if let TransactionKind::Genesis(_genesis) = &tx_data.kind() {
            //TODO pending to configure
        }

        if let TransactionKind::ConsensusCommitPrologue(consensus) = &tx_data.kind() {
            SuiConsensusCommitPrologue {
                epoch: consensus.epoch,
                round: consensus.round,
                commit_timestamp_ms: consensus.commit_timestamp_ms.into(),
            };
        }

        if let TransactionKind::AuthenticatorStateUpdate(authenticator) = &tx_data.kind() {
            SuiAuthenticatorStateUpdate {
                epoch: authenticator.epoch,
                round: authenticator.round,
                new_active_jwks: authenticator
                    .new_active_jwks
                    .iter()
                    .map(|elem| SuiActiveJwk {
                        iss: elem.jwk_id.iss.clone(),
                        kid: elem.jwk_id.kid.clone(),
                        jwk_kty: elem.jwk.kty.clone(),
                        jwk_n: elem.jwk.n.clone(),
                        jwk_alg: elem.jwk.alg.clone(),
                        epoch: elem.epoch,
                    })
                    .collect::<Vec<SuiActiveJwk>>(),
                authenticator_obj_initial_shared_version: authenticator
                    .authenticator_obj_initial_shared_version
                    .into(),
            };
        }

        if let TransactionKind::RandomnessStateUpdate(randomness) = &tx_data.kind() {
            SuiRandomnessStateUpdate {
                epoch: randomness.epoch,
                randomness_round: randomness.randomness_round.0,
                random_bytes: randomness.random_bytes.clone(),
                randomness_obj_initial_shared_version: randomness
                    .randomness_obj_initial_shared_version
                    .into(),
            };
        }
        if let TransactionKind::ConsensusCommitPrologueV2(consensus) = &tx_data.kind() {
            SuiConsensusCommitPrologueV2 {
                epoch: consensus.epoch,
                round: consensus.round,
                commit_timestamp_ms: consensus.commit_timestamp_ms.into(),
                consesus_commit_digest: consensus.consensus_commit_digest.inner().to_vec(),
            };
        }

        if let TransactionKind::EndOfEpochTransaction(end_of_epoch) = &tx_data.kind() {
            let transactions = end_of_epoch
                .iter()
                .filter_map(|elem| {
                    match elem {
                        EndOfEpochTransactionKind::ChangeEpoch(change) => {
                            let changed_epoch = SuiChangeEpoch {
                                epoch: change.epoch,
                                protocol_version: change.protocol_version.as_u64(),
                                storage_charge: change.storage_charge,
                                computation_charge: change.computation_charge,
                                storage_rebate: change.storage_rebate,
                                non_refundable_storage: change.non_refundable_storage_fee,
                                epoch_start_timestamp_ms: change.epoch_start_timestamp_ms,
                                system_packages: change
                                    .system_packages
                                    .iter()
                                    .map(|(seq_num, modules, object_ids)| {
                                        (
                                            seq_num.value(),
                                            modules.clone(),
                                            object_ids
                                                .iter()
                                                .map(|elem| elem.to_string().clone())
                                                .collect::<Vec<String>>(),
                                        )
                                    })
                                    .collect::<Vec<(u64, Vec<Vec<u8>>, Vec<String>)>>(),
                            };
                            Some(SuiEndOfEpochTransactionKind::ChangeEpoch(changed_epoch))
                        }
                        EndOfEpochTransactionKind::AuthenticatorStateCreate => {
                            Some(SuiEndOfEpochTransactionKind::AuthenticatorStateCreate)
                        }
                        EndOfEpochTransactionKind::AuthenticatorStateExpire(expire_state) => {
                            Some(SuiEndOfEpochTransactionKind::AuthenticatorStateExpire(
                                SuiAuthenticatorStateExpire {
                                    min_epoch: expire_state.min_epoch,
                                    authenticator_obj_initial_shared_version: expire_state
                                        .authenticator_obj_initial_shared_version
                                        .into(),
                                },
                            ))
                        }
                        EndOfEpochTransactionKind::RandomnessStateCreate => {
                            Some(SuiEndOfEpochTransactionKind::RandomnessStateCreate)
                        }
                        EndOfEpochTransactionKind::DenyListStateCreate => {
                            Some(SuiEndOfEpochTransactionKind::DenyListStateCreate)
                        }
                        EndOfEpochTransactionKind::BridgeStateCreate(_)
                        | EndOfEpochTransactionKind::BridgeCommitteeInit(_) => {
                            info!("Detected bridgeStateCreate and BridgeCommitteeInit");
                            None
                        }
                    }
                })
                .collect::<Vec<SuiEndOfEpochTransactionKind>>();
            SuiTransactionType::EndOfEpochTransactionKind(transactions);
        }
        None
    }

    fn build_programmable_transactions(&mut self, tx: &ProgrammableTransaction) -> Vec<SuiCommand> {
        let mut commands: Vec<SuiCommand> = Vec::new();
        for (seq, command) in tx.commands.iter().enumerate() {
            //let kind: &'static str = command.into();
            let command = match command {
                Command::Publish(modules, dependencies) => {
                    //modules_for_command.extend(modules.clone());
                    let deps = dependencies
                        .iter()
                        .map(|elem| format_object_id(elem))
                        .collect::<Vec<String>>();
                    SuiCommand::Publish(SuiPublishCommand {
                        seq: seq.to_string(),
                        module_contents: modules.clone(),
                        dependencies: deps,
                    })
                }
                Command::Upgrade(modules, dependencies, package_id, arg) => {
                    //modules_for_command.extend(modules.clone());
                    let deps = dependencies
                        .iter()
                        .map(|elem| format_object_id(elem))
                        .collect::<Vec<String>>();
                    SuiCommand::Upgrade(SuiUpgradeCommand {
                        seq: seq.to_string(),
                        module_contents: modules.clone(),
                        dependencies: deps,
                        package_id: format_object_id(package_id),
                        argument: arg.to_string(),
                    })
                }
                Command::MakeMoveVec(typ, value) => SuiCommand::Makemovevec((
                    typ.as_ref().map(|t| t.to_string()),
                    value
                        .iter()
                        .map(|elem| elem.to_string())
                        .collect::<Vec<String>>(),
                )),
                //review how to convert in objectid
                Command::MoveCall(boxed_progr_move_call) => {
                    SuiCommand::Movecall(SuiProgrammableMoveCall {
                        pack: boxed_progr_move_call.package.to_string(),
                        module: boxed_progr_move_call.module.to_string(),
                        function: boxed_progr_move_call.function.to_string(),
                        //TODO parse to typetag
                        type_arguments: boxed_progr_move_call
                            .type_arguments
                            .iter()
                            .map(|elem: &TypeTag| elem.to_string())
                            .collect::<Vec<String>>(),
                    })
                }
                Command::TransferObjects(objects, address) => {
                    let values = (
                        objects
                            .iter()
                            .map(|elem| elem.to_string())
                            .collect::<Vec<String>>(),
                        address.to_string(),
                    );
                    SuiCommand::Transferobjects(values)
                }
                Command::SplitCoins(orig_amount, new_coins) => {
                    let values = (
                        orig_amount.to_string(),
                        new_coins
                            .iter()
                            .map(|elem| elem.to_string())
                            .collect::<Vec<String>>(),
                    );
                    SuiCommand::Splitcoins(values)
                }
                Command::MergeCoins(first_coin_to_merge, n_coins) => {
                    let values = (
                        first_coin_to_merge.to_string(),
                        n_coins
                            .iter()
                            .map(|elem| elem.to_string())
                            .collect::<Vec<String>>(),
                    );
                    SuiCommand::Mergecoins(values)
                }
            };
            commands.push(command);
        }
        commands
    }

    fn extract_events(
        &mut self,
        layout_resolver: &mut dyn LayoutResolver,
        tx_seq: u64,
        events: &[Event],
    ) -> Vec<SuiEvent> {
        let mamoru_events: Vec<_> = events
            .iter()
            .filter_map(|event| {
                let Ok(event_datatype_layout) = layout_resolver.get_annotated_layout(&event.type_)
                else {
                    warn!(%event.type_, "Can't fetch layout by type");
                    return None;
                };

                let Ok(event_struct) =
                    Event::move_event_to_move_value(&event.contents, event_datatype_layout)
                else {
                    warn!(%event.type_, "Can't parse event contents");
                    return None;
                };

                let Ok(contents) = into_value_data(event_struct) else {
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

    fn build_objects(
        &mut self,
        layout_resolver: &mut dyn LayoutResolver,
        effects: &TransactionEffects,
        inner_temporary_store: &InnerTemporaryStore,
    ) -> Vec<SuiObject> {
        let written = &inner_temporary_store.written;

        let mut fetch_move_value = |object_ref: &ObjectRef| {
            let object_id = object_ref.0;

            match written.get_object(&object_id) {
                Ok(Some(object)) => {
                    if let Data::Move(move_object) = &object.as_inner().data {
                        let struct_tag = move_object.type_().clone().into();
                        let Ok(datatype_layout) = layout_resolver.get_annotated_layout(&struct_tag)
                        else {
                            warn!(%object_id, "Can't fetch layout by struct tag");
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

        let mut objects: Vec<SuiObject> = Vec::new();
        for (created, owner) in effects.created().iter() {
            if let Some((object, move_value)) = fetch_move_value(created) {
                let Ok(object_data) = into_value_data(move_value) else {
                    warn!("Can't make ValueData contents to ValueData");
                    continue;
                };
                objects.push(SuiObject {
                    id: format_object_id(object.id()),
                    typ: SuiObjectType::Created(SuiCreatedObject {
                        data: object_data,
                        owner: sui_owner_to_wit_mamoru(*owner),
                    }),
                });
            }
        }

        for (mutated, owner) in effects.mutated().iter() {
            if let Some((object, move_value)) = fetch_move_value(mutated) {
                let Ok(object_data) = into_value_data(move_value) else {
                    warn!("Can't make ValueData contents to ValueData");
                    continue;
                };

                objects.push(SuiObject {
                    id: format_object_id(object.id()),
                    typ: SuiObjectType::Mutated(SuiMutatedObject {
                        data: object_data,
                        owner: sui_owner_to_wit_mamoru(*owner),
                    }),
                });
            }
        }

        for deleted in effects.deleted().iter() {
            objects.push(SuiObject {
                id: format_object_id(deleted.0),
                typ: SuiObjectType::Deleted,
            });
        }

        for wrapped in effects.wrapped().iter() {
            objects.push(SuiObject {
                id: format_object_id(wrapped.0),
                typ: SuiObjectType::Wrapped,
            });
        }

        for (unwrapped, _) in effects.unwrapped().iter() {
            objects.push(SuiObject {
                id: format_object_id(unwrapped.0),
                typ: SuiObjectType::Unwrapped,
            });
        }
        for unwrapped_then_deleted in effects.unwrapped_then_deleted().iter() {
            objects.push(SuiObject {
                id: format_object_id(unwrapped_then_deleted.0),
                typ: SuiObjectType::Unwrappedandthendeleted,
            });
        }
        objects
    }
}

#[derive(Debug)]
struct SuiCalltraceHandler {
    pub call_traces: Vec<MoveCallTrace>,
    pub tx_seq: u64,
}

//TODO improve how to handle the calltraces
impl SuiCalltraceHandler {
    pub fn new(call_traces: Vec<MoveCallTrace>, tx_seq: u64) -> Self {
        Self {
            call_traces,
            tx_seq,
        }
    }
}

impl SuiCalltraceHandler {
    fn extract_calltraces(&self) -> Vec<Calltrace> {
        let mut calltrace_identifier: u64 = 0;
        let mut calltrace_arg_identifier: u64 = 0;
        let mut calltrace_type_arg_identifier: u64 = 0;

        self.call_traces
            .clone()
            .into_iter()
            .map(|trace| {
                info!("Starting register calltraces");
                let start_time = Instant::now();

                calltrace_identifier += 1;

                let mut cta: Vec<CalltraceTypeArg> = vec![];
                let mut ca: Vec<CalltraceArg> = vec![];

                let ty_args_start_time = Instant::now();
                for arg in trace.ty_args.into_iter() {
                    calltrace_type_arg_identifier += 1;
                    cta.push(CalltraceTypeArg {
                        seq: calltrace_type_arg_identifier,
                        calltrace_seq: calltrace_identifier,
                        arg: SuiValueData {
                            data: None,
                            value: mamoru_sui_types::ValueType::String(
                                arg.to_canonical_string(true),
                            ),
                        },
                    });
                }
                let duration_ns = ty_args_start_time.elapsed().as_nanos();
                info!(duration_ns = duration_ns, "Type args loop duration in  ns");

                let args_start_time = Instant::now();
                for arg in trace.args.into_iter() {
                    calltrace_arg_identifier += 1;
                    match into_value_data(arg.as_ref().clone()) {
                        Ok(arg) => {
                            ca.push(CalltraceArg {
                                seq: calltrace_arg_identifier,
                                calltrace_seq: calltrace_identifier,
                                arg,
                            });
                        }
                        Err(_) => continue,
                    }
                }

                let duration_ns = args_start_time.elapsed().as_nanos();
                info!(duration_ns = duration_ns, "Args loop duration ns");

                let call_trace = Calltrace {
                    seq: calltrace_identifier,
                    tx_seq: self.tx_seq,
                    depth: trace.depth,
                    call_type: match trace.call_type {
                        MoveCallType::Call => 0,
                        MoveCallType::CallGeneric => 1,
                    },
                    gas_used: trace.gas_used,
                    transaction_module: trace.module_id.map(|module| module.short_str_lossless()),
                    function: trace.function.to_string(),
                    calltrace_type_arg: cta.clone(),
                    calltrace_arg: ca.clone(),
                };

                let total_duration = start_time.elapsed().as_nanos();
                info!(duration_ns = total_duration, "Total duration (ns)");

                call_trace
            })
            .collect()
    }
}

impl CallTraceHandler for SuiCalltraceHandler {
    fn get_calltraces(&self) -> Vec<Calltrace> {
        let call_traces_timer = Instant::now();
        let parsed_call_traces = self.extract_calltraces();
        info!(
            duration_ms = call_traces_timer.elapsed().as_millis(),
            "sniffer.register_call_traces() executed",
        );
        parsed_call_traces
    }
}

impl SuiSniffer {
    pub async fn new() -> Result<Self, SuiSnifferError> {
        let sniffer =
            Sniffer::new(SnifferConfig::from_env().expect("Missing environment variables")).await?;

        Ok(Self { inner: sniffer })
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

        let tx_hash = format_tx_digest(effects.transaction_digest());
        let call_traces_len = call_traces.len();
        let events = &inner_temporary_store.events.data;
        let events_len = events.len();

        let span = span!(Level::DEBUG, "ctx_builder", ?tx_hash);
        let _guard = span.enter();

        let mut ctx_builder = BlockchainDataBuilder::<SuiCtx>::new();

        ctx_builder.set_tx_data(format!("{}", seq), tx_hash.clone());
        //let gas_cost_summary = effects.gas_cost_summary();
        let mut sui_builder_transaction = SuiTransactionBuilder::new();
        ctx_builder.data_mut().transaction = sui_builder_transaction.new_transaction(
            &certificate,
            &effects,
            time,
            inner_temporary_store,
            layout_resolver,
        );
        let events_timer = Instant::now();
        ctx_builder.data_mut().events =
            sui_builder_transaction.extract_events(layout_resolver, seq, events);
        info!(
            duration_ms = events_timer.elapsed().as_millis(),
            "sniffer.register_events() executed",
        );

        //TODO check, if it is necessary to add the calltraces
        let call_trace_handler = SuiCalltraceHandler::new(call_traces.clone(), seq);
        let call_trace_handler: Box<SuiCalltraceHandler> = Box::new(call_trace_handler);
        ctx_builder.data_mut().move_calltrace_handler = Some(call_trace_handler);
        ctx_builder.set_statistics(0, 1, events_len as u64, call_traces_len as u64);

        let ctx = ctx_builder.build()?;

        Ok(ctx)
    }

    pub async fn observe_data(&self, data: BlockchainData<SuiCtx>) {
        self.inner.observe_data(data).await;
    }
}

fn sui_owner_to_wit_mamoru(owner: Owner) -> SuiOwner {
    match owner {
        Owner::AddressOwner(address) => SuiOwner::Address(format_object_id(address)),
        Owner::ObjectOwner(address) => SuiOwner::Object(format_object_id(address)),
        Owner::Immutable => SuiOwner::Inmutable,
        Owner::Shared {
            initial_shared_version,
        } => SuiOwner::Shared(initial_shared_version.to_string()),
    }
}

fn format_object_id<T: AsRef<[u8]>>(data: T) -> String {
    format!("0x{}", Hex::encode(data))
}

fn format_tx_digest<T: AsRef<[u8]>>(data: T) -> String {
    Base58::encode(data.as_ref())
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
        MoveValue::Variant(value) => size_of_val(value),
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
