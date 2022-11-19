pub use crate::language_storage::TypeTag;

use crate::{
    identifier::Identifier, language_storage::ModuleId, value::MoveValue, vm_status::VMStatus,
};
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallType {
    Call,
    CallGeneric,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallTrace {
    pub depth: u32,
    pub call_type: CallType,
    pub module_id: Option<ModuleId>,
    pub function: Identifier,
    pub ty_args: Vec<TypeTag>,
    pub args: Vec<Arc<MoveValue>>,
    pub gas_used: u64,
    pub err: Option<VMStatus>,
}
