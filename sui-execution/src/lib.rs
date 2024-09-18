// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// DO NOT MODIFY, Generated by ./scripts/execution-layer

use std::path::PathBuf;
use std::sync::Arc;

use sui_protocol_config::ProtocolConfig;
use sui_types::{error::SuiResult, metrics::BytecodeVerifierMetrics};

pub use executor::Executor;
pub use verifier::Verifier;

pub mod executor;
pub mod verifier;

mod latest;
mod v0;
mod v1;
mod v2;

#[cfg(test)]
mod tests;

pub fn executor(
    protocol_config: &ProtocolConfig,
    silent: bool,
    enable_profiler: Option<PathBuf>,
) -> SuiResult<Arc<dyn Executor + Send + Sync>> {
    let version = protocol_config.execution_version_as_option().unwrap_or(0);
    Ok(match version {
        0 => Arc::new(v0::Executor::new(protocol_config, silent, enable_profiler)?),

        1 => Arc::new(v1::Executor::new(protocol_config, silent, enable_profiler)?),

        2 => Arc::new(v2::Executor::new(protocol_config, silent, enable_profiler)?),

        3 => Arc::new(latest::Executor::new(
            protocol_config,
            silent,
            enable_profiler,
        )?),

        v => panic!("Unsupported execution version {v}"),
    })
}

pub fn verifier<'m>(
    protocol_config: &ProtocolConfig,
    signing_limits: Option<(usize, usize)>,
    metrics: &'m Arc<BytecodeVerifierMetrics>,
) -> Box<dyn Verifier + 'm> {
    let version = protocol_config.execution_version_as_option().unwrap_or(0);
    let config = protocol_config.verifier_config(signing_limits);
    match version {
        0 => Box::new(v0::Verifier::new(config, metrics)),
        1 => Box::new(v1::Verifier::new(config, metrics)),
        2 => Box::new(v2::Verifier::new(config, metrics)),
        3 => Box::new(latest::Verifier::new(config, metrics)),
        v => panic!("Unsupported execution version {v}"),
    }
}
