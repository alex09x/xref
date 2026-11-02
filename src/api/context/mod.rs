/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
mod facts;
mod flow;
mod guards;
#[cfg(test)]
mod tests;
pub mod types;

use super::{
    Analysis, ApiError, Cancellation, Output,
    types::{Data, InstructionRow},
};
use crate::{listing, scan};
use std::{collections::BTreeSet, fmt::Write};
use types::{Argument, CallContext, Value};

impl Analysis {
    pub(super) fn call_context(&self, address: &str, call_site: &str, cancel: &Cancellation) -> Output {
        let context = self.context(address, call_site, cancel)?;
        Ok((
            Data::CallContext { context: Box::new(context) },
            None,
            vec!["sysv_integer_register_candidates_not_recovered_signature", "direct_cfg_and_returning_call_model"],
        ))
    }
    pub(super) fn context(
        &self,
        address: &str,
        call_site: &str,
        cancel: &Cancellation,
    ) -> Result<CallContext, ApiError> {
        let function = self.function(address)?;
        let site = Self::address(call_site)?;
        if function.end - function.start > 32768 {
            return Err(ApiError::new("context_budget", "call context supports at most 32 KiB of code"));
        }
        let code = self.image.code(&function).ok_or_else(|| ApiError::new("no_code", "function bytes unavailable"))?;
        let mut insns = vec![];
        scan::decode(code, function.start, |ins| insns.push(*ins));
        if insns.len() > 2048 {
            return Err(ApiError::new("context_budget", "call context supports at most 2048 instructions"));
        }
        let call =
            insns.iter().position(|ins| ins.ip() == site && listing::is_call(ins, &function)).ok_or_else(|| {
                ApiError::new(
                    "invalid_call_site",
                    "call_site must name a decoded call or tail-jump instruction in the selected FDE",
                )
            })?;
        let flow = flow::Flow::new(&insns);
        let state = facts::at_call(&insns, &flow, call, cancel)?;
        let (guards, evidence, guards_complete) = guards::guards(&insns, &flow, call, cancel)?;
        let mut complete = state.is_some() && !flow.incomplete && guards_complete;
        let mut indexes: BTreeSet<_> = evidence.into_iter().collect();
        indexes.insert(call);
        let mut warnings =
            vec!["sysv_integer_register_candidates_not_recovered_signature", "direct_cfg_and_returning_call_model"];
        if state.is_none() {
            warnings.push("unreachable_or_dataflow_budget_exhausted");
        }
        if flow.incomplete {
            warnings.push("unresolved_control_flow_values_suppressed");
        }
        if !guards_complete {
            warnings.push("guard_budget_or_missing_edges");
        }
        let arguments = [7, 6, 2, 1, 8, 9]
            .into_iter()
            .map(|k| {
                if let Some(state) = &state {
                    let fact = &state[k];
                    indexes.extend(fact.defs.iter().copied());
                    Argument {
                        register: facts::NAMES[k],
                        value: if flow.incomplete { Value::Unknown } else { fact.value.clone() },
                        definition_addresses: fact.defs.iter().map(|&j| format!("{:#x}", insns[j].ip())).collect(),
                        definitions_truncated: fact.truncated,
                    }
                } else {
                    Argument {
                        register: facts::NAMES[k],
                        value: Value::Unknown,
                        definition_addresses: vec![],
                        definitions_truncated: false,
                    }
                }
            })
            .collect();
        if indexes.len() > 96 {
            warnings.push("instruction_evidence_truncated_use_asm_query");
            complete = false;
        }
        let instructions =
            indexes.into_iter().take(96).map(|i| self.evidence_instruction(&insns[i], code, function.start)).collect();
        Ok(CallContext {
            function: self.function_info(&function),
            call: self.evidence_instruction(&insns[call], code, function.start),
            arguments,
            guards,
            instructions,
            complete_under_model: complete,
            warnings,
        })
    }
    fn evidence_instruction(&self, ins: &iced_x86::Instruction, code: &[u8], start: u64) -> InstructionRow {
        let at = usize::try_from(ins.ip() - start).unwrap_or(usize::MAX - 16);
        let mut bytes = String::new();
        for byte in code.get(at..at + ins.len()).unwrap_or_default() {
            let _ = write!(bytes, "{byte:02x}");
        }
        InstructionRow {
            address: format!("{:#x}", ins.ip()),
            rva: format!("{:#x}", ins.ip().saturating_sub(self.base)),
            size_bytes: ins.len(),
            bytes,
            valid: !ins.is_invalid(),
            text: scan::format(ins),
            memory_address: ins.is_ip_rel_memory_operand().then(|| format!("{:#x}", ins.ip_rel_memory_address())),
            direct_branch_target: scan::branch_target(ins).map(|ip| format!("{ip:#x}")),
        }
    }
}
