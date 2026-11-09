/*
 * XRef Code — The function card as the structured API returns it
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `crate::card::model::FunctionCard` for `operation = "card"`: addresses as `0x…` strings, as
//! everywhere else in the structured API (and exact above 2^53), and every list capped so that the
//! card fits a response; the totals say how much was left out. `xref card --json` keeps the model.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::Serialize;

use crate::card::model::{CardInputs, FieldStore, FunctionCard};

/// Serialized card bytes at most, leaving room in the 64 KiB response for the envelope.
const CARD_BUDGET: usize = 48 * 1024;
/// Rows per list tried first, then halved until the card fits.
const FIRST_CAP: usize = 64;

#[derive(Debug, Serialize, JsonSchema)]
pub struct CardView {
    pub function: CardSpan,
    pub inputs: CardInputs,
    pub return_registers: Vec<String>,
    pub stores: BTreeMap<String, Vec<FieldStore>>,
    pub callees: Vec<CardCallee>,
    pub indirect_calls: Vec<CardIndirect>,
    pub panic_callees: Vec<CardCallee>,
    pub exits: Vec<CardExit>,
    /// The full length of every list, before the cap.
    pub totals: CardTotals,
    /// Whether any list was cut to fit the response.
    pub truncated: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CardSpan {
    pub start: String,
    pub end: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CardCallee {
    pub ip: String,
    pub target: String,
    pub name: String,
    /// Recovered argument values (panic calls have none).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CardIndirect {
    pub ip: String,
    pub target: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CardExit {
    pub ip: String,
    pub return_registers: Vec<String>,
    pub constant_code: Option<i64>,
    pub is_error: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CardTotals {
    pub stores: usize,
    pub callees: usize,
    pub indirect_calls: usize,
    pub panic_callees: usize,
    pub exits: usize,
}

fn hex(value: u64) -> String {
    format!("{value:#x}")
}

impl CardView {
    /// The card with every list capped at `cap` rows (stores: at `cap` stores in all).
    fn capped(card: &FunctionCard, cap: usize) -> Self {
        let stores_total = card.stores.values().map(Vec::len).sum();
        let mut left = cap;
        let stores = card
            .stores
            .iter()
            .filter_map(|(base, list)| {
                let taken: Vec<FieldStore> = list.iter().take(left).cloned().collect();
                left -= taken.len();
                (!taken.is_empty()).then(|| (base.clone(), taken))
            })
            .collect();
        let totals = CardTotals {
            stores: stores_total,
            callees: card.callees.len(),
            indirect_calls: card.indirect_calls.len(),
            panic_callees: card.panic_callees.len(),
            exits: card.exits.len(),
        };
        let truncated = [totals.stores, totals.callees, totals.indirect_calls, totals.panic_callees, totals.exits]
            .iter()
            .any(|&n| n > cap);
        Self {
            function: CardSpan {
                start: hex(card.function.start),
                end: hex(card.function.end),
                name: card.function.name.clone(),
            },
            inputs: card.inputs.clone(),
            return_registers: card.return_registers.clone(),
            stores,
            callees: card
                .callees
                .iter()
                .take(cap)
                .map(|c| CardCallee {
                    ip: hex(c.ip),
                    target: hex(c.target),
                    name: c.name.clone(),
                    args: c.args.clone(),
                })
                .collect(),
            indirect_calls: card
                .indirect_calls
                .iter()
                .take(cap)
                .map(|c| CardIndirect { ip: hex(c.ip), target: c.target.clone() })
                .collect(),
            panic_callees: card
                .panic_callees
                .iter()
                .take(cap)
                .map(|c| CardCallee { ip: hex(c.ip), target: hex(c.target), name: c.name.clone(), args: Vec::new() })
                .collect(),
            exits: card
                .exits
                .iter()
                .take(cap)
                .map(|e| CardExit {
                    ip: hex(e.ip),
                    return_registers: e.return_registers.clone(),
                    constant_code: e.constant_code,
                    is_error: e.is_error,
                })
                .collect(),
            totals,
            truncated,
        }
    }

    /// The card with the most rows per list that still fits `CARD_BUDGET`.
    #[must_use]
    pub fn fitted(card: &FunctionCard) -> Self {
        let mut cap = FIRST_CAP;
        loop {
            let view = Self::capped(card, cap);
            let fits = serde_json::to_vec(&view).is_ok_and(|bytes| bytes.len() <= CARD_BUDGET);
            if fits || cap == 0 {
                return view;
            }
            cap /= 2;
        }
    }
}
