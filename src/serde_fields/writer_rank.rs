/*
 * XRef — executable analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    FieldOptions,
    model::{AccessorCandidate, LayoutCandidate, Lead, ScoreTerms, TermDelta},
    writer_index::{Access, Entry},
};
use std::collections::{BTreeMap, BTreeSet};

/// Widest instruction read observed for each layout offset (8 when nothing was observed). A store wider
/// than this spans neighbouring fields, which is a whole-struct copy rather than a write of the field.
pub(super) fn field_widths(layout: &LayoutCandidate) -> BTreeMap<u64, usize> {
    let mut widths = BTreeMap::new();
    for field in &layout.fields {
        let width = field.observed_read_widths.iter().copied().max().unwrap_or(8).max(1);
        let slot = widths.entry(field.offset).or_insert(width);
        *slot = (*slot).max(width);
    }
    widths
}

/// Field-precise evidence on `argument` (#76): the most ranking offsets stored in one block by stores that
/// start at the field and are no wider than it, and whether a ranking field is read before it is written
/// (an update such as `cmp r, [p+0x10]` … `mov [p+0x10], r`). A root whose ranking slot is dereferenced
/// holds a pointer there (e.g. a `Vec` `{cap, ptr, len}`), so it earns neither credit.
pub(super) fn write_precision<'a>(
    accesses: impl Iterator<Item = &'a Access>,
    argument: usize,
    dereferenced: &[(usize, i64)],
    ranking: &BTreeSet<u64>,
    widths: &BTreeMap<u64, usize>,
) -> Precision {
    if dereferenced
        .iter()
        .any(|&(root, offset)| root == argument && u64::try_from(offset).is_ok_and(|offset| ranking.contains(&offset)))
    {
        return Precision::default();
    }
    let mut precise = BTreeMap::<usize, BTreeSet<u64>>::new();
    let mut covered = BTreeSet::new();
    let mut first_read = BTreeMap::<u64, u64>::new();
    let mut mutator = false;
    for access in accesses {
        if access.kind == "address" {
            continue;
        }
        let Some(range) = access.range() else { continue };
        if access.write {
            if let Ok(offset) = u64::try_from(access.offset)
                && let Some(width) = widths.get(&offset)
                && access.width <= *width
                && !stores_immediate(&access.assembly)
            {
                covered.insert(offset);
                if ranking.contains(&offset) {
                    precise.entry(access.block).or_default().insert(offset);
                }
            }
            mutator |= ranking.range(range).any(|offset| first_read.get(offset).is_some_and(|ip| *ip < access.ip));
        } else if access.kind == "conditional_read"
            || access.assembly.starts_with("cmp ")
            || access.assembly.starts_with("test ")
        {
            // Only a comparison of the field gates an update; a plain load before a store is common in
            // code that merely copies or initialises the value.
            for offset in ranking.range(range) {
                first_read.entry(*offset).and_modify(|ip| *ip = (*ip).min(access.ip)).or_insert(access.ip);
            }
        }
    }
    Precision { colocated: precise.values().map(BTreeSet::len).max().unwrap_or(0), covered: covered.len(), mutator }
}

/// A store of an immediate (`mov qword ptr [p+0x10], 0`) initialises a field, typically an enum tag or an
/// empty value; it is not evidence of an update that writes a computed value into the field.
fn stores_immediate(assembly: &str) -> bool {
    assembly.rsplit_once(", ").is_some_and(|(_, source)| {
        let digits = source.trim().trim_start_matches('-');
        digits
            .strip_prefix("0x")
            .map_or_else(|| digits.parse::<u64>().is_ok(), |hex| u64::from_str_radix(hex, 16).is_ok())
    })
}

/// Field-precise evidence for one root; see [`write_precision`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Precision {
    /// Most ranking fields stored by field-precise stores in one block.
    pub colocated: usize,
    /// Layout fields (queried or not) with a field-precise store anywhere in the function.
    pub covered: usize,
    /// A ranking field is read before it is written.
    pub mutator: bool,
}

/// A read that compares a field (`cmp`/`test` or a conditional read): conditional-update evidence.
pub(super) fn compares(access: &Access) -> bool {
    !access.write
        && (access.kind == "conditional_read"
            || access.assembly.starts_with("cmp ")
            || access.assembly.starts_with("test "))
}

/// Writer ranking points shared by the indexed and the direct accessor paths, without the call graph
/// (added by [`callgraph_points`] once the distance is known).
#[must_use]
pub(super) const fn writer_terms(colocated: usize, precision: Precision, conditional: bool) -> ScoreTerms {
    ScoreTerms {
        colocated: colocated * 8,
        precise: precision.colocated * 8,
        covered: precision.covered * 4,
        update: if precision.mutator { 8 } else { 0 },
        conditional: if conditional { 1 } else { 0 },
        callgraph: 0,
    }
}

/// Writer ranking score without the call graph; see [`writer_terms`].
#[cfg(test)]
#[must_use]
pub(super) const fn writer_score(colocated: usize, precision: Precision, conditional: bool) -> usize {
    writer_terms(colocated, precision, conditional).total()
}

/// Points for a direct-call distance from the serializer (none without a known path).
#[must_use]
pub(super) const fn callgraph_points(distance: Option<usize>) -> usize {
    match distance {
        Some(distance) => 7_usize.saturating_sub(distance) * 2,
        None => 0,
    }
}

/// Fill in each row's lead over the next listed row of a different function, then keep `limit` rows.
/// `rows` is ranked best first and may hold one row past `limit`; `complete` says every matching
/// candidate is among them, so a missing next function means there is none.
pub(super) fn annotate_leads(rows: &mut Vec<AccessorCandidate>, limit: usize, complete: bool) {
    for index in 0..rows.len().min(limit) {
        let row = &rows[index];
        let next = rows[index + 1..].iter().find(|other| other.function != row.function);
        let lead = next.map_or_else(
            || Lead {
                missing: Some(if complete { "no_other_candidate" } else { "next_candidate_beyond_limit" }),
                ..Lead::default()
            },
            |next| Lead {
                over: Some(next.function.clone()),
                points: Some(row.ranking_score.saturating_sub(next.ranking_score)),
                terms: row
                    .score_terms
                    .named()
                    .into_iter()
                    .zip(next.score_terms.named())
                    .filter(|((_, mine), (_, theirs))| mine != theirs)
                    .map(|((term, mine), (_, theirs))| TermDelta {
                        term,
                        points: i64::try_from(mine).unwrap_or(i64::MAX) - i64::try_from(theirs).unwrap_or(i64::MAX),
                    })
                    .collect(),
                missing: None,
            },
        );
        rows[index].lead = lead;
    }
    rows.truncate(limit);
}

pub(super) struct Plan {
    expected: Vec<u64>,
    queried: BTreeSet<u64>,
    required: Vec<BTreeSet<u64>>,
    ranking: BTreeSet<u64>,
    widths: BTreeMap<u64, usize>,
    masks: Option<Masks>,
}

struct Masks {
    queried: u128,
    required: Vec<u128>,
    ranking: u128,
}

impl Plan {
    pub fn new(layout: &LayoutCandidate, options: &FieldOptions) -> Self {
        let expected: Vec<_> =
            layout.fields.iter().map(|field| field.offset).collect::<BTreeSet<_>>().into_iter().collect();
        let required: Vec<BTreeSet<_>> = options
            .writes_all_of
            .iter()
            .map(|name| layout.fields.iter().filter(|field| &field.name == name).map(|field| field.offset).collect())
            .collect();
        let mut queried: BTreeSet<_> = layout.offsets.iter().map(|field| field.offset).collect();
        queried.extend(required.iter().flatten().copied());
        let ranking = if required.is_empty() {
            expected.iter().copied().collect()
        } else {
            required.iter().flatten().copied().collect()
        };
        let masks = (expected.len() <= 128).then(|| {
            let mask_for = |offsets: &BTreeSet<u64>| {
                expected.iter().enumerate().fold(0_u128, |mask, (index, offset)| {
                    if offsets.contains(offset) { mask | (1_u128 << index) } else { mask }
                })
            };
            Masks {
                queried: mask_for(&queried),
                required: required.iter().map(mask_for).collect(),
                ranking: mask_for(&ranking),
            }
        });
        Self { expected, queried, required, ranking, widths: field_widths(layout), masks }
    }

    /// Field-precise colocated stores and update evidence for `argument` (see [`write_precision`]).
    pub fn precision(&self, entry: &Entry, argument: usize) -> Precision {
        write_precision(
            entry.accesses.iter().filter(|access| access.argument == argument),
            argument,
            &entry.dereferenced,
            &self.ranking,
            &self.widths,
        )
    }

    pub fn score(&self, entry: &Entry, argument: usize, minimum: usize) -> Option<(usize, usize, usize)> {
        self.masks.as_ref().map_or_else(
            || self.score_large(entry, argument, minimum),
            |masks| self.score_mask(entry, argument, minimum, masks),
        )
    }

    fn score_mask(
        &self,
        entry: &Entry,
        argument: usize,
        minimum: usize,
        masks: &Masks,
    ) -> Option<(usize, usize, usize)> {
        let mut matched = 0_u128;
        let mut written = 0_u128;
        let mut current_block = None;
        let mut current_writes = 0_u128;
        let mut colocated = 0_usize;
        let mut conditional = false;
        for access in entry.accesses.iter().filter(|access| access.argument == argument) {
            let Some(range) = access.range() else { continue };
            let mut mask = 0_u128;
            for (index, offset) in self.expected.iter().enumerate() {
                if range.contains(offset) {
                    mask |= 1_u128 << index;
                }
            }
            if access.write {
                written |= mask;
                if current_block != Some(access.block) {
                    colocated = colocated.max(current_writes.count_ones() as usize);
                    current_writes = 0;
                    current_block = Some(access.block);
                }
                current_writes |= mask & masks.ranking;
            } else {
                if mask & masks.ranking != 0
                    && (access.kind == "conditional_read"
                        || access.assembly.starts_with("cmp ")
                        || access.assembly.starts_with("test "))
                {
                    conditional = true;
                }
                if !masks.required.is_empty() {
                    continue;
                }
            }
            matched |= mask;
        }
        if (matched.count_ones() as usize) < minimum
            || written & masks.queried == 0
            || masks.required.iter().any(|mask| written & mask == 0)
        {
            return None;
        }
        colocated = colocated.max(current_writes.count_ones() as usize);
        Some((colocated, usize::from(conditional), matched.count_ones() as usize))
    }

    fn score_large(&self, entry: &Entry, argument: usize, minimum: usize) -> Option<(usize, usize, usize)> {
        let mut matched = BTreeSet::new();
        let mut written = BTreeSet::new();
        let mut blocks = BTreeMap::<usize, BTreeSet<u64>>::new();
        let mut conditional = false;
        for access in entry.accesses.iter().filter(|access| access.argument == argument) {
            let Some(range) = access.range() else { continue };
            for &offset in &self.expected {
                if range.contains(&offset) {
                    if access.write {
                        written.insert(offset);
                        if self.ranking.contains(&offset) {
                            blocks.entry(access.block).or_default().insert(offset);
                        }
                    } else {
                        if self.ranking.contains(&offset)
                            && (access.kind == "conditional_read"
                                || access.assembly.starts_with("cmp ")
                                || access.assembly.starts_with("test "))
                        {
                            conditional = true;
                        }
                        if !self.required.is_empty() {
                            continue;
                        }
                    }
                    matched.insert(offset);
                }
            }
        }
        if matched.len() < minimum
            || written.is_disjoint(&self.queried)
            || self.required.iter().any(|offsets| written.is_disjoint(offsets))
        {
            return None;
        }
        let colocated = blocks.values().map(BTreeSet::len).max().unwrap_or(0);
        Some((colocated, usize::from(conditional), matched.len()))
    }
}
