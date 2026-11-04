/*
 * XRef — executable analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Propagate observed key references through direct callers, then retain connected
/// helper paths for roots that can reach the requested number of distinct keys.
pub(super) fn select(
    direct: &BTreeMap<u64, u16>,
    reverse: &BTreeMap<u64, BTreeSet<u64>>,
    forward: &BTreeMap<u64, BTreeSet<u64>>,
    minimum: usize,
    limit: usize,
    depth_limit: usize,
    exhaustive: bool,
) -> (BTreeSet<u64>, bool, bool, usize) {
    let mut masks = direct.clone();
    let mut propagation: VecDeque<_> = direct.iter().map(|(&function, &mask)| (function, mask, 0)).collect();
    if !exhaustive {
        while let Some((function, mask, depth)) = propagation.pop_front() {
            if depth >= depth_limit {
                continue;
            }
            for &parent in reverse.get(&function).into_iter().flatten() {
                let entry = masks.entry(parent).or_default();
                let added = mask & !*entry;
                if added != 0 {
                    *entry |= added;
                    propagation.push_back((parent, added, depth + 1));
                }
            }
        }
    }
    let direct_count = |function: u64| direct.get(&function).copied().unwrap_or(0).count_ones();
    let mut roots: Vec<_> = masks
        .iter()
        .filter(|(_, mask)| mask.count_ones() as usize >= minimum)
        .map(|(&function, &mask)| (function, mask.count_ones()))
        .collect();
    let fallback = !exhaustive && roots.is_empty();
    let use_partial = fallback || exhaustive;
    if use_partial {
        roots = direct.iter().map(|(&function, &mask)| (function, mask.count_ones())).collect();
    }
    roots.sort_by(|&(a, ac), &(b, bc)| {
        bc.cmp(&ac).then_with(|| direct_count(b).cmp(&direct_count(a))).then_with(|| a.cmp(&b))
    });
    let mut pending: VecDeque<_> = roots.into_iter().map(|(function, _)| function).collect();
    let mut selected = BTreeSet::new();
    let mut truncated = false;
    while let Some(function) = pending.pop_front() {
        if selected.contains(&function) {
            continue;
        }
        if selected.len() >= limit {
            truncated = true;
            break;
        }
        selected.insert(function);
        if use_partial {
            pending.extend(reverse.get(&function).into_iter().flatten().copied());
        } else {
            for &child in forward.get(&function).into_iter().flatten() {
                if masks.get(&child).copied().unwrap_or(0) != 0 {
                    pending.push_back(child);
                }
            }
        }
    }
    let excluded = if use_partial { 0 } else { direct.keys().filter(|function| !selected.contains(function)).count() };
    (selected, truncated, fallback, excluded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intersection_keeps_split_helpers_and_excludes_unrelated_references() {
        let direct = BTreeMap::from([(2, 0b01), (3, 0b10), (8, 0b01)]);
        let reverse = BTreeMap::from([(2, BTreeSet::from([1])), (3, BTreeSet::from([1]))]);
        let forward = BTreeMap::from([(1, BTreeSet::from([2, 3]))]);
        let (selected, truncated, fallback, excluded) = select(&direct, &reverse, &forward, 2, 10, 12, false);
        assert_eq!(selected, BTreeSet::from([1, 2, 3]));
        assert!(!truncated && !fallback);
        assert_eq!(excluded, 1);
        let (limited, truncated, _, _) = select(&direct, &reverse, &forward, 2, 2, 12, false);
        assert_eq!(limited.len(), 2);
        assert!(truncated);
    }

    #[test]
    fn many_single_key_references_do_not_fill_the_analysis_budget() {
        let mut direct = BTreeMap::from([(2, 0b001), (3, 0b010), (4, 0b100)]);
        direct.extend((100..8_300).map(|function| (function, 0b001)));
        let reverse = BTreeMap::from([(2, BTreeSet::from([1])), (3, BTreeSet::from([1])), (4, BTreeSet::from([1]))]);
        let forward = BTreeMap::from([(1, BTreeSet::from([2, 3, 4]))]);
        let (selected, truncated, fallback, excluded) = select(&direct, &reverse, &forward, 3, 512, 12, false);
        assert_eq!(selected, BTreeSet::from([1, 2, 3, 4]));
        assert!(!truncated && !fallback);
        assert_eq!(excluded, 8200);
        let (exhaustive, _, _, excluded) = select(&direct, &reverse, &forward, 3, 8192, 12, true);
        assert!(exhaustive.len() > selected.len());
        assert_eq!(excluded, 0);
    }

    #[test]
    fn direct_multi_key_match_is_not_crowded_out_by_wide_ancestors() {
        let mut direct = BTreeMap::from([(500_000, 0b111)]);
        let mut reverse = BTreeMap::new();
        let mut forward = BTreeMap::new();
        for child in 1..=500 {
            direct.insert(child, 0b001);
            forward.entry(100).or_insert_with(BTreeSet::new).insert(child);
            reverse.entry(child).or_insert_with(BTreeSet::new).insert(100);
        }
        for child in 501..=600 {
            direct.insert(child, 0b010);
            forward.entry(100).or_insert_with(BTreeSet::new).insert(child);
            reverse.entry(child).or_insert_with(BTreeSet::new).insert(100);
        }
        for child in 601..=700 {
            direct.insert(child, 0b100);
            forward.entry(100).or_insert_with(BTreeSet::new).insert(child);
            reverse.entry(child).or_insert_with(BTreeSet::new).insert(100);
        }
        let (selected, _, _, _) = select(&direct, &reverse, &forward, 3, 10, 12, false);
        assert!(
            selected.contains(&500_000),
            "direct 3-key seed must be retained even with wide ancestors: {selected:?}"
        );
    }
}
