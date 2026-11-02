/*
 * XRef Code — Bounded structured result pages
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::types::{ApiError, Page, Pagination};
use std::collections::BTreeMap;

pub(super) struct Rows<T> {
    values: BTreeMap<u64, T>,
    capacity: usize,
}

impl<T> Rows<T> {
    pub fn new(page: &Page) -> Result<Self, ApiError> {
        if !(1..=100).contains(&page.limit) || page.offset > 10000 {
            return Err(ApiError::new("invalid_page", "limit must be 1..100 and offset at most 10000"));
        }
        Ok(Self { values: BTreeMap::new(), capacity: page.offset + page.limit + 1 })
    }

    pub fn insert(&mut self, address: u64, make: impl FnOnce() -> T) {
        if self.values.contains_key(&address) {
            return;
        }
        if self.values.len() == self.capacity && self.values.last_key_value().is_some_and(|(&last, _)| address >= last)
        {
            return;
        }
        self.values.insert(address, make());
        if self.values.len() > self.capacity {
            self.values.pop_last();
        }
    }

    pub fn finish(self, page: &Page) -> Result<(Vec<T>, Pagination), ApiError> {
        if page.offset > self.values.len() {
            return Err(ApiError::new("invalid_offset", "offset is past the result set"));
        }
        let more = self.values.len() > page.offset + page.limit;
        let rows: Vec<T> = self.values.into_values().skip(page.offset).take(page.limit).collect();
        let next_offset = more.then_some(page.offset + rows.len()).filter(|&offset| offset <= 10000);
        let meta =
            Pagination { unit: "items", offset: page.offset, returned: rows.len(), next_offset, complete: !more };
        Ok((rows, meta))
    }
}
