/*
 * XRef — sampled address and mapping attribution
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    aggregate::{Frame, FunctionKey},
    types::{Header, Mapping},
};
use crate::{image::Image, live::types::remove_slide};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;

const MAX_MODULE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_MODULE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct Module {
    pub id: u32,
    pub kind: &'static str,
    pub path: String,
    pub device_major: u32,
    pub device_minor: u32,
    pub inode: u64,
    pub sha256: Option<String>,
    pub symbols_loaded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ModuleIdentity {
    major: u32,
    minor: u32,
    inode: u64,
    path: String,
    sha256: Option<String>,
}

pub struct MappingIndex {
    mappings: Vec<(Mapping, u32)>,
    max_end: Vec<u64>,
    pub modules: Vec<Module>,
    images: BTreeMap<u32, Image>,
}

impl MappingIndex {
    pub fn new(mut mappings: Vec<Mapping>, header: &Header) -> Self {
        mappings.sort_by(|a, b| {
            (a.start, a.timestamp_ns, &a.path, a.inode).cmp(&(b.start, b.timestamp_ns, &b.path, b.inode))
        });
        let mut modules = vec![
            Module {
                id: 0,
                kind: "unknown",
                path: String::new(),
                device_major: 0,
                device_minor: 0,
                inode: 0,
                sha256: None,
                symbols_loaded: false,
            },
            Module {
                id: 1,
                kind: "target",
                path: String::new(),
                device_major: 0,
                device_minor: 0,
                inode: header.exe_inode,
                sha256: header.process_exe_sha256.clone(),
                symbols_loaded: true,
            },
            Module {
                id: 2,
                kind: "kernel",
                path: "[kernel]".to_owned(),
                device_major: 0,
                device_minor: 0,
                inode: 0,
                sha256: None,
                symbols_loaded: false,
            },
        ];
        let mut interned = BTreeMap::new();
        let mut indexed = Vec::with_capacity(mappings.len());
        let mut max_end = Vec::with_capacity(mappings.len());
        let mut previous_end = 0;
        for mapping in mappings {
            let target = u64::from(mapping.device_major) == header.exe_device_major
                && u64::from(mapping.device_minor) == header.exe_device_minor
                && mapping.inode == header.exe_inode
                && mapping.inode != 0;
            let id = if target {
                if modules[1].path.is_empty() {
                    modules[1].path.clone_from(&mapping.path);
                    modules[1].device_major = mapping.device_major;
                    modules[1].device_minor = mapping.device_minor;
                }
                1
            } else if mapping.inode == 0 || mapping.path.is_empty() {
                0
            } else {
                let identity = ModuleIdentity {
                    major: mapping.device_major,
                    minor: mapping.device_minor,
                    inode: mapping.inode,
                    path: mapping.path.clone(),
                    sha256: mapping.sha256.clone(),
                };
                *interned.entry(identity).or_insert_with(|| {
                    let id = u32::try_from(modules.len()).unwrap_or(u32::MAX);
                    modules.push(Module {
                        id,
                        kind: "shared_object",
                        path: mapping.path.clone(),
                        device_major: mapping.device_major,
                        device_minor: mapping.device_minor,
                        inode: mapping.inode,
                        sha256: mapping.sha256.clone(),
                        symbols_loaded: false,
                    });
                    id
                })
            };
            previous_end = previous_end.max(mapping.start.saturating_add(mapping.length));
            max_end.push(previous_end);
            indexed.push((mapping, id));
        }
        let mut images = BTreeMap::new();
        let mut total = 0_u64;
        for module in &mut modules {
            if module.kind != "shared_object" {
                continue;
            }
            if let Some((image, size)) = load_verified_module(module, MAX_TOTAL_MODULE_BYTES.saturating_sub(total)) {
                total = total.saturating_add(size);
                module.symbols_loaded = true;
                images.insert(module.id, image);
            }
        }
        Self { mappings: indexed, max_end, modules, images }
    }

    /// An ambiguous mapping stays unresolved instead of being assigned by path.
    #[allow(clippy::too_many_arguments)] // The mapping lookup needs the full sample identity and address context.
    pub fn frame(
        &self,
        image: &Image,
        header: &Header,
        pid: u32,
        timestamp_ns: u64,
        ip: u64,
        kernel: bool,
        return_address: bool,
    ) -> Frame {
        if kernel {
            return Frame { function: FunctionKey { module: 2, start: None }, instruction: None };
        }
        let address = if return_address { ip.saturating_sub(1) } else { ip };
        let best = self.mapping_at(pid, timestamp_ns, address);
        let module = best.map_or(0, |(_, module)| module);
        let selected = if module == 1 { Some(image) } else { self.images.get(&module) };
        let static_ip = if module == 1 {
            remove_slide(address, header.pie_slide)
        } else {
            best.and_then(|(mapping, _)| selected.and_then(|image| static_address(image, mapping, address)))
        };
        let start = static_ip
            .and_then(|address| selected.and_then(|image| image.function_at(address)))
            .map(|range| range.start);
        Frame { function: FunctionKey { module, start }, instruction: static_ip }
    }

    fn mapping_at(&self, pid: u32, timestamp_ns: u64, address: u64) -> Option<(&Mapping, u32)> {
        let mut position = self.mappings.partition_point(|(mapping, _)| mapping.start <= address);
        let mut best: Option<(&Mapping, u32)> = None;
        let mut ambiguous = false;
        while position > 0 {
            position -= 1;
            if self.max_end[position] <= address {
                break;
            }
            let (mapping, module) = &self.mappings[position];
            if mapping.pid != pid
                || !mapping.executable
                || mapping.timestamp_ns > timestamp_ns
                || mapping.start.checked_add(mapping.length).is_none_or(|end| address >= end)
            {
                continue;
            }
            if let Some((previous, previous_module)) = best {
                if previous.timestamp_ns > mapping.timestamp_ns {
                    continue;
                }
                if previous.timestamp_ns == mapping.timestamp_ns && previous_module != *module {
                    ambiguous = true;
                    continue;
                }
            }
            best = Some((mapping, *module));
            ambiguous = false;
        }
        if ambiguous { None } else { best }
    }

    pub fn unwinder_key(
        &self,
        header: &Header,
        pid: u32,
        timestamp_ns: u64,
        ip: u64,
        return_address: bool,
    ) -> Option<(u32, i64)> {
        let address = if return_address { ip.checked_sub(1)? } else { ip };
        let (mapping, module) = self.mapping_at(pid, timestamp_ns, address)?;
        if module == 1 {
            return Some((module, header.pie_slide));
        }
        let selected = self.images.get(&module)?;
        let static_ip = static_address(selected, mapping, address)?;
        let slide = i64::try_from(i128::from(address) - i128::from(static_ip)).ok()?;
        Some((module, slide))
    }

    pub fn unwinders<'a>(
        &'a self,
        image: &'a Image,
        header: &Header,
    ) -> BTreeMap<(u32, i64), super::unwind::Unwinder<'a>> {
        let mut result = BTreeMap::new();
        for (mapping, module) in &self.mappings {
            if !mapping.executable || *module == 0 {
                continue;
            }
            let selected = if *module == 1 {
                image
            } else if let Some(image) = self.images.get(module) {
                image
            } else {
                continue;
            };
            let slide = if *module == 1 {
                Some(header.pie_slide)
            } else {
                static_address(selected, mapping, mapping.start)
                    .and_then(|address| i64::try_from(i128::from(mapping.start) - i128::from(address)).ok())
            };
            if let Some(slide) = slide
                && !result.contains_key(&(*module, slide))
                && let Ok(unwinder) = super::unwind::Unwinder::new(selected, slide)
            {
                result.insert((*module, slide), unwinder);
            }
        }
        result
    }
}

fn load_verified_module(module: &Module, remaining: u64) -> Option<(Image, u64)> {
    let expected = module.sha256.as_deref()?;
    if !std::path::Path::new(&module.path).is_absolute() || module.path.ends_with(" (deleted)") {
        return None;
    }
    let file = std::fs::File::open(&module.path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_MODULE_BYTES || metadata.len() > remaining {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_MODULE_BYTES + 1).read_to_end(&mut bytes).ok()?;
    let length = u64::try_from(bytes.len()).ok()?;
    if length != metadata.len()
        || length > MAX_MODULE_BYTES
        || length > remaining
        || crate::trace_analysis::index::hex_bytes(&Sha256::digest(&bytes)) != expected
    {
        return None;
    }
    Some((Image::parse(bytes).ok()?, length))
}

fn static_address(image: &Image, mapping: &Mapping, address: u64) -> Option<u64> {
    let mut matches = image.metadata.load_segments.iter().filter_map(|segment| {
        let page = segment.file_offset & !4095;
        let end = segment.file_offset.checked_add(segment.file_size)?.checked_add(4095)? & !4095;
        if mapping.file_offset < page || mapping.file_offset >= end || segment.executable != mapping.executable {
            return None;
        }
        (segment.va & !4095).checked_add(mapping.file_offset - page)?.checked_add(address.checked_sub(mapping.start)?)
    });
    let value = matches.next()?;
    if matches.any(|other| other != value) {
        return None;
    }
    Some(value)
}
