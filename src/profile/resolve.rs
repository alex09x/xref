/*
 * XRef — sampled address and mapping attribution
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::names::ModuleNames;
use super::types::remove_slide;
use super::{
    aggregate::{Frame, FunctionKey},
    types::{Header, Mapping},
};
use crate::image::Image;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

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
    /// Where the function names came from (`symtab`, `dynsym`, `debug_file`, `debuginfod`,
    /// `kallsyms`, `vdso`); absent when the module has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_source: Option<&'static str>,
    #[serde(skip)]
    pub names: Option<Arc<ModuleNames>>,
}

impl Module {
    const fn new(id: u32, kind: &'static str, path: String) -> Self {
        Self {
            id,
            kind,
            path,
            device_major: 0,
            device_minor: 0,
            inode: 0,
            sha256: None,
            symbols_loaded: false,
            symbol_source: None,
            names: None,
        }
    }

    fn set_names(&mut self, names: Option<ModuleNames>) {
        if let Some(names) = names.filter(|names| !names.is_empty()) {
            self.symbol_source = Some(names.source);
            self.names = Some(Arc::new(names));
        }
    }
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
        let mut target_module = Module::new(1, "target", String::new());
        target_module.inode = header.exe_inode;
        target_module.sha256.clone_from(&header.process_exe_sha256);
        target_module.symbols_loaded = true;
        let mut modules = vec![
            Module::new(0, "unknown", String::new()),
            target_module,
            Module::new(2, "kernel", "[kernel]".to_owned()),
        ];
        // Kernel and vdso addresses are those of one boot: name them only for this boot's recordings.
        let this_boot = super::names::recorded_in_this_boot(&mappings);
        mappings.retain(|mapping| !(mapping.pid == 0 && mapping.path == super::names::BOOT_MARKER_PATH));
        if this_boot {
            modules[2].set_names(super::names::kallsyms());
            modules[2].symbols_loaded = modules[2].names.is_some();
        }
        let vdso_names = if this_boot { super::names::own_vdso().map(Arc::new) } else { None };
        let mut vdso_id = None;
        let mut interned = BTreeMap::new();
        let mut indexed = Vec::with_capacity(mappings.len());
        let mut max_end = Vec::with_capacity(mappings.len());
        let mut previous_end = 0;
        for mapping in mappings {
            let target = u64::from(mapping.device_major) == header.exe_device_major
                && u64::from(mapping.device_minor) == header.exe_device_minor
                && mapping.inode == header.exe_inode
                && mapping.inode != 0;
            let id = if mapping.path == "[vdso]" {
                // Its own module even without names (another boot), so its samples are not
                // merged into the unknown module.
                *vdso_id.get_or_insert_with(|| {
                    let id = u32::try_from(modules.len()).unwrap_or(u32::MAX);
                    let mut module = Module::new(id, "vdso", "[vdso]".to_owned());
                    if let Some(names) = &vdso_names {
                        module.symbols_loaded = true;
                        module.symbol_source = Some(names.source);
                        module.names = Some(Arc::clone(names));
                    }
                    modules.push(module);
                    id
                })
            } else if target {
                if modules[1].path.is_empty() {
                    modules[1].path.clone_from(&mapping.path);
                    modules[1].device_major = mapping.device_major;
                    modules[1].device_minor = mapping.device_minor;
                }
                1
            } else if mapping.path.is_empty() || (mapping.inode == 0 && mapping.sha256.is_none()) {
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
                    let mut module = Module::new(id, "shared_object", mapping.path.clone());
                    module.device_major = mapping.device_major;
                    module.device_minor = mapping.device_minor;
                    module.inode = mapping.inode;
                    module.sha256.clone_from(&mapping.sha256);
                    modules.push(module);
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
                module.set_names(super::names::for_library(&image, &module.path));
                images.insert(module.id, image);
            }
        }
        Self { mappings: indexed, max_end, modules, images }
    }

    fn names(&self, module: u32) -> Option<&ModuleNames> {
        self.modules.get(usize::try_from(module).ok()?).filter(|m| m.id == module)?.names.as_deref()
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
        let address = if return_address { ip.saturating_sub(1) } else { ip };
        if kernel {
            let start = self.names(2).and_then(|names| names.start_containing(address));
            return Frame { function: FunctionKey { module: 2, start }, instruction: None };
        }
        let best = self.mapping_at(pid, timestamp_ns, address);
        let module = best.map_or(0, |(_, module)| module);
        if let Some((mapping, _)) = best
            && self.modules.get(usize::try_from(module).unwrap_or(usize::MAX)).is_some_and(|m| m.kind == "vdso")
        {
            // vdso names are offsets from the start of the mapping.
            let offset = address.checked_sub(mapping.start);
            let start = offset.and_then(|offset| self.names(module)?.start_containing(offset));
            return Frame { function: FunctionKey { module, start }, instruction: None };
        }
        let selected = if module == 1 { Some(image) } else { self.images.get(&module) };
        let static_ip = if module == 1 {
            best.and_then(|(mapping, _)| target_slide(image, header, mapping))
                .and_then(|slide| remove_slide(address, slide))
        } else {
            best.and_then(|(mapping, _)| selected.and_then(|image| static_address(image, mapping, address)))
        };
        let start = static_ip.and_then(|address| {
            // A library function is keyed by the symbol holding the sample, so the report can name
            // it even when its CFI ranges start elsewhere or it has none; CFI covers the rest.
            let named = (module != 1).then(|| self.names(module)?.start_containing(address)).flatten();
            named.or_else(|| selected.and_then(|image| image.function_at(address)).map(|range| range.start))
        });
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

    #[allow(clippy::too_many_arguments)] // The unwinder lookup needs the sample identity and the target image.
    pub fn unwinder_key(
        &self,
        image: &Image,
        header: &Header,
        pid: u32,
        timestamp_ns: u64,
        ip: u64,
        return_address: bool,
    ) -> Option<(u32, i64)> {
        let address = if return_address { ip.checked_sub(1)? } else { ip };
        let (mapping, module) = self.mapping_at(pid, timestamp_ns, address)?;
        if module == 1 {
            return Some((module, target_slide(image, header, mapping)?));
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
                target_slide(image, header, mapping)
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

/// The PIE slide of the target in the process of `mapping`: the recorded one for the first target,
/// and from the mapping itself for another process of the same binary (a separately started
/// instance followed by `--comm` loads elsewhere; a forked child keeps its parent's).
fn target_slide(image: &Image, header: &Header, mapping: &Mapping) -> Option<i64> {
    if mapping.pid == header.pid {
        return Some(header.pie_slide);
    }
    let base = static_address(image, mapping, mapping.start)?;
    i64::try_from(i128::from(mapping.start) - i128::from(base)).ok()
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
