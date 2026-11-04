/*
 * xref Serde field map ELF fixture
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
// Ordinary Serde derives, native layout oracles and exported entry points.
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Serialize, Deserialize)]
pub struct Payload {
    pub narrow: u16,
    #[serde(rename = "payload")]
    pub wide: u64,
    pub flag: u8,
    #[serde(skip)]
    pub omitted: String,
    pub nested: Nested,
    pub unit: (),
}
#[derive(Serialize, Deserialize)]
pub struct Nested {
    pub child: u8,
    pub trailing: u32,
}
#[derive(Serialize, Deserialize)]
pub struct Other {
    pub payload: u32,
    pub stamp: u64,
}
#[derive(Serialize, Deserialize)]
pub struct ShortRecord {
    pub c: u64,
    pub m: u64,
    pub e: u64,
}

static PACKED_KEYS: &str = "cme";
#[derive(Deserialize)]
pub struct PackedRecord {
    pub c: u64,
    pub m: u64,
    pub e: u64,
}

pub struct SplitRecord {
    pub x: u64,
    pub y: u64,
    pub z: u64,
}

#[inline(never)]
fn emit_x<S: SerializeStruct>(state: &mut S, value: &u64) -> Result<(), S::Error> {
    state.serialize_field("x", value)
}
#[inline(never)]
fn emit_y<S: SerializeStruct>(state: &mut S, value: &u64) -> Result<(), S::Error> {
    state.serialize_field("y", value)
}
#[inline(never)]
fn emit_z<S: SerializeStruct>(state: &mut S, value: &u64) -> Result<(), S::Error> {
    state.serialize_field("z", value)
}
impl Serialize for SplitRecord {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SplitRecord", 3)?;
        emit_x(&mut state, &self.x)?;
        emit_y(&mut state, &self.y)?;
        emit_z(&mut state, &self.z)?;
        state.end()
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn serialize_split_entry(value: &SplitRecord, output: &mut String) {
    *output = serde_json::to_string(value).unwrap();
}

impl Serialize for PackedRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PackedRecord", 3)?;
        state.serialize_field(&PACKED_KEYS[0..1], &self.c)?;
        state.serialize_field(&PACKED_KEYS[1..2], &self.m)?;
        state.serialize_field(&PACKED_KEYS[2..3], &self.e)?;
        state.end()
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn serialize_payload_entry(value: &Payload, output: &mut String) {
    *output = serde_json::to_string(value).unwrap();
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn serialize_nested_entry(value: &Nested, output: &mut String) {
    *output = serde_json::to_string(value).unwrap();
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn serialize_other_entry(value: &Other, output: &mut String) {
    *output = serde_json::to_string(value).unwrap();
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn serialize_short_entry(value: &ShortRecord, output: &mut String) {
    *output = serde_json::to_string(value).unwrap();
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn serialize_packed_entry(value: &PackedRecord, output: &mut String) {
    *output = serde_json::to_string(value).unwrap();
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn update_payload_stage(value: &mut Payload, amount: u64) {
    value.wide = value.wide.wrapping_add(amount);
    value.narrow ^= 3;
    value.flag ^= 1;
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn update_short_stage(value: &mut ShortRecord, amount: u64) {
    value.m = value.m.wrapping_add(amount);
    value.e ^= amount;
    let output = serde_json::to_string(value).unwrap();
    std::hint::black_box(output);
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn related_short_writer(value: &mut ShortRecord, amount: u64) {
    value.m = value.m.wrapping_add(amount);
    value.e ^= amount;
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn process_short(value: &mut ShortRecord, amount: u64) {
    update_short_stage(value, amount);
    related_short_writer(value, amount);
}

macro_rules! decoy_writers {
    ($($name:ident),* $(,)?) => {
        $(#[unsafe(no_mangle)] #[inline(never)]
        pub extern "C" fn $name(value: &mut ShortRecord, amount: u64) {
            let digits = stringify!($name).as_bytes();
            let salt = u64::from(digits[5] - b'0') * 10 + u64::from(digits[6] - b'0');
            value.m ^= amount.wrapping_add(salt);
            value.e = value.e.wrapping_add(amount);
        })*
        static DECOY_WRITERS: &[extern "C" fn(&mut ShortRecord, u64)] = &[$($name),*];
    };
}
decoy_writers!(
    decoy00, decoy01, decoy02, decoy03, decoy04, decoy05, decoy06, decoy07, decoy08, decoy09, decoy10, decoy11,
    decoy12, decoy13, decoy14, decoy15, decoy16, decoy17, decoy18, decoy19, decoy20, decoy21, decoy22, decoy23,
    decoy24, decoy25, decoy26, decoy27, decoy28, decoy29, decoy30, decoy31, decoy32, decoy33, decoy34, decoy35,
    decoy36, decoy37, decoy38, decoy39, decoy40, decoy41, decoy42, decoy43, decoy44, decoy45, decoy46, decoy47,
    decoy48, decoy49, decoy50, decoy51, decoy52, decoy53, decoy54, decoy55, decoy56, decoy57, decoy58, decoy59,
    decoy60, decoy61, decoy62, decoy63, decoy64, decoy65, decoy66, decoy67, decoy68, decoy69,
);

#[repr(C)]
pub struct Unrelated {
    pad: [u8; std::mem::offset_of!(Payload, wide)],
    coincident: u64,
    far: [u64; 16],
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn update_unrelated(value: &mut Unrelated, amount: u64) {
    value.coincident = value.coincident.wrapping_add(amount);
    value.far[13] = value.far[13].wrapping_add(1);
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn log_only_entry(value: &Payload, output: &mut String) {
    *output = format!("log_only_name{}", value.wide);
}

fn main() {
    let seed = std::hint::black_box(u64::from(std::process::id()));
    let mut payload = Payload {
        narrow: seed as u16,
        wide: seed,
        flag: (seed >> 8) as u8,
        omitted: "skip".into(),
        nested: Nested { child: seed as u8, trailing: seed as u32 },
        unit: (),
    };
    let mut output = String::new();
    serialize_payload_entry(&payload, &mut output);
    let restored: Payload = serde_json::from_str(&output).unwrap();
    assert_eq!(restored.wide, payload.wide);
    update_payload_stage(&mut payload, 1);
    serialize_nested_entry(&payload.nested, &mut output);
    serialize_other_entry(&Other { payload: seed as u32, stamp: seed }, &mut output);
    let mut short = ShortRecord { c: seed, m: seed + 1, e: seed + 2 };
    serialize_short_entry(&short, &mut output);
    process_short(&mut short, 1);
    std::hint::black_box(DECOY_WRITERS);
    std::hint::black_box(short);
    let packed = PackedRecord { c: seed, m: seed + 1, e: seed + 2 };
    serialize_packed_entry(&packed, &mut output);
    std::hint::black_box(output.clone());
    let split = SplitRecord { x: seed, y: seed + 1, z: seed + 2 };
    serialize_split_entry(&split, &mut output);
    std::hint::black_box(output.clone());
    let _: Other =
        serde_json::from_str(&format!("{{\"payload\":{},\"stamp\":{},\"unknown\":true}}", seed as u32, seed)).unwrap();
    let mut unrelated = Unrelated { pad: [0; std::mem::offset_of!(Payload, wide)], coincident: seed, far: [0; 16] };
    update_unrelated(&mut unrelated, 1);
    std::hint::black_box(unrelated);
    log_only_entry(&payload, &mut output);
    std::hint::black_box(&output);
    println!("Payload.payload={}", std::mem::offset_of!(Payload, wide));
    println!("Payload.narrow={}", std::mem::offset_of!(Payload, narrow));
    println!("Payload.flag={}", std::mem::offset_of!(Payload, flag));
    println!("Payload.nested={}", std::mem::offset_of!(Payload, nested));
    println!("Payload.child={}", std::mem::offset_of!(Payload, nested) + std::mem::offset_of!(Nested, child));
    println!("Payload.trailing={}", std::mem::offset_of!(Payload, nested) + std::mem::offset_of!(Nested, trailing));
    println!("Payload.size={}", std::mem::size_of::<Payload>());
    println!("Payload.unit={}", std::mem::offset_of!(Payload, unit));
    println!("Nested.child={}", std::mem::offset_of!(Nested, child));
    println!("Nested.trailing={}", std::mem::offset_of!(Nested, trailing));
    println!("Other.payload={}", std::mem::offset_of!(Other, payload));
    println!("Other.stamp={}", std::mem::offset_of!(Other, stamp));
    println!("ShortRecord.c={}", std::mem::offset_of!(ShortRecord, c));
    println!("ShortRecord.m={}", std::mem::offset_of!(ShortRecord, m));
    println!("ShortRecord.e={}", std::mem::offset_of!(ShortRecord, e));
    println!("PackedRecord.c={}", std::mem::offset_of!(PackedRecord, c));
    println!("PackedRecord.m={}", std::mem::offset_of!(PackedRecord, m));
    println!("PackedRecord.e={}", std::mem::offset_of!(PackedRecord, e));
    println!("SplitRecord.x={}", std::mem::offset_of!(SplitRecord, x));
    println!("SplitRecord.y={}", std::mem::offset_of!(SplitRecord, y));
    println!("SplitRecord.z={}", std::mem::offset_of!(SplitRecord, z));
}
