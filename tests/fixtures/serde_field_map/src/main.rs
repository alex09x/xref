/*
 * xref Serde field map ELF fixture
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
// Ordinary Serde derives, native layout oracles and exported entry points.
use serde::{Deserialize,Serialize};

#[derive(Serialize,Deserialize)]
pub struct Payload {
    pub narrow:u16,
    #[serde(rename="payload")]
    pub wide:u64,
    pub flag:u8,
    #[serde(skip)]
    pub omitted:String,
    pub nested:Nested,
    pub unit:(),
}
#[derive(Serialize,Deserialize)]
pub struct Nested {pub child:u8,pub trailing:u32}
#[derive(Serialize,Deserialize)]
pub struct Other {pub payload:u32,pub stamp:u64}
#[derive(Serialize,Deserialize)]
pub struct ShortRecord {pub c:u64,pub m:u64,pub e:u64}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn serialize_payload_entry(value:&Payload,output:&mut String) {
    *output=serde_json::to_string(value).unwrap();
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn serialize_nested_entry(value:&Nested,output:&mut String) {
    *output=serde_json::to_string(value).unwrap();
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn serialize_other_entry(value:&Other,output:&mut String) {
    *output=serde_json::to_string(value).unwrap();
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn serialize_short_entry(value:&ShortRecord,output:&mut String) {
    *output=serde_json::to_string(value).unwrap();
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn update_payload_stage(value:&mut Payload,amount:u64) {
    value.wide=value.wide.wrapping_add(amount);
    value.narrow^=3;
    value.flag^=1;
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn update_short_stage(value:&mut ShortRecord,amount:u64) {
    value.m=value.m.wrapping_add(amount);
    value.e^=amount;
    let output=serde_json::to_string(value).unwrap();
    std::hint::black_box(output);
}

#[repr(C)]
pub struct Unrelated {
    pad:[u8;std::mem::offset_of!(Payload,wide)],
    coincident:u64,
    far:[u64;16],
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn update_unrelated(value:&mut Unrelated,amount:u64) {
    value.coincident=value.coincident.wrapping_add(amount);
    value.far[13]=value.far[13].wrapping_add(1);
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn log_only_entry(value:&Payload,output:&mut String) {
    *output=format!("log_only_name{}",value.wide);
}

fn main() {
    let seed=std::hint::black_box(u64::from(std::process::id()));
    let mut payload=Payload {narrow:seed as u16,wide:seed,flag:(seed>>8) as u8,omitted:"skip".into(),nested:Nested {child:seed as u8,trailing:seed as u32},unit:()};
    let mut output=String::new();
    serialize_payload_entry(&payload,&mut output);
    let restored:Payload=serde_json::from_str(&output).unwrap();
    assert_eq!(restored.wide,payload.wide);
    update_payload_stage(&mut payload,1);
    serialize_nested_entry(&payload.nested,&mut output);
    serialize_other_entry(&Other {payload:seed as u32,stamp:seed},&mut output);
    let mut short=ShortRecord {c:seed,m:seed+1,e:seed+2};
    serialize_short_entry(&short,&mut output);
    update_short_stage(&mut short,1);
    std::hint::black_box(short);
    let _:Other=serde_json::from_str(&format!("{{\"payload\":{},\"stamp\":{},\"unknown\":true}}",seed as u32,seed)).unwrap();
    let mut unrelated=Unrelated {pad:[0;std::mem::offset_of!(Payload,wide)],coincident:seed,far:[0;16]};
    update_unrelated(&mut unrelated,1);
    std::hint::black_box(unrelated);
    log_only_entry(&payload,&mut output);
    std::hint::black_box(&output);
    println!("Payload.payload={}",std::mem::offset_of!(Payload,wide));
    println!("Payload.narrow={}",std::mem::offset_of!(Payload,narrow));
    println!("Payload.flag={}",std::mem::offset_of!(Payload,flag));
    println!("Payload.nested={}",std::mem::offset_of!(Payload,nested));
    println!("Payload.child={}",std::mem::offset_of!(Payload,nested)+std::mem::offset_of!(Nested,child));
    println!("Payload.trailing={}",std::mem::offset_of!(Payload,nested)+std::mem::offset_of!(Nested,trailing));
    println!("Payload.size={}",std::mem::size_of::<Payload>());
    println!("Payload.unit={}",std::mem::offset_of!(Payload,unit));
    println!("Nested.child={}",std::mem::offset_of!(Nested,child));
    println!("Nested.trailing={}",std::mem::offset_of!(Nested,trailing));
    println!("Other.payload={}",std::mem::offset_of!(Other,payload));
    println!("Other.stamp={}",std::mem::offset_of!(Other,stamp));
    println!("ShortRecord.c={}",std::mem::offset_of!(ShortRecord,c));
    println!("ShortRecord.m={}",std::mem::offset_of!(ShortRecord,m));
    println!("ShortRecord.e={}",std::mem::offset_of!(ShortRecord,e));
}
