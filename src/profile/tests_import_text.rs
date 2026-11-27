/*
 * XRef — tests: perf-script text import from a `perf record -- CMD` recording
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::codec::ProfileReader;
use super::types::Record;

/// `perf script -F comm,pid,tid,time,ip,sym,dso --show-mmap-events` of a program started by
/// `perf record -- ./mtbin`: a sample of `perf-exec` before the exec, the target's MMAP2, then
/// samples of two threads (headers carry no event name).
const TEXT: &str = "\
perf-exec  100/100  10.000001: \n\tffffffff81ac76f3 native_write_msr ([kernel.kallsyms])\n\n\
mtbin  100/100  10.000010: PERF_RECORD_MMAP2 100/100: [0x5000(0x1000) @ 0x1000 fc:00 7 9]: r-xp /srv/app/mtbin\n\
mtbin  100/100  10.000020: \n\t5010 serial_step (/srv/app/mtbin)\n\t5100 main (/srv/app/mtbin)\n\n\
mtbin  100/101  10.000030: \n\t5020 worker_step (/srv/app/mtbin)\n\n\
mtbin  100/100  10.000040: \n\t5010 serial_step (/srv/app/mtbin)\n\n";

fn image() -> crate::image::Image {
    let mut image = crate::image::Image::default();
    image.metadata.load_segments.push(crate::image_format::LoadSegment {
        va: 0x1000,
        file_offset: 0x1000,
        file_size: 0x1000,
        mem_size: 0x1000,
        executable: true,
        writable: false,
    });
    image
}

fn import(tids: &[u32]) -> Result<(i64, Vec<u32>), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (input, output, bin) = (dir.path().join("script.txt"), dir.path().join("out.xprof"), dir.path().join("mtbin"));
    std::fs::write(&input, TEXT)?;
    let options = super::import_text::Options {
        bin: &bin,
        input: &input,
        output: &output,
        base: None,
        maps: None,
        target_path: None,
        pid: Some(100),
        tids,
    };
    super::import_text::run(&image(), &options)?;
    let mut reader = ProfileReader::new(std::fs::File::open(&output)?)?;
    let slide = reader.header.pie_slide;
    let mut threads = Vec::new();
    while let Some(record) = reader.read_record()? {
        if let Record::Sample(sample) = record {
            threads.push(sample.tid);
        }
    }
    Ok((slide, threads))
}

#[test]
fn text_without_base_takes_the_target_from_its_mmap2_and_skips_what_ran_before_the_exec()
-> Result<(), Box<dyn std::error::Error>> {
    let (slide, threads) = import(&[])?;
    // The target's text segment (file offset 0x1000, VA 0x1000) is mapped at 0x5000.
    assert_eq!(slide, 0x4000);
    // The perf-exec sample before the MMAP2 is left out; both threads are kept.
    assert_eq!(threads, vec![100, 101, 100]);
    Ok(())
}

#[test]
fn text_import_keeps_only_the_given_threads() -> Result<(), Box<dyn std::error::Error>> {
    let (_, threads) = import(&[101])?;
    assert_eq!(threads, vec![101]);
    Ok(())
}
