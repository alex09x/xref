#!/usr/bin/env python3
# Synthetic input generator; compilation only, never execution.
# SPDX-License-Identifier: MIT OR Apache-2.0
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
COMPACT = """
.text
.p2align 4
.globl _macho_compact
_macho_compact:
.cfi_startproc
movl $11,%eax
retq
.cfi_endproc
"""
SIZES = {"_macho_entry":35,"_macho_helper":6,"_macho_export_return":6,
         "_macho_hidden":6,"_macho_pair":11,"_macho_import":18,"_macho_abort":11}
def capture(argv):
    return subprocess.run(argv,check=True,capture_output=True,text=True).stdout
def produce(name, version, kind="execute", mixed=False, basic=False):
    source=(ROOT/("basic.s" if basic else "rich.s")).read_text()
    output=ROOT/(name+".macho")
    with tempfile.TemporaryDirectory(prefix="xref-macho-input-") as temp:
        asm=Path(temp)/"input.s";asm.write_text(source)
        argv=["/usr/bin/xcrun","clang","-arch","x86_64","-mmacosx-version-min="+version,
              "-nostdlib","-Wl,-no_uuid",str(asm),"-lSystem","-o",str(output)]
        if mixed:
            compact=Path(temp)/"compact.c"
            compact.write_text("__attribute__((noinline)) int macho_compact(void) { return 11; }\n")
            argv+=["-O1",str(compact)]
        if kind=="execute": argv+=["-Wl,-e,_macho_entry"]
        elif kind=="dylib": argv+=["-dynamiclib","-Wl,-install_name,@rpath/libxref_fixture.dylib"]
        else: argv+=["-bundle"]
        subprocess.run(argv,check=True,capture_output=True)
    output.chmod(0o644)
    data=output.read_bytes()
    assert b"/Users/" not in data and b"/home/" not in data
    header=struct.unpack_from("<IiiIIIII",data)
    assert header[0]==0xfeedfacf and header[1]==0x01000007
    at=32;segments=[];sections={};commands=[]
    for _ in range(header[4]):
        cmd,size=struct.unpack_from("<II",data,at);commands.append(hex(cmd))
        assert size>=8 and at+size<=32+header[5]
        if cmd==0x19:
            s=struct.unpack_from("<II16sQQQQiiII",data,at)
            segments.append(dict(name=s[2].split(b"\0")[0].decode(),va=s[3],vm_size=s[4],offset=s[5],file_size=s[6]))
            for i in range(s[9]):
                f=struct.unpack_from("<16s16sQQIIIIIIII",data,at+72+80*i)
                sections[f[0].split(b"\0")[0].decode()]=dict(va=f[2],size=f[3],offset=f[4])
        at+=size
    assert "__eh_frame" in sections
    nm=capture(["/usr/bin/xcrun","nm","-n",str(output)])
    symbols={}
    for line in nm.splitlines():
        f=line.split()
        if len(f)==3:
            try: symbols[f[2]]=int(f[0],16)
            except ValueError: pass
    def read(va,size):
        for s in segments:
            if s["file_size"] and s["va"]<=va and va+size<=s["va"]+s["file_size"]:
                off=s["offset"]+va-s["va"];return data[off:off+size]
        raise ValueError("unmapped VA")
    assert read(symbols["_macho_marker"],16)==b"XREF_MACHO_SEED\0"
    entry=symbols["_macho_entry"]
    code=read(entry,18 if basic else 35)
    assert code[4:7]==bytes.fromhex("488d3d") and code[11]==0xe8
    assert entry+11+5+int.from_bytes(code[12:16],"little",signed=True)==symbols["_macho_helper"]
    assert code[-1]==0xc3
    sizes={"_macho_entry":18,"_macho_helper":6} if basic else SIZES
    functions=[dict(name=n,start=symbols[n],end=symbols[n]+size) for n,size in sizes.items()]
    report=dict(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),format="macho",architecture="x86_64",
                kind=kind,base=next(s["va"] for s in segments if s["name"]=="__TEXT"),
                commands=commands,segments=segments,sections=sections,symbols=symbols,functions=functions,
                marker=symbols["_macho_marker"],reference=entry+4,call=entry+11,target=symbols["_macho_helper"],
                compact=symbols.get("_macho_compact"),callback=symbols.get("_macho_callback"))
    if name=="chained": assert "0x80000034" in commands
    if name=="legacy": assert "0x80000022" in commands
    (ROOT/(name+".json")).write_text(json.dumps(report,indent=2)+"\n")
    print(name,len(data),"bytes",report["sha256"])
if __name__=="__main__":
    produce("basic","10.15",basic=True)
    produce("legacy","10.15")
    produce("chained","13.0")
    produce("mixed","10.15",mixed=True)
    produce("dylib","13.0",kind="dylib")
    produce("bundle","13.0",kind="bundle")
