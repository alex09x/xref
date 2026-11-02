<!-- translation-source: 2d64e7f757b4814d816d65327e346208c9870ad3 -->
> Este documento es una traducción de la versión en inglés disponible en el commit [`2d64e7f`](https://github.com/alex09x/xref/blob/2d64e7f757b4814d816d65327e346208c9870ad3/README.md). La versión canónica y más actualizada siempre se encuentra en el [README en inglés](https://github.com/alex09x/xref/blob/main/README.md).

<div align="center">

[English](https://github.com/alex09x/xref/blob/main/README.md) | [Русский](https://github.com/alex09x/xref/blob/main/readme/README.ru.md) | [简体中文](https://github.com/alex09x/xref/blob/main/readme/README.zh-CN.md) | [**Español**](https://github.com/alex09x/xref/blob/main/readme/README.es.md) | [Português (Brasil)](https://github.com/alex09x/xref/blob/main/readme/README.pt-BR.md) | [日本語](https://github.com/alex09x/xref/blob/main/readme/README.ja.md) | [Deutsch](https://github.com/alex09x/xref/blob/main/readme/README.de.md) | [Français](https://github.com/alex09x/xref/blob/main/readme/README.fr.md) | [한국어](https://github.com/alex09x/xref/blob/main/readme/README.ko.md) | [العربية](https://github.com/alex09x/xref/blob/main/readme/README.ar.md)

</div>

<div align="center">

<img src="../docs/logo-banner.svg" alt="XRef Code (xref)" width="732"/>

<br/><br/>

**Referencias cruzadas ultrarrápidas, recuperación de diseño de estructuras, segmentación de programas y pseudo-C estructurado para binarios ELF x86-64.**

Análisis de binarios sin indexación previa en Rust seguro puro (`#![forbid(unsafe_code)]`). Los límites de funciones se obtienen directamente de las tablas de desenrollado `.eh_frame` (con alternativa basada en tramos de código) y las consultas sobre binarios completos se decodifican a través de todos los núcleos de CPU en milisegundos — incluso en binarios de Rust optimizados totalmente despojados de símbolos (*stripped*), donde las tablas de símbolos están vacías.

<br/>

[**Banco de pruebas interactivo (xrefcode.com)**](https://xrefcode.com) · Por [Alexander Panasenko](https://prod.codes/about/)

<br/>

[![GitHub release](https://img.shields.io/github/v/release/alex09x/xref?color=e8c57a&labelColor=1a1d24&style=flat-square)](https://github.com/alex09x/xref/releases)
[![Crates.io](https://img.shields.io/crates/v/xref-code?color=e8c57a&label=crates.io&labelColor=1a1d24&style=flat-square)](https://crates.io/crates/xref-code)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.23878789-7ef0b3?labelColor=1a1d24&style=flat-square)](https://doi.org/10.5281/zenodo.23878789)
[![CI](https://img.shields.io/github/actions/workflow/status/alex09x/xref/ci.yml?branch=main&color=2ea043&labelColor=1a1d24&style=flat-square)](https://github.com/alex09x/xref/actions)
[![License](https://img.shields.io/badge/license-MIT_%2F_Apache--2.0-e8c57a?labelColor=1a1d24&style=flat-square)](../LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-edition_2024-dea584?labelColor=1a1d24&style=flat-square)](../Cargo.toml)
[![Safety](https://img.shields.io/badge/unsafe-forbidden-2ea043?labelColor=1a1d24&style=flat-square)](../Cargo.toml)

<br/>

[**Por qué**](#why) · [**Instalación**](#installation) · [**Inicio rápido**](#quick-start) · [**Ejemplos grabados**](#recorded-examples) · [**Referencia de comandos**](#command-reference) · [**Arquitectura**](#architecture) · [**Rendimiento**](#recorded-performance) · [**Limitaciones**](#scope--limitations) · [**Cita**](#citation)

</div>

---

<a name="why"></a>
## Por qué

Las suites tradicionales de ingeniería inversa asumen la presencia de un analista interactivo dispuesto a esperar minutos a que se complete una importación previa de la base de datos de todo el programa antes de hacer la primera pregunta. Los binarios de Rust sin símbolos (*stripped*) empeoran esto: los símbolos desaparecen, las cadenas son fragmentos `(ptr, len)` no terminados en NUL alojados en bloques de `.rodata`, y los pánicos por comprobación de límites fracturan los bucles en ramificaciones frías que convierten a los descompiladores ingenuos en un espagueti ilegible de `goto`.

**XRef Code** (`xref`) está diseñado para una investigación iterativa y rápida, tanto por especialistas en ingeniería inversa como por agentes autónomos de IA:

- **Sin índice previo y sin cachés obsoletas.** Cada invocación mapea la imagen ELF en memoria, extrae los rangos exactos de funciones a partir de los registros de desenrollado de pila `.eh_frame` (con repliegue automático basado en tramos) y escanea las funciones en paralelo mediante `rayon`.
- **Pseudo-C nativo estructurado y tipado (`xref c`).** Eleva el código máquina x86-64 directamente a C legible sin herramientas externas — recuperando firmas inmutables `arg_0..arg_5`, redes de rangos de vida SSA (`ptr_*`, `v_*`, `slot_*`), arrays con direccionamiento SIB e indexación por elementos, operaciones de ensanchamiento de 1 operando de `128-bit` `mul`/`imul`/`div`/`idiv`, cadenas de acarreo/préstamo de precisión múltiple `adc`/`sbb`, intrínsecos de desbordamiento aritmético con signo y regiones estructuradas `if`/`else`/`while`/`do-while`/`switch`.
- **Recuperación informada para binarios Rust sin símbolos.** Reconoce las funciones auxiliares en tiempo de ejecución de Rust despojadas de símbolos (`rust_panic_bounds_check`, `rust_slice_index_fail`, `rust_capacity_overflow`), segmenta literales exactos `&str` de tipo `(ptr, len)`, mapea descriptores `core::panic::Location` (`file:line:col`) a las rutas de los crates originales y resuelve las ramas de tablas de salto para `Display`.
- **Segmentación y comparación entre compilaciones (`xref slice`, `xref match`, `xref diff-c`).** Aísla instrucciones balanceadas y condiciones de control que alcanzan una llamada o IP de instrucción exacta, reubica funciones sin símbolos desplazadas entre distintas compilaciones y compara mediante diff el pseudo-C normalizado abstrayendo las direcciones hexadecimales volátiles.

Explore **114 ejecuciones CLI grabadas textualmente** contra el propio `xref` sin símbolos en el banco de pruebas web estático en **[xrefcode.com](https://xrefcode.com)**.

---

<a name="installation"></a>
## Instalación

### Homebrew (macOS Apple Silicon y Linux `x86_64`)

Instala el binario precompilado de `xref` directamente desde el tap [`alex09x/homebrew-apps`](https://github.com/alex09x/homebrew-apps) (no se requiere compilación con Cargo):

```bash
brew tap alex09x/apps
brew install xref
xref --version
```

### Paquetes tarball precompilados de lanzamiento (Linux `x86_64` y macOS `arm64`)

Los archivos comprimidos precompilados (`x86_64-unknown-linux-gnu`, requiriendo `glibc >= 2.34`, y `aarch64-apple-darwin`) incluyen `xref`, `README.md`, `LICENSE-MIT`, `LICENSE-APACHE` y `CITATION.cff`:

```bash
curl -fsSLO https://github.com/alex09x/xref/releases/download/v0.1.0/xref-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
curl -fsSLO https://github.com/alex09x/xref/releases/download/v0.1.0/xref-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256
sha256sum -c xref-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf xref-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
./xref --version
```

### Cargo y `crates.io` (Linux y macOS)

Publicado en [`crates.io` como `xref-code`](https://crates.io/crates/xref-code), lo cual instala el binario CLI `xref` (requiere `rustc 1.88+` para las cadenas `let` de la Edición 2024; los binarios precompilados también funcionan mediante [`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall)):

```bash
cargo install xref-code --locked
# or prebuilt via cargo-binstall:
cargo binstall xref-code -y
# or directly from the pinned release tag:
cargo install --git https://github.com/alex09x/xref --tag v0.1.0 --locked
```

---

<a name="quick-start"></a>
## Inicio rápido

Pase `-b <ELF>` en cada comando o exporte `XREF_BIN=/ruta/al/binario.elf` una vez por sesión de shell. Las direcciones usan la numeración virtual de ELF (direcciones de `objdump`) en hexadecimal `0x` o decimal:

```bash
export XREF_BIN=./xref.stripped

xref stats                                      # function count, .text bytes, pointers, panic locations
xref refs "goto L_"                             # code & data references to strings or addresses (--inline)
xref where src/loops.rs                         # stripped function ranges compiled from a Rust source file
xref layout 0xa2270 --reg rsi --callees         # recover struct field offsets, sizes, strides & 1-hop callees
xref c 0x9a8a0 --fields                         # structured typed pseudo-C with inferred ->f_<off> hints
xref slice 0xc7d60 --to fn_160bb0               # backward slice of statements & guards reaching a target
```

---

<a name="recorded-examples"></a>
## Ejemplos grabados

Todas las salidas mostradas a continuación corresponden a ejecuciones completas y no editadas capturadas contra `xref.stripped` (`1,962,608` bytes, `0` símbolos, `sha256:3f3ba3b311f3eca8e26a929285d4fc9ffef4e4b6e8fc015105766180a2a6869d`) y verificadas en CI para coincidir línea por línea con `docs/recorded-data.js` (salvo espacios en blanco finales).

### 1. Pseudo-C estructurado y tipado con sugerencias de desplazamiento de campos (`xref c --fields`)

```c
$ xref -b xref.stripped c 0x9a8a0 --fields
/* field offsets: arg_0 [+0x0:u64, +0x8:u64, +0x10:u64, +0x18:u64] */
/*
 * fn_9a8a0 — 0x9a8a0..0x9a97a (218 bytes, 1 direct caller; synthetic FDE entry)
 *   source: src/cfg.rs:154:22, src/cfg.rs:75:25, src/cfg.rs:154:57
 *   params:
 *     arg_0 (rdi): const void * — reads +0x0 (8B), +0x8 (8B), +0x10 (8B), +0x18 (8B)
 *     arg_1 (rsi): unk64 — 64-bit register (signedness unconstrained)
 *     arg_2 (rdx): unk64 — 64-bit register (signedness unconstrained)
 *   return: u8 in rax (consumed by 1/1 direct call site)
 */
u8 fn_9a8a0(const void *arg_0, unk64 arg_1, unk64 arg_2) {
  usize v_1 = arg_1; /* rsi */
  u64 v_6; /* rbx */
  const u8 *ptr_9; /* rax */
  unk64 slot_0; /* [rsp+0x0], addr-taken */
  unk64 slot_8; /* [rsp+0x8] */

  if (v_1 == 0) {
    ptr_9 = 0;
    return ptr_9;
  }
  u64 v_2 = arg_0->f_8;
  if (v_1 >= v_2) {
    usize v_12 = v_1;
    /* [runtime] rust_panic_bounds_check(index, len, loc) -> noreturn */
    rust_panic_bounds_check(v_12, v_2, "src/cfg.rs:154:22");
  }
  if (((u64 *)arg_0->f_0)[v_1] != 1) {
    ptr_9 = 0;
    return ptr_9;
  }
  const void *ptr_3 = arg_0->f_18;
  unk64 v_4 = *(u64 *)(arg_0->f_10);
  if (v_1 == v_4 + 2) {
    usize v_5 = (v_4 + 1);
    v_6 = *(u64 *)(ptr_3 + 16);
    if (v_5 >= v_6) {
      /* [runtime] rust_panic_bounds_check(index, len, loc) -> noreturn */
      rust_panic_bounds_check(v_5, v_6, "src/cfg.rs:154:57");
    }
    usize v_7 = v_1;
    unk64 v_8 = ((v_5 * 96) + *(u64 *)(ptr_3 + 8));
    slot_8 = arg_2;
    slot_0 = 1;
    /* fn_fb8e0: calls fn_fb9c6, fn_fb920 */
    ptr_9 = fn_fb8e0(v_8, &slot_0);
    u32 v_10 = ptr_9;
    ptr_9 = 1;
    v_1 = v_7;
    if (v_10 != 0) {
      return ptr_9;
    }
  } else {
    v_6 = *(u64 *)(ptr_3 + 16);
  }
  usize v_11 = (v_1 - 1);
  if (v_11 < v_6) {
    ptr_9 = *(u64 *)(ptr_3 + 8);
    ptr_9 = (((u8 *)ptr_9)[(v_11 * 96)] & 5) != 0;
    return ptr_9;
  }
  usize v_13 = v_11;
  /* [runtime] rust_panic_bounds_check(index, len, loc) -> noreturn */
  rust_panic_bounds_check(v_13, v_6, "src/cfg.rs:75:25");
}
```

### 2. Recuperación interprocedimental del diseño de estructuras (`xref layout --callees`)

```text
$ xref -b xref.stripped layout 0xa2270 --reg rsi --callees
layout of rsi in 0xa2270..0xa2566:
  +0       size  4  u32   r:0  w:2
  +8       size  8  u64   r:2  w:0
  +10      size  8  u64   r:2  w:0
  +20      size  8  u64   r:1  w:0
  +28      size  8  u64   r:1  w:0
5 fields (min span 0x30)
other pointer args: rdi (3 fields), rdx (1 fields)  (use --reg <REG>)
```

### 3. Segmentación retrospectiva de programas (`xref slice`)

```c
$ xref -b xref.stripped slice 0xc7d60 --to fn_160bb0
/* slice of 0xc7d60..0xc7fbf -> fn_160bb0 (37/131 lines) */
void fn_c7d60(void *arg_0, const void *arg_1, usize arg_2) {
  u8 slot_28; /* [rsp+0x28], addr-taken */
  usize slot_30; /* [rsp+0x30] */
  unk64 slot_40; /* [rsp+0x40], addr-taken */
  if (arg_2 == 0) {
    return; /* callers ignore rax */
  }
  const void *ptr_1 = arg_1;
  const void *v_2 = arg_1 + arg_2 * 24;
  void *v_4 = &slot_40;
  do {
    const u8 *ptr_6 = *(u64 *)(ptr_1 + 8);
    usize v_7 = *(u64 *)(ptr_1 + 16);
    /* fn_160550: source core/src/str/pattern.rs:1398; calls fn_1606e0, fn_160a43, fn_1605f8 */
    fn_160550(v_4, ptr_6, v_7, "goto L_", 7);
    /* fn_124d50: source core/src/str/pattern.rs:1131; calls fn_124e3a, fn_160bb0, fn_124e29 */
    fn_124d50(&slot_28, v_4);
    if (slot_28 != 0) {
      usize v_8 = slot_30;
      usize v_9 = (v_8 + 7);
      if (v_9 != 0) {
        if (v_9 < v_7) {
          if ((i64)((u8 *)ptr_6)[v_9] < 192) {
            /* fn_160bb0: noreturn; source core/src/str/mod.rs:486; calls fn_160bc0 */
            fn_160bb0(ptr_6, v_7, v_9, v_7, "src/loops.rs:45:36");
          }
        } else {
          if (v_9 != v_7) {
            /* fn_160bb0: noreturn; source core/src/str/mod.rs:486; calls fn_160bc0 */
            fn_160bb0(ptr_6, v_7, v_9, v_7, "src/loops.rs:45:36");
          }
        }
      }
    }
    ptr_1 = (ptr_1 + 24);
  } while (ptr_1 != v_2);
}
```

### 4. Reubicación entre compilaciones y comparación de pseudo-C normalizado (`xref diff-c`)

Las líneas indentadas con `  ...` que aparecen a continuación son emitidas directamente por `xref diff-c` para marcar fragmentos normalizados sin cambios fuera del bloque de diferencias:

```diff
$ xref -b xref.stripped diff-c --other xref-v0.0.2.stripped 0xd57c0
=== diff 0xd57c0..0xd6301 (current) vs 0xd5530..0xd6071 (other, score 384: locs:240 strs:0 imms:4 disps:10 nbrs:105 size:0xb41 callees:8) ===
  ...
      }
      @var_11 = (@slot_10 + @var_8);
-     @var_1 = 0xc2bc;
+     @var_1 = 0xc518;
      @var_32 = @slot_9;
      switch (*(u64 *)(@var_11)) {
  ...
```

---

<a name="command-reference"></a>
## Referencia de comandos

Las [opciones avanzadas](https://github.com/alex09x/xref/blob/main/docs/advanced-options.md) explican la búsqueda de desplazamientos en la pila y la salida que conserva las etiquetas de salto.

Las [consultas estructuradas y MCP local](https://github.com/alex09x/xref/blob/main/docs/mcp.md) ofrecen acceso programático al mismo núcleo de análisis.

### Inventario, símbolos y referencias cruzadas
```text
xref -b BIN stats                                    # functions, .text bytes, pointers, imports, panic locations
xref -b BIN sym PATTERN                              # symbol search (non-stripped binaries)
xref -b BIN func 0xa1b50                             # function span containing an address
xref -b BIN refs "goto L_" 0xa1b50                   # .rodata / pointer / code xrefs (--inline for mov/movabs stores)
xref -b BIN istr "text"                              # shorthand for refs --inline
xref -b BIN imm 24 --in 0xa1b50                      # immediate constants (--store, --cmp, --in FN)
xref -b BIN find --src src/loops.rs --calls 0x160bb0 # single-pass multi-predicate function search (--any K)
```

### Diseños de estructuras, desplazamientos y grafos de llamadas
```text
xref -b BIN disp 0x20 0x28 --all                     # field loads/stores/leas (--write, --lea, --stride, --in FN)
xref -b BIN layout 0xa2270 --reg rsi --callees       # aggregate field offsets, widths, strides & 1-hop callees
xref -b BIN callers 0xcafb0                          # direct calls/tail-jumps, address-taken & pointer-table xrefs
xref -b BIN calls 0xcafb0                            # outgoing calls and tail-jumps in instruction order
xref -b BIN args 0xa2270 --max 20                    # constant & symbolic arguments across all call sites
xref -b BIN path 0xc7fc0 0x160bb0 --depth 8          # shortest call chains between two functions
xref -b BIN tree 0xd0aa0 --callers --depth 2         # indented caller/callee tree with panic source anchors
```

### Desensamblado, pseudo-C, segmentación, exportación de crates y diferencias
```text
xref -b BIN asm 0xc7d60 --from A --to B              # annotated Intel disassembly (strings, slots, targets)
xref -b BIN c 0x9a8a0 --fields                       # structured typed pseudo-C (--out DIR for parallel batch export)
xref -b BIN slice 0xc7d60 --to fn_160bb0 --fields    # backward slice to target call, hex IP, offset, or string
xref -b BIN dump --out DIR --src src/loops.rs        # parallel modular .c export grouped by panic source paths
xref -b BIN match --other OLD_BIN 0xc7d60 --top 3    # relocate shifted stripped functions across two builds
xref -b BIN diff-c --other OLD_BIN 0xd57c0           # normalized cross-build pseudo-C LCS diff
```

### Ubicaciones de código fuente de Rust y tablas de salto de enums
```text
xref -b BIN src 0x9a8a0                              # core::panic::Location (file:line:col) descriptors in function
xref -b BIN where src/image.rs --line 46             # stripped functions referencing a Rust file (and line)
xref -b BIN files src/                               # distinct Rust source files recovered from panic descriptors
xref -b BIN error "invalid"                          # jump-table discriminant whose Display arm names text
xref -b BIN variant 0xc7fc0 1 2                      # inverse of error: texts referenced by jump-table arms
xref -b BIN arm 0xc8010                              # jump-table indices whose arm contains an address
```

---

<a name="architecture"></a>
## Arquitectura

```mermaid
flowchart LR
    ELF["x86-64 ELF Image\n(.text, .rodata, .eh_frame, .rela)"] --> Span["Span & Runtime Discovery\n(.eh_frame FDEs + fallback,\npanic Location & helper map)"]
    Span --> Decode["Parallel Decode (rayon)\niced-x86 instruction stream\n& jump-table recovery"]
    Decode --> Xref["Direct Xref & Layout Queries\nrefs / disp / layout / find /\ncallers / args / match"]
    Decode --> CFG["CFG & Region Structurer\nnatural loops, cold noreturn\ninlining & skip-flag guards"]
    CFG --> SSA["SSA Webs & Lifting\n128-bit widening ALU, carry/borrow,\nbidirectional types & SIB arrays"]
    SSA --> Emit["C Emitter, Slicer & Differ\nxref c / slice / dump / diff-c"]
```

---

<a name="recorded-performance"></a>
## Rendimiento registrado

Tiempos transcurridos reales de ejecución en CLI en una sola pasada reportados por `xref 0.0.5` (`stderr`) en un `AMD Ryzen 9 9950X` (16 núcleos / 32 hilos, Linux 6.8 `x86_64`, caché de páginas del SO caliente) analizando `xref.stripped` (`1.96 MB`, `1,974` funciones, `0` símbolos):

| Operación | Comando | Carga de ELF | Tiempo total |
|---|---|---:|---:|
| Inventario del binario (`1,974` funciones, `588` ubicaciones de pánico) | `xref -b xref.stripped stats` | `0.84 ms` | **`2.2 ms`** |
| Escaneo de referencias cruzadas de cadenas y punteros en todo el binario | `xref -b xref.stripped refs "goto L_"` | `0.80 ms` | **`3.9 ms`** |
| Mapeo de módulos de Rust a partir de ubicaciones de pánico incrustadas | `xref -b xref.stripped where src/loops.rs` | `0.79 ms` | **`3.4 ms`** |
| Recuperación interprocedimental del diseño de estructuras (llamadas directas a 1 salto) | `xref -b xref.stripped layout 0xa2270 --reg rsi --callees` | `0.81 ms` | **`2.6 ms`** |
| Segmentación retrospectiva de programa + sugerencias de desplazamiento de campos (`37 / 131` líneas) | `xref -b xref.stripped slice 0xc7d60 --to fn_160bb0 --fields` | `0.81 ms` | **`5.1 ms`** |
| Emparejamiento de funciones entre compilaciones y diff de pseudo-C normalizado | `xref -b xref.stripped diff-c --other xref-v0.0.2.stripped 0xc7d60` | `0.86 ms` | **`13.4 ms`** |

---

<a name="scope--limitations"></a>
## Alcance y limitaciones

- **Formato de entrada compatible:** Binarios y objetos compartidos ELF `x86-64` (`ET_EXEC`, `ET_DYN`). PE/Mach-O y AArch64 están fuera del alcance actual.
- **Detección de límites de funciones:** Los rangos exactos de funciones se derivan de las tablas de desenrollado `.eh_frame` (emitidas por defecto por `rustc`, `clang` y `gcc` en `x86-64` incluso tras `strip --strip-all`), recurriendo a un mecanismo de reserva por huecos/destinos de llamadas cuando no hay entradas de desenrollado. Los binarios desprovistos de `.eh_frame` (`strip -R .eh_frame`) dependen de límites heurísticos basados en intervalos.
- **Pseudo-C estático e inferencia de desplazamientos:** Las firmas de parámetros (`arg_*`), los tipos de punteros/enteros inferidos (`const void *`, `usize`, `unk64`, etc.) y las sugerencias de desplazamiento de `--fields` (`->f_<off>`) son reconstrucciones estáticas conservadoras a partir de los usos en código máquina, no tipos de origen DWARF. Las instrucciones del sistema/SIMD no modeladas se preservan en línea como comentarios explícitos de ensamblador `/* 0xaddr: ... */` en lugar de omitirse silenciosamente; compruebe siempre las invariantes críticas con `xref asm`.

---

<a name="development--testing"></a>
## Desarrollo y pruebas

`rustc` debe estar disponible en el `PATH` al ejecutar las pruebas: la suite de pruebas de extremo a extremo compila `tests/fixtures/sample.rs` en un archivo binario ELF temporal y verifica los subcomandos de la CLI con él.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

---

<a name="citation"></a>
## Cita

Para referencias académicas, de seguridad o de archivo, cite la versión publicada `v0.1.0` a través de Zenodo o [`CITATION.cff`](../CITATION.cff):

```bibtex
@software{panasenko_2026_23878790,
  author       = {Panasenko, Alexander},
  title        = {XRef Code — Ultra Blazing Fast x86-64 ELF Cross-References \& Pseudo-C Decompiler},
  month        = nov,
  year         = 2026,
  publisher    = {Zenodo},
  version      = {0.1.0},
  doi          = {10.5281/zenodo.23878790},
  url          = {https://doi.org/10.5281/zenodo.23878790}
}
```

- Alexander Panasenko (2026). *XRef Code — Ultra Blazing Fast x86-64 ELF Cross-References & Pseudo-C Decompiler* (v0.1.0). Zenodo. https://doi.org/10.5281/zenodo.23878790 ([concept DOI: 10.5281/zenodo.23878789](https://doi.org/10.5281/zenodo.23878789))

---

<a name="license"></a>
## Licencia

Copyright © 2026 [Alexander Panasenko](https://prod.codes/about/) (`alex@prod.codes`).

Bajo doble licencia según cualquiera de las siguientes opciones:
- **Licencia Apache, Versión 2.0** ([`LICENSE-APACHE`](../LICENSE-APACHE) o http://www.apache.org/licenses/LICENSE-2.0)
- **Licencia MIT** ([`LICENSE-MIT`](../LICENSE-MIT) o http://opensource.org/licenses/MIT)

a su elección.
