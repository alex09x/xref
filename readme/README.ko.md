<!-- translation-source: 237c0a29f14445f47d2d01f56623db1b71f3586c -->
> **참고**: 이 문서는 영어 원본 커밋 [237c0a2](https://github.com/alex09x/xref/blob/237c0a29f14445f47d2d01f56623db1b71f3586c/README.md)의 번역본입니다. 최신 공식 문서는 [영어 README](https://github.com/alex09x/xref/blob/main/README.md)를 참조하십시오.

[English](https://github.com/alex09x/xref/blob/main/README.md) | [Русский](https://github.com/alex09x/xref/blob/main/readme/README.ru.md) | [简体中文](https://github.com/alex09x/xref/blob/main/readme/README.zh-CN.md) | [Español](https://github.com/alex09x/xref/blob/main/readme/README.es.md) | [Português (Brasil)](https://github.com/alex09x/xref/blob/main/readme/README.pt-BR.md) | [日本語](https://github.com/alex09x/xref/blob/main/readme/README.ja.md) | [Deutsch](https://github.com/alex09x/xref/blob/main/readme/README.de.md) | [Français](https://github.com/alex09x/xref/blob/main/readme/README.fr.md) | **[한국어](https://github.com/alex09x/xref/blob/main/readme/README.ko.md)** | [العربية](https://github.com/alex09x/xref/blob/main/readme/README.ar.md)

<div align="center">

<img src="../docs/logo-banner.svg" alt="XRef (xref)" width="732"/>

<br/><br/>

**x86-64 ELF / Mach-O 바이너리를 위한 초고속 상호 참조(교차 참조), 구조체 레이아웃 복원, 프로그램 슬라이싱 및 구조화된 의사 C(pseudo-C) 생성 도구.**

순수 안전 Rust(`#![forbid(unsafe_code)]`) 기반의 제로 인덱스(zero-index) 바이너리 분석. 함수 경계는 `.eh_frame` 언와인드 테이블에서 직접 추출되며(스팬 대체 메커니즘 지원), 심볼 테이블이 완전히 비어 있는 스트립(stripped)된 Rust 릴리스 바이너리에서도 전체 바이너리 쿼리를 모든 CPU 코어에서 수 밀리초 만에 병렬로 디코딩합니다.

<br/>

[**인터랙티브 워크벤치 (xrefcode.com)**](https://xrefcode.com) · 개발자: [Alexander Panasenko](https://prod.codes/about/)

<br/>

[![GitHub release](https://img.shields.io/github/v/release/alex09x/xref?color=e8c57a&labelColor=1a1d24&style=flat-square)](https://github.com/alex09x/xref/releases)
[![Crates.io](https://img.shields.io/crates/v/xref-code?color=e8c57a&label=crates.io&labelColor=1a1d24&style=flat-square)](https://crates.io/crates/xref-code)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.23878789-7ef0b3?labelColor=1a1d24&style=flat-square)](https://doi.org/10.5281/zenodo.23878789)
[![CI](https://img.shields.io/github/actions/workflow/status/alex09x/xref/ci.yml?branch=main&color=2ea043&labelColor=1a1d24&style=flat-square)](https://github.com/alex09x/xref/actions)
[![License](https://img.shields.io/badge/license-MIT_%2F_Apache--2.0-e8c57a?labelColor=1a1d24&style=flat-square)](../LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-edition_2024-dea584?labelColor=1a1d24&style=flat-square)](../Cargo.toml)
[![Safety](https://img.shields.io/badge/unsafe-forbidden-2ea043?labelColor=1a1d24&style=flat-square)](../Cargo.toml)

<br/>

[**선택 이유**](#why) · [**설치**](#installation) · [**빠른 시작**](#quick-start) · [**실행 기록 예제**](#recorded-examples) · [**명령어 레퍼런스**](#command-reference) · [**아키텍처**](#architecture) · [**벤치마크 성능**](#recorded-performance) · [**적용 범위 및 한계**](#scope--limitations) · [**인용**](#citation)

</div>

---

<a name="why"></a>
## 선택 이유

전통적인 리버스 엔지니어링 도구 모음은 첫 질문을 던지기 전에 전체 프로그램 데이터베이스를 사전에 임포트하느라 수 분간 기다릴 의향이 있는 대화형 분석가를 전제로 합니다. 심볼이 제거(stripped)된 Rust 바이너리에서는 상황이 더 나빠집니다. 심볼은 사라지고, 문자열은 `.rodata` 풀에 존재하는 NUL 종료자가 없는 `(ptr, len)` 슬라이스이며, 경계 검사 패닉으로 인해 루프가 콜드 에지(cold edge)로 산산조각 나면서 단순한 디컴파일러는 읽을 수 없는 `goto` 스파게티 코드를 만들어 냅니다.

**XRef**(`xref`)는 리버스 엔지니어와 자율 AI 에이전트 모두의 신속하고 반복적인 조사를 위해 설계되었습니다:

- **사전 인덱스 없음, 오래된 캐시 없음.** 분석 명령은 ELF 이미지를 메모리에 매핑하고, `.eh_frame` 언와인드 레코드에서 정확한 함수 범위를 추출하며(자동 스팬 폴백 포함), `rayon`으로 함수를 병렬 스캔합니다. 예외는 `xref field`입니다. 입력 파일과 xref 실행 파일의 내용에 연결된 선택적 디스크 인덱스를 유지하며, 저장된 보고서를 재생하거나 백그라운드 field daemon에 질의할 수 있습니다. 이 두 가지는 정규화된 파일 경로와 그 메타데이터(장치, inode, 크기, 수정 및 상태 변경 시간)에 연결됩니다. 변경이 있으면 다시 빌드되거나 우회됩니다.
- **네이티브 구조화 및 타입이 명시된 의사 C (`xref c`).** 외부 도구 없이 x86-64 기계어를 읽기 쉬운 C 코드로 직접 리프팅합니다. 불변 `arg_0..arg_5` 서명, SSA 라이브 레인지 웹(`ptr_*`, `v_*`, `slot_*`), 요소 인덱스 방식의 SIB 배열, 단일 피연산자 `128비트` 확장 `mul`/`imul`/`div`/`idiv`, 다중 정밀도 `adc`/`sbb` 캐리/빌림 체인, 부호 있는 산술 오버플로 인트린식, 그리고 구조화된 `if`/`else`/`while`/`do-while`/`switch` 영역을 복원합니다. 스칼라 SSE/AVX 부동소수점 연산(`f32`/`f64` 매개변수, 반환값 및 호출 결과)과 상수 vtable을 통한 간접 호출도 복원하며 각 대상을 선택하는 분기 조건을 표시합니다.
- **Rust 바이너리 특화 스트립 복원.** 심볼이 제거된 Rust 런타임 헬퍼(`rust_panic_bounds_check`, `rust_slice_index_fail`, `rust_capacity_overflow`)를 인식하고, 정확한 `(ptr, len)` `&str` 리터럴을 슬라이스하며, `core::panic::Location`(`file:line:col`) 설명자를 원래의 크레이트 소스 경로로 역매핑하고, `Display` 점프 테이블 암(arm)을 확인합니다.
- **슬라이싱 및 빌드 간 비교 (`xref slice`, `xref match`, `xref diff-c`).** 특정 호출 또는 명령어 IP에 도달하는 균형 잡힌 구문과 제어 가드를 분리하고, 빌드 간에 이동된 스트립 함수를 재배치하며, 가변적인 16진수 주소를 추상화한 정규화된 의사 C로 diff를 생성합니다.
- **직렬화된 필드 검색(`xref field`).** 직렬화된 키 문자열을 근거 명령어와 함께 구조체 필드 오프셋에 연결하고, 해당 필드를 쓰는 후보 함수의 순위를 매깁니다. 필요하면 반환된 포인터, 인자 포인터 또는 로드된 포인터를 통해 쓰는 함수만 남길 수 있습니다(`--writer-root`). 결과는 근거가 포함된 후보이며 소스 타입의 증명이 아닙니다.
- **오류 기원과 상수 인자 (`xref origin`, `xref callargs`).** `origin`은 오류 메시지에서 시작해 이를 만드는 코드를 나열합니다. 값, 너비, 레이아웃이 일치하는 enum 태그 저장, 안쪽에서 바깥쪽으로의 변환, 저장에 태그를 전달하는 호출과 각 지점의 가드 조건을 보여 줍니다. 전달된 태그를 피호출자 보존 복사본, 스필, 스택 객체, 프레임 포인터, 스택 인자 슬롯, 레코드로의 복사 및 나중에 레코드를 값으로 읽는 루프까지 추적합니다. `callargs`는 상수를 전달하는 모든 호출을 피호출 함수별로 나열합니다. 지점은 근거가 있는 후보입니다.
- **출처와 타입 지정 데이터 (`xref deps`, `xref data`).** [`cargo-auditable`](https://github.com/rust-secure-code/cargo-auditable)이 Rust 바이너리에 삽입한 의존성 매니페스트(`.dep-v0`)와 Go 모듈 목록(`.go.buildinfo`), 컴파일러/링커 문자열과 Build-ID를 읽습니다. `data`는 가상 주소에서 타입 지정 값(`u8`..`u64`, `f32`/`f64`, 바이트, 문자열)을 읽습니다.
- **에이전트용 구조화 출력 (`xref query`, `xref mcp`).** 하나의 불변 이미지에 대한 버전 지정 JSON입니다. `info`는 초기 진단(언어, 도구 체인, 내장 의존성, 바로 실행할 다음 질의)으로 시작하고, 각 답변에는 신뢰 등급(`observed`, `derived`, `inferred`)과 결정적인 근거 ID가 있으며 바이너리 내용은 신뢰할 수 없는 데이터로 표시됩니다. `--compact`는 MCP 응답을 짧게 유지합니다.
- **실행 중인 Linux 프로세스 검사(`xref live`).** 정적 뷰를 실행 중인 x86-64 Linux 프로세스에 연결합니다. 메모리에서 값을 찾고, 런타임 포인터를 정적 함수로 해석하고, 제한된 uprobe로 호출과 호출자를 세고, 하드웨어 워치포인트로 필드를 쓰는 명령어를 찾아내며, 스레드별 순서가 보존된 호출 윈도우(`live trace`)와 제한된 CPU 프로파일(`live profile`)을 기록합니다. 각 결과는 커버리지와 한계를 명시합니다.
- **프로파일 및 오프라인 트레이스(`xref profile`, `xref symbolize`, `xref edges`).** `.xprof` 기록을 요약, 주석, 비교하고, `perf.data`(제한된 Intel PT 디코딩 포함)와 `perf script` 텍스트를 가져오며, 저장된 스택과 관찰된 호출 엣지를 선택한 실행 파일에 매핑합니다.

정적 브라우저 워크벤치인 **[xrefcode.com](https://xrefcode.com)**에서 스트립된 `xref` 자체를 대상으로 기록된 **원문 그대로 기록한 114개의 CLI 실행 결과**를 직접 살펴보십시오.

---

<a name="installation"></a>
## 설치

### 한 줄 설치 (macOS Apple Silicon 및 Linux `x86_64`)

```bash
curl -fsSL https://xrefcode.com/install.sh | sh
```

스크립트가 설치 방법을 스스로 고릅니다. 플랫폼에 맞는 릴리스 바이너리를 공개된 SHA-256으로 검증해 설치하고, 맞는 사전 빌드 바이너리가 없으면 `cargo install xref-code --locked`를 사용합니다. `XREF_VERSION=v0.5.0`으로 릴리스를 고정하고, `XREF_INSTALL_DIR`로 설치 디렉터리를 지정합니다(기본값은 쓰기 가능하면 `/usr/local/bin`, 아니면 `~/.local/bin`). 원하면 먼저 [스크립트를 읽어 보세요](https://xrefcode.com/install.sh).

### Homebrew (macOS Apple Silicon 및 Linux `x86_64`)

[`alex09x/homebrew-apps`](https://github.com/alex09x/homebrew-apps) 탭에서 사전 빌드된 `xref` 바이너리를 직접 설치합니다 (Cargo 컴파일 불필요):

```bash
brew tap alex09x/apps
brew install xref
xref --version
```

### 사전 빌드 릴리스 압축 파일 (Linux `x86_64` 및 macOS `arm64`)

사전 빌드된 아카이브(`x86_64-unknown-linux-gnu`는 `glibc >= 2.34` 필요, 및 `aarch64-apple-darwin`)는 `xref`, `README.md`, `LICENSE-MIT`, `LICENSE-APACHE`, `CITATION.cff`를 함께 제공합니다:

```bash
curl -fsSLO https://github.com/alex09x/xref/releases/download/v0.5.0/xref-v0.5.0-x86_64-unknown-linux-gnu.tar.gz
curl -fsSLO https://github.com/alex09x/xref/releases/download/v0.5.0/xref-v0.5.0-x86_64-unknown-linux-gnu.tar.gz.sha256
sha256sum -c xref-v0.5.0-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf xref-v0.5.0-x86_64-unknown-linux-gnu.tar.gz
./xref --version
```

### Cargo 및 `crates.io` (Linux 및 macOS)

[`crates.io`에 `xref-code`](https://crates.io/crates/xref-code)로 등록되어 있어 `xref` CLI 바이너리를 설치할 수 있습니다 (Edition 2024의 `let` 체인 지원을 위해 `rustc 1.88+` 필요; 사전 빌드된 바이너리는 [`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall)을 통해서도 설치 가능):

```bash
cargo install xref-code --locked
# or prebuilt via cargo-binstall:
cargo binstall xref-code -y
# or directly from the pinned release tag:
cargo install --git https://github.com/alex09x/xref --tag v0.5.0 --locked
```

---

<a name="quick-start"></a>
## 빠른 시작

각 명령에 `-b <BINARY>`를 전달하거나 셸 세션에 `XREF_BIN=/path/to/binary`를 설정하세요. 주소는 `0x` 16진수 또는 10진수의 정적 이미지 VA이며, Mach-O RVA 기준은 `__TEXT.vmaddr`입니다.

```bash
export XREF_BIN=./xref.stripped

xref stats                                      # function count, .text bytes, pointers, panic locations
xref refs "goto L_"                             # code & data references to strings or addresses (--inline)
xref where src/loops.rs                         # stripped function ranges compiled from a Rust source file
xref layout 0xa2270 --reg rsi --callees         # recover struct field offsets, sizes, strides & 1-hop callees
xref c 0x9a8a0 --fields                         # structured typed pseudo-C with inferred ->f_<off> hints
xref c 0x9a8a0 --only-paths-to 0x9a950          # pseudo-C containing only basic blocks that reach ADDR
xref slice 0xc7d60 --to fn_160bb0               # backward slice of statements & guards reaching a target
xref origin "number out of range"               # code that builds an error message: tag stores, conversions, guards
xref deps                                       # embedded cargo-auditable / Go build manifest, toolchains, Build-ID
xref query '{"operation":"info"}'              # versioned JSON for one immutable image
xref mcp                                       # local read-only stdio MCP server
```

---

<a name="live-analysis-linux-x86-64"></a>
## 라이브 프로세스 분석 (Linux x86-64)

v0.3.0부터 `xref live`는 실행 중인 Linux x86-64 프로세스를 검증된 실행 파일의 정적 분석과 연결합니다. `-b`로 동일한 ELF를 전달하면, xref는 주소를 변환하기 전에 `/proc/<pid>/exe`(GNU build-id 또는 SHA-256)와 대조하여 검증합니다.

```bash
xref -b ./app live maps --pid PID                        # mappings, binary match, PIE slide
xref -b ./app live memscan --pid PID 0x4441454d4f4e5632  # find u64 values; classify neighbouring words
xref -b ./app live resolve --pid PID 0x55d1c0ffc9d0      # runtime address -> static VA, function, file offset
sudo xref -b ./app live probe --pid PID --callers 0x1f9f0       # bounded uprobe hit counts, callers, registers
sudo xref -b ./app live watch --pid PID 0x55d1e1c3adc8          # DR0-DR3 write watch: writer instruction and value
sudo xref -b ./app live trace --pid PID --start 0x1f9f0 --stop-return 0x1f9f0 --callees-of 0x1f9f0 # ordered per-thread call windows
sudo xref -b ./app live profile --pid PID --duration 10s --out app.xprof # bounded CPU sampling profile
xref -b ./app mcp --allow-live-pid PID                   # opt-in xref_live MCP tool pinned to one process
```

- `maps`, `resolve`, `memscan`은 `/proc/<pid>/maps` 및 `/proc/<pid>/mem`만 읽습니다(대상 프로세스에 대한 ptrace 접근 권한이 필요하며, 프로세스는 일시 중지되지 않습니다).
- `probe` 및 `watch`는 대상에서 perf 이벤트를 열며 특권 perf 접근 권한(root 또는 `CAP_PERFMON`)이 필요합니다. 이벤트 적중 시마다 대상 프로세스에 트랩(trap)이 발생하므로, 부하가 높은 프로세스에서는 관찰 주기를 짧게 유지하십시오.
- `trace`는 격리된 `tracefs` uprobe 인스턴스를 사용하며 쓰기 가능한 tracefs(보통 root)가 필요합니다. 윈도우는 지정한 중지 주소나 반환에서 닫히고, 윈도우 수, 이벤트 수, 시간의 명시적 한도에서 멈춥니다. `profile`은 perf 이벤트로 샘플링하며, 커널 정책이 요청한 이벤트를 허용하지 않으면 조용히 바꾸지 않고 오류를 반환합니다.
- 분석 결과는 관찰된 사실과 추론을 명확히 구분합니다: 0 카운트는 명시된 시간 구간 및 스레드만을 대상으로 하며, 보고된 쓰기 명령어는 명시적 신뢰도를 가진 후보이며, 누락된 이벤트나 지연 연결된 스레드가 있는 경우 카운트는 하한값이 됩니다.

단계별 기록 세션 (메모리 검색 → 정적 함수 → 호출 횟수 → 필드 기록 명령어 → 버퍼 재할당 이동): **[라이브 분석 단계별 가이드 (Live Analysis walkthrough)](https://xrefcode.com/live-walkthrough)**. 규약 및 제약 사항: [docs/live.md](https://github.com/alex09x/xref/blob/main/docs/live.md); MCP: [docs/mcp.md](https://github.com/alex09x/xref/blob/main/docs/mcp.md).

---

<a name="recorded-examples"></a>
## 실행 기록 예제

아래의 모든 출력은 `xref.stripped`(`1,962,608` 바이트, 심볼 `0`개, `sha256:3f3ba3b311f3eca8e26a929285d4fc9ffef4e4b6e8fc015105766180a2a6869d`)를 대상으로 캡처된 편집되지 않은 전체 실행 결과이며, CI에서 `docs/recorded-data.js`와 한 줄 한 줄 정확히 일치하는지 검증되었습니다 (줄 끝 후행 공백 제외).

### 1. 필드 오프셋 힌트가 포함된 구조화 타입 의사 C (`xref c --fields`)

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

### 2. 프로시저 간 구조체 레이아웃 복원 (`xref layout --callees`)

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

### 3. 역방향 프로그램 슬라이싱 (`xref slice`)

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
          if ((i8)((u8 *)ptr_6)[v_9] < -64) {
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

### 4. 빌드 간 함수 재배치 및 정규화된 의사 C diff (`xref diff-c`)

아래에 들여쓰기된 `  ...` 줄은 diff 헝크 외부에서 변경되지 않은 정규화된 코드 줄을 표시하기 위해 `xref diff-c`가 직접 출력한 내용입니다:

```diff
$ xref -b xref.stripped diff-c --other xref-v0.0.2.stripped 0xd57c0
  warning: scores, ratios and pseudo-C similarities are heuristics, not calibrated probabilities or semantic equivalence proof
  warning: candidate list capped at 128 of 396; omitted plausible candidates keep ambiguity
  warning: pseudo-C ordering is heuristic inference; structural scores remain explicit
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
## 명령어 레퍼런스

[고급 옵션](https://github.com/alex09x/xref/blob/main/docs/advanced-options.md)에서 스택 변위 검색과 점프 레이블을 유지하는 출력 모드를 설명합니다.

[구조화 쿼리와 로컬 MCP](https://github.com/alex09x/xref/blob/main/docs/mcp.md)를 통해 동일한 분석 코어에 프로그램으로 접근할 수 있습니다.

[범위가 제한된 조사](https://github.com/alex09x/xref/blob/main/docs/investigations.md)는 문자열, 참조, 호출, 인수 근거와 명시적으로 선택한 슬라이스를 연결하며 후보와 제한 정보를 유지합니다.

[필드 출처 조사](https://github.com/alex09x/xref/blob/main/docs/field-origin.md)는 진입 레지스터 기준 주소와 로드된 값을 구분하고 메모리 접근 및 호출 대상의 명령 근거를 제공합니다.

### 인벤토리, 심볼 및 상호 참조

```text
xref -b BIN stats                                    # functions, .text bytes, pointers, imports, panic locations
xref -b BIN sym PATTERN                              # symbol search (non-stripped binaries)
xref -b BIN func 0xa1b50                             # function span containing an address
xref -b BIN refs "goto L_" 0xa1b50                   # .rodata / pointer / code xrefs (--inline for mov/movabs stores)
xref -b BIN istr "text"                              # shorthand for refs --inline
xref -b BIN imm 24 --in 0xa1b50                      # immediate constants (--store, --cmp, --in FN)
xref -b BIN find --src src/loops.rs --calls 0x160bb0 # single-pass multi-predicate function search (--any K)
xref -b BIN find --insn 'divsd xmm*' --size 0x10..0x400 # functions containing matching instructions
```

### 구조체 레이아웃, 변위 및 호출 그래프

```text
xref -b BIN disp 0x20 0x28 --all                     # field loads/stores/leas (--write, --lea, --stride, --in FN)
xref -b BIN layout 0xa2270 --reg rsi --callees       # aggregate field offsets, widths, strides & 1-hop callees
xref -b BIN card 0xa2270                             # function summary card: inputs, exits, stores, callees (--json)
xref -b BIN field --keys c,m,e --write --writes-all-of m,e # serialized keys -> field layout & ranked writers
xref -b BIN callers 0xcafb0                          # direct calls/tail-jumps, address-taken & pointer-table xrefs
xref -b BIN calls 0xcafb0                            # outgoing calls and tail-jumps in instruction order
xref -b BIN args 0xa2270 --max 20                    # constant & symbolic arguments across all call sites
xref -b BIN args 0xa2270 --filter 'rdx == 0'         # preflight probe filter against call-site arguments
xref -b BIN callargs 39 --arg r9                     # every call passing 39 in r9, grouped by callee
xref -b BIN path 0xc7fc0 0x160bb0 --depth 8          # shortest call chains between two functions
xref -b BIN tree 0xd0aa0 --callers --depth 2         # indented caller/callee tree with panic source anchors
```

### 디스어셈블리, 의사 C, 슬라이싱, 크레이트 내보내기 및 diff

```text
xref -b BIN asm 0xc7d60 --from A --to B              # annotated Intel disassembly (strings, slots, targets)
xref -b BIN c 0x9a8a0 --fields                       # structured typed pseudo-C (--out DIR for parallel batch export)
xref -b BIN slice 0xc7d60 --to fn_160bb0 --fields    # backward slice to target call, hex IP, offset, or string
xref -b BIN slice 0xc7d60 --to-field "+0x10 of rax@0xc7d60" # slice focused on accesses to a struct field
xref -b BIN dump --out DIR --src src/loops.rs        # parallel modular .c export grouped by panic source paths
xref -b BIN match --other OLD_BIN 0xc7d60 --top 3    # relocate shifted stripped functions across two builds
xref -b BIN diff-c --other OLD_BIN 0xd57c0           # normalized cross-build pseudo-C LCS diff
```

### Rust 소스 위치 및 열거형 점프 테이블

```text
xref -b BIN src 0x9a8a0                              # core::panic::Location (file:line:col) descriptors in function
xref -b BIN where src/image.rs --line 46             # stripped functions referencing a Rust file (and line)
xref -b BIN files src/                               # distinct Rust source files recovered from panic descriptors
xref -b BIN error "invalid"                          # jump-table discriminant whose Display arm names text
xref -b BIN variant 0xc7fc0 1 2                      # inverse of error: texts referenced by jump-table arms
xref -b BIN arm 0xc8010                              # jump-table indices whose arm contains an address
```

### 오류 기원, 출처와 타입 지정 데이터
```text
xref -b BIN origin "number out of range"            # tag stores, conversions, passed tags, guards & record readers
xref -b BIN deps --filter tokio --json               # embedded cargo-auditable / Go manifest, toolchains, Build-ID
xref -b BIN data 0x492c0b --as str                   # typed values at a VA (u8..u64, i8..i64, f32, f64, bytes, str)
xref -b BIN table 0x1da3e0 --stride 0x20             # fixed-size records / vtables with their relocated pointers
```

### 프로파일 및 오프라인 트레이스
```text
xref -b BIN profile report app.xprof --by function --top 30 # summarize a recorded or imported profile
xref -b BIN profile annotate app.xprof 0x1234 --c    # sample shares on pseudo-C (or assembly without --c)
xref -b BIN profile diff before.xprof after.xprof    # compare two profiles normalized by their sample counts
xref -b BIN profile import perf.data --out app.xprof # native perf.data / perf script import (bounded Intel PT)
xref -b BIN symbolize --input addresses.txt --base 0x555555554000 # saved addresses/stacks -> static functions
xref -b BIN edges import --format perf --input stacks.perf.txt --out observed.json # observed call edges for callers/tree/path
```

---

<a name="architecture"></a>
## 아키텍처

```mermaid
flowchart LR
    ELF["x86-64 ELF / Mach-O Image\n(load maps, unwind, linkage)"] --> Span["Span & Runtime Discovery\n(.eh_frame FDEs + fallback,\npanic Location & helper map)"]
    Span --> Decode["Parallel Decode (rayon)\niced-x86 instruction stream\n& jump-table recovery"]
    Decode --> Xref["Direct Xref & Layout Queries\nrefs / disp / layout / find /\ncallers / args / match"]
    Decode --> CFG["CFG & Region Structurer\nnatural loops, cold noreturn\ninlining & skip-flag guards"]
    CFG --> SSA["SSA Webs & Lifting\n128-bit widening ALU, carry/borrow,\nbidirectional types & SIB arrays"]
    SSA --> Emit["C Emitter, Slicer & Differ\nxref c / slice / dump / diff-c"]
```

---

<a name="recorded-performance"></a>
## 벤치마크 성능

스트립된 `xref.stripped`(`1.96 MB`, `1,974`개 함수, `0`개 심볼)를 분석할 때 `AMD Ryzen 9 9950X`(16코어 / 32스레드, Linux 6.8 `x86_64`, 웜 OS 페이지 캐시) 환경에서 `xref 0.0.5`(`stderr`)가 보고한 단일 실행 CLI 경과 시간:

| 작업 | 명령어 | ELF 로드 | 총 소요 시간 |
|---|---|---:|---:|
| 바이너리 인벤토리 (`1,974`개 함수, `588`개 패닉 위치) | `xref -b xref.stripped stats` | `0.84 ms` | **`2.2 ms`** |
| 전체 바이너리 문자열 및 포인터 상호 참조 스캔 | `xref -b xref.stripped refs "goto L_"` | `0.80 ms` | **`3.9 ms`** |
| 내장 패닉 위치 기반 Rust 모듈 매핑 | `xref -b xref.stripped where src/loops.rs` | `0.79 ms` | **`3.4 ms`** |
| 프로시저 간 구조체 레이아웃 복원 (1홉 피호출 함수) | `xref -b xref.stripped layout 0xa2270 --reg rsi --callees` | `0.81 ms` | **`2.6 ms`** |
| 역방향 프로그램 슬라이스 + 필드 오프셋 힌트 | `xref -b xref.stripped slice 0xc7d60 --to fn_160bb0 --fields` | `0.81 ms` | **`5.1 ms`** |
| 빌드 간 함수 매칭 및 정규화된 의사 C diff | `xref -b xref.stripped diff-c --other xref-v0.0.2.stripped 0xc7d60` | `0.86 ms` | **`13.4 ms`** |

---

<a name="scope--limitations"></a>
## 적용 범위 및 한계

- **지원 입력:** `x86-64` ELF 바이너리와 공유 객체(`ET_EXEC`, `ET_DYN`). v0.2.0부터 DWARF unwind 정보가 있는 thin little-endian x86-64 Mach-O 실행 파일, dylib, bundle도 지원합니다. [Mach-O 입력](https://github.com/alex09x/xref/blob/main/docs/macho.md)을 참조하세요. 배포된 v0.1.0은 ELF만 지원합니다. ARM64, PE, fat/universal 및 compact unwind만 있는 입력은 지원하지 않습니다.
- **함수 경계 탐색:** 정확한 함수 범위는 `.eh_frame` 언와인드 테이블에서 가져옵니다(`x86-64`에서는 `strip --strip-all` 이후에도 `rustc`, `clang`, `gcc`가 기본적으로 생성함). 언와인드 항목이 없는 경우 갭/호출 대상 스팬 대체 기능이 작동합니다. `.eh_frame`까지 제거된 바이너리(`strip -R .eh_frame`)는 휴리스틱 스팬 경계에 의존합니다.
- **라이브 분석:** Linux x86-64 전용이며 세션당 대상 실행 파일은 하나입니다. 공유 라이브러리 내부의 쓰기 명령어와 호출자는 정적 함수나 기록된 값 없이 대상 실행 파일 외부로 보고됩니다. `probe`, `watch`, `trace`는 perf 또는 tracefs에 대한 권한 있는 접근이 필요하며 관찰 대상 프로세스에 트랩을 추가합니다. `profile`을 권한 없이 실행할 수 있는지는 커널의 `perf_event_paranoid` 정책, 대상에 대한 ptrace 접근, 선택한 이벤트에 따라 달라집니다. `--trigger-probe` 모드에는 시스템 전체 perf 접근과 쓰기 가능한 tracefs가 필요합니다.
- **직렬화된 필드 검색:** 쓰기 함수 순위는 명령어 근거에 기반한 휴리스틱이며, 함수가 특정 객체를 다룬다는 증명이 아닙니다. 전체 이미지 스캔에는 한도가 있으며(함수 262,144개, 코드 128 MiB, 엣지 및 30초 예산), 한도에 도달하면 커버리지에 보고합니다.
- **오류 기원:** `origin`은 태그 값, 너비, 레이아웃의 일치 정도에 따라 후보 지점과 가드 조건을 나열하며 실행을 증명하지는 않습니다. 전달된 태그는 최대 `--arg-depth` 호출과 64개 함수까지 추적합니다. 16바이트 또는 32바이트 벡터 로드로 이동한 레코드 필드는 해당 로드에 표시되며 더 추적하지 않습니다.
- **출처:** `deps`는 바이너리에 내장된 내용만 보고합니다. `cargo-auditable` 없이 빌드한 Rust 바이너리에는 매니페스트가 없으며 문자열에서 크레이트를 추측하지 않습니다. 버전은 기록된 문자열이며 레지스트리나 보안 권고 데이터베이스와 대조하지 않습니다.
- **정적 의사 C 및 오프셋 추론:** 매개변수 서명(`arg_*`), 추론된 포인터/정수 타입(`const void *`, `usize`, `unk64` 등) 및 `--fields` 오프셋 힌트(`->f_<off>`)는 DWARF 소스 타입이 아니라 기계어 명령어 사용 패턴을 기반으로 보수적으로 정적 재구성한 것입니다. 모델링되지 않은 SIMD/시스템 명령어는 자동으로 무시되지 않고 명시적인 `/* 0xaddr: ... */` 어셈블리 주석으로 인라인 보존됩니다. 중요한 불변 조건은 항상 `xref asm`으로 교차 확인하십시오.

---

<a name="development--testing"></a>
## 개발 및 테스트

테스트를 실행할 때 `PATH`에 `rustc`가 있어야 합니다. 엔드투엔드 테스트 스위트는 `tests/fixtures/sample.rs`를 임시 ELF 픽스처로 컴파일하고 이에 대해 CLI 하위 명령어를 검증합니다.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

---

<a name="citation"></a>
## 인용

아래 항목은 가장 최근에 아카이빙된 스냅샷(`v0.5.0`)입니다. 이전 `v0.4.0` 스냅샷: [10.5281/zenodo.23968336](https://doi.org/10.5281/zenodo.23968336); `v0.3.0` 스냅샷: [10.5281/zenodo.23932112](https://doi.org/10.5281/zenodo.23932112); `v0.2.0` 스냅샷: [10.5281/zenodo.23902824](https://doi.org/10.5281/zenodo.23902824); `v0.1.0` 스냅샷: [10.5281/zenodo.23878790](https://doi.org/10.5281/zenodo.23878790).

```bibtex
@software{panasenko_2026_24076380,
  author       = {Panasenko, Alexander},
  title        = {XRef — Ultra Blazing Fast x86-64 ELF and Mach-O
                   Analysis, Live Linux Process Inspection, Pseudo-C
                   and Local MCP
                  },
  month        = nov,
  year         = 2026,
  publisher    = {Zenodo},
  version      = {0.5.0},
  doi          = {10.5281/zenodo.24076380},
  url          = {https://doi.org/10.5281/zenodo.24076380}
}
```

- Alexander Panasenko (2026). *XRef — Ultra Blazing Fast x86-64 ELF and Mach-O Analysis, Live Linux Process Inspection, Pseudo-C and Local MCP* (v0.5.0). Zenodo. https://doi.org/10.5281/zenodo.24076380 ([concept DOI: 10.5281/zenodo.23878789](https://doi.org/10.5281/zenodo.23878789))

---

<a name="license"></a>
## 라이선스

저작권 © 2026 [Alexander Panasenko](https://prod.codes/about/) (`alex@prod.codes`).

다음 중 하나의 라이선스에 따라 이중 라이선스가 적용됩니다:
- **Apache License, Version 2.0** ([`LICENSE-APACHE`](../LICENSE-APACHE) 또는 http://www.apache.org/licenses/LICENSE-2.0)
- **MIT License** ([`LICENSE-MIT`](../LICENSE-MIT) 또는 http://opensource.org/licenses/MIT)

선택에 따라 사용할 수 있습니다.
