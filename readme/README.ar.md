<!-- translation-source: d6a4b63cfa231723b1095f61014ef1b374070d64 -->

> [!NOTE]
> هذه ترجمة للتوثيق الإنجليزي الأصلي لـ [الإيداع d6a4b63](https://github.com/alex09x/xref/blob/d6a4b63cfa231723b1095f61014ef1b374070d64/README.md). النسخة القياسية والأحدث متاحة دائمًا بـ [اللغة الإنجليزية](https://github.com/alex09x/xref/blob/main/README.md).

<div dir="rtl">

<div align="center" dir="ltr">

[English](https://github.com/alex09x/xref/blob/main/README.md) | [Русский](https://github.com/alex09x/xref/blob/main/readme/README.ru.md) | [简体中文](https://github.com/alex09x/xref/blob/main/readme/README.zh-CN.md) | [Español](https://github.com/alex09x/xref/blob/main/readme/README.es.md) | [Português (Brasil)](https://github.com/alex09x/xref/blob/main/readme/README.pt-BR.md) | [日本語](https://github.com/alex09x/xref/blob/main/readme/README.ja.md) | [Deutsch](https://github.com/alex09x/xref/blob/main/readme/README.de.md) | [Français](https://github.com/alex09x/xref/blob/main/readme/README.fr.md) | [한국어](https://github.com/alex09x/xref/blob/main/readme/README.ko.md) | **[العربية](https://github.com/alex09x/xref/blob/main/readme/README.ar.md)**

<br/>

<img src="../docs/logo-banner.svg" alt="XRef (xref)" width="732"/>

<br/><br/>

**مراجع متقاطعة فائقة السرعة، استعادة تخطيط البنى (structs)، تجزيء البرامج (slicing)، وشبه كود C مهيكل لملفات x86-64 ELF / Mach-O الثنائية.**

تحليل ثنائي بدون فهرسة مسبقة (zero-index) بلغة Rust الآمنة تمامًا (`#![forbid(unsafe_code)]`). تُستخرج حدود الدوال مباشرة من جداول تتبع المكدس `.eh_frame` (مع دعم بديل للنطاقات)، وتُفكك الاستعلامات عبر الملف الثنائي بالكامل عبر جميع أنوية المعالج في أجزاء من الثانية — حتى على ملفات Rust الثنائية المجردة تمامًا من الرموز (stripped) حيث تكون جداول الرموز فارغة.

<br/>

[**بيئة العمل التفاعلية (xrefcode.com)**](https://xrefcode.com) · بواسطة [Alexander Panasenko](https://prod.codes/about/)

<br/>

[![GitHub release](https://img.shields.io/github/v/release/alex09x/xref?color=e8c57a&labelColor=1a1d24&style=flat-square)](https://github.com/alex09x/xref/releases)
[![Crates.io](https://img.shields.io/crates/v/xref-code?color=e8c57a&label=crates.io&labelColor=1a1d24&style=flat-square)](https://crates.io/crates/xref-code)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.23878789-7ef0b3?labelColor=1a1d24&style=flat-square)](https://doi.org/10.5281/zenodo.23878789)
[![CI](https://img.shields.io/github/actions/workflow/status/alex09x/xref/ci.yml?branch=main&color=2ea043&labelColor=1a1d24&style=flat-square)](https://github.com/alex09x/xref/actions)
[![License](https://img.shields.io/badge/license-MIT_%2F_Apache--2.0-e8c57a?labelColor=1a1d24&style=flat-square)](../LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-edition_2024-dea584?labelColor=1a1d24&style=flat-square)](../Cargo.toml)
[![Safety](https://img.shields.io/badge/unsafe-forbidden-2ea043?labelColor=1a1d24&style=flat-square)](../Cargo.toml)

<br/>

[**لماذا**](#why) · [**التثبيت**](#installation) · [**البدء السريع**](#quick-start) · [**أمثلة مسجلة**](#recorded-examples) · [**دليل الأوامر**](#command-reference) · [**البنية المعمارية**](#architecture) · [**الأداء**](#recorded-performance) · [**القيود والمدى**](#scope--limitations) · [**الاقتباس**](#citation)

</div>

---

<a name="why"></a>
## لماذا

تفترض حزم الهندسة العكسية التقليدية وجود محلل تفاعلي واحد مستعد للانتظار لدقائق لاستيراد قاعدة بيانات البرنامج بالكامل قبل طرح السؤال الأول. وتزداد الأمور تعقيدًا مع ملفات Rust الثنائية المجردة من الرموز (stripped): فالرموز مفقودة، والسلاسل النصية عبارة عن شرائح `(ptr, len)` غير منتهية بقيمة صفرية في تجمعات `.rodata`، كما أن حالات الذعر الناتجة عن فحص الحدود (bounds-check panics) تفتت الحلقات التكرارية إلى مسارات باردة تحيل مخرجات أدوات فك الترجمة البسيطة إلى فوضى غير مقروءة من تعليمات `goto`.

تم بناء **XRef** (`xref`) للتحقيق التكراري السريع من قبل مهندسي الهندسة العكسية ووكلاء الذكاء الاصطناعي المستقلين على حد سواء:

- **بلا فهرس مسبق، وبلا تخزين مؤقت قديم.** تقوم أوامر التحليل بتعيين صورة ELF في الذاكرة، واستخراج نطاقات الدوال الدقيقة من سجلات `.eh_frame` (مع دعم تلقائي بديل لحدود النطاقات)، وفحص الدوال بالتوازي عبر `rayon`. الاستثناء هو `xref field`: إذ يحتفظ بفهرس اختياري على القرص مرتبط بمحتوى ملف الإدخال والملف التنفيذي لـ xref، وقد يعيد تشغيل تقرير محفوظ أو يستعلم من field daemon يعمل في الخلفية، وكلاهما مرتبط بالمسار القانوني للملف وبياناته الوصفية (الجهاز، وinode، والحجم، وزمنَي التعديل والتغيير). وأي تغيير يؤدي إلى إعادة بنائهما أو تجاوزهما.
- **شبه كود C أصلي ومُهيكل ومُحدد الأنواع (`xref c`).** يرفع كود آلة x86-64 مباشرة إلى كود C مقروء دون أدوات خارجية — مستعيدًا تواقيع المعاملات غير القابلة للتغيير `arg_0..arg_5`، وشبكات مدى حياة SSA (`ptr_*` و `v_*` و `slot_*`)، ومصفوفات مفهرسة بنمط SIB، وعمليات توسيع `128-بت` أحادية المعامل `mul`/`imul`/`div`/`idiv`، وسلاسل الحمل والاستعارة متعددة الدقة `adc`/`sbb`، وعمليات مدمجة لاكتشاف فيض العمليات الحسابية ذات الإشارة، وتراكيب التحكم المهيكلة `if`/`else`/`while`/`do-while`/`switch`.
- **استعادة مخصصة لملفات Rust الثنائية المجردة.** يتعرف على دوال بيئة تشغيل Rust المجردة (`rust_panic_bounds_check` و `rust_slice_index_fail` و `rust_capacity_overflow`)، ويستخرج نصوص `&str` الدقيقة كشرائح `(ptr, len)`، ويربط واصفات `core::panic::Location` (`الملف:السطر:العمود`) بمسارات الحزم البرمجية الأصلية، ويحل فروع جداول القفز لـ `Display`.
- **التجزيء والمقارنة عبر البناءات (`xref slice` و `xref match` و `xref diff-c`).** يعزل التعليمات المتوازنة وحراس التحكم المؤديين إلى استدعاء محدد أو عنوان تعليمة IP، ويعيد تحديد مواقع الدوال المجردة المنقولة بين البناءات المختلفة، ويقارن كود C المعياري المجرد من عناوين الذاكرة الست عشرية المتغيرة.
- **البحث عن الحقول المُسلسلة (`xref field`).** يربط سلاسل المفاتيح المُسلسلة بإزاحات حقول البُنى مع تعليمات شاهدة، ويرتّب الدوال المرشحة التي تكتب هذه الحقول، مع إمكانية الاقتصار على الدوال التي تكتب عبر مؤشر مُعاد أو مؤشر وسيط أو مؤشر محمّل (`--writer-root`). النتائج مرشحات مع أدلتها، وليست إثباتًا لنوع المصدر.
- **فحص عمليات لينكس قيد التشغيل (`xref live`).** يربط الرؤية الاستاتيكية بعملية قيد التشغيل على Linux x86-64: يبحث عن القيم في الذاكرة، ويطابق مؤشرات وقت التشغيل مع الدوال الاستاتيكية، ويحصي الاستدعاءات والمستدعين عبر uprobes محدودة، ويحدد التعليمة التي تكتب حقلًا عبر نقاط مراقبة العتاد، ويسجّل نوافذ استدعاءات مرتبة لكل خيط (`live trace`) وملفات تعريف محدودة لوحدة المعالجة المركزية (`live profile`) — وكل نتيجة تذكر تغطيتها وحدودها.
- **ملفات التعريف والتتبعات دون اتصال (`xref profile`، `xref symbolize`، `xref edges`).** يلخّص تسجيلات `.xprof` ويعلّق عليها ويقارن بينها، ويستورد `perf.data` (بما في ذلك فك ترميز Intel PT المحدود) ونص `perf script`، ويطابق المكدسات المحفوظة وحواف الاستدعاء المرصودة مع الملف التنفيذي المحدد.

استكشف **114 تشغيلًا مسجلاً بالكامل دون تعديل** لأوامر CLI على ملف `xref` المجرد نفسه في بيئة العمل الثابتة للمتصفح عبر **[xrefcode.com](https://xrefcode.com)**.

---

<a name="installation"></a>
## التثبيت

### عبر Homebrew (لأجهزة macOS مع معالجات Apple Silicon ولينكس `x86_64`)

يثبت الملف الثنائي المترجم مسبقًا لـ `xref` مباشرة من مستودع [`alex09x/homebrew-apps`](https://github.com/alex09x/homebrew-apps) (دون البناء من المصدر باستخدام Cargo):

<div dir="ltr">

```bash
brew tap alex09x/apps
brew install xref
xref --version
```

</div>

### الأرشيفات المترجمة مسبقًا للإصدارات (لينكس `x86_64` و macOS `arm64`)

تتضمن الأرشيفات الجاهزة (`x86_64-unknown-linux-gnu`، التي تتطلب `glibc >= 2.34`، و `aarch64-apple-darwin`) كلاً من `xref` و `README.md` و `LICENSE-MIT` و `LICENSE-APACHE` و `CITATION.cff`:

<div dir="ltr">

```bash
curl -fsSLO https://github.com/alex09x/xref/releases/download/v0.4.0/xref-v0.4.0-x86_64-unknown-linux-gnu.tar.gz
curl -fsSLO https://github.com/alex09x/xref/releases/download/v0.4.0/xref-v0.4.0-x86_64-unknown-linux-gnu.tar.gz.sha256
sha256sum -c xref-v0.4.0-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf xref-v0.4.0-x86_64-unknown-linux-gnu.tar.gz
./xref --version
```

</div>

### عبر Cargo و `crates.io` (لينكس و macOS)

منشور على [`crates.io` باسم `xref-code`](https://crates.io/crates/xref-code)، ويثبت ملف CLI الثنائي `xref` (يتطلب `rustc 1.88+` لدعم سلاسل `let` في إصدار 2024؛ كما تعمل الثنائيات المترجمة مسبقًا عبر [`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall)):

<div dir="ltr">

```bash
cargo install xref-code --locked
# or prebuilt via cargo-binstall:
cargo binstall xref-code -y
# or directly from the pinned release tag:
cargo install --git https://github.com/alex09x/xref --tag v0.4.0 --locked
```

</div>

---

<a name="quick-start"></a>
## البدء السريع

مرر `-b <BINARY>` مع كل أمر أو اضبط `XREF_BIN=/path/to/binary` لكل جلسة. العناوين هي VA ثابتة للصورة بصيغة `0x` الست عشرية أو العشرية؛ قاعدة RVA لملفات Mach-O هي `__TEXT.vmaddr`.

<div dir="ltr">

```bash
export XREF_BIN=./xref.stripped

xref stats                                      # function count, .text bytes, pointers, panic locations
xref refs "goto L_"                             # code & data references to strings or addresses (--inline)
xref where src/loops.rs                         # stripped function ranges compiled from a Rust source file
xref layout 0xa2270 --reg rsi --callees         # recover struct field offsets, sizes, strides & 1-hop callees
xref c 0x9a8a0 --fields                         # structured typed pseudo-C with inferred ->f_<off> hints
xref c 0x9a8a0 --only-paths-to 0x9a950          # pseudo-C containing only basic blocks that reach ADDR
xref slice 0xc7d60 --to fn_160bb0               # backward slice of statements & guards reaching a target
xref query '{"operation":"info"}'              # versioned JSON for one immutable image
xref mcp                                       # local read-only stdio MCP server
```

</div>

---

<a name="live-analysis-linux-x86-64"></a>
## التحليل المباشر (Linux x86-64)

بدءاً من الإصدار v0.3.0، يربط `xref live` عملية جارية على Linux x86-64 بالتحليل الاستاتيكي لملفها التنفيذي الموثق. مرر نفس ملف ELF عبر الخيار `-b`؛ حيث يتحقق منه xref بمطابقته مع `/proc/<pid>/exe` (بمعرف البناء GNU build-id أو ترميز SHA-256) قبل ترجمة أي عنوان.

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

- العمليات `maps` و `resolve` و `memscan` تقرأ فقط من `/proc/<pid>/maps` و `/proc/<pid>/mem` (يتطلب ذلك صلاحية ptrace للعملية المستهدفة؛ دون إيقاف العملية).
- العمليات `probe` و `watch` تفتح أحداث perf على الهدف وتتطلب وصولاً مميزاً لأحداث perf (صلاحية root أو `CAP_PERFMON`). يمثل كل اصطدام مصيدة (trap) داخل العملية المستهدفة، لذا احرص على إبقاء نوافذ المراقبة قصيرة في العمليات كثيفة النشاط.
- يستخدم `trace` نسخة معزولة من uprobes في `tracefs` ويتطلب tracefs قابلًا للكتابة (عادةً صلاحية root)؛ تُغلق نوافذه عند عنوان التوقف أو الرجوع المحدد وتتوقف عند حدود صريحة لعدد النوافذ والأحداث والوقت. أما `profile` فيأخذ العينات عبر أحداث perf ويفشل عندما لا تسمح سياسة النواة بالأحداث المطلوبة بدلًا من استبدالها بصمت.
- تفصل النتائج بوضوح بين الملاحظة والاستنتاج: الإحصاء الصفري يغطي فقط النافذة الزمنية والخيوط المحددة، وتعليمة الكتابة المكتشفة هي مرشح بدرجة ثقة صريحة، وتجعل الأحداث المفقودة أو الخيوط المرتبطة متأخراً الإحصاءات حداً أدنى موثوقاً.

جلسة مسجلة خطوة بخطوة (البحث في الذاكرة ← الدالة الاستاتيكية ← إحصاءات الاستدعاء ← تعليمة كتابة الحقل ← انتقال المخزن المؤقت): **[دليل التحليل المباشر المسجل (Live Analysis walkthrough)](https://xrefcode.com/live-walkthrough)**. العقد والقيود: [docs/live.md](https://github.com/alex09x/xref/blob/main/docs/live.md)؛ بروتوكول MCP: [docs/mcp.md](https://github.com/alex09x/xref/blob/main/docs/mcp.md).

---

<a name="recorded-examples"></a>
## أمثلة مسجلة

جميع المخرجات أدناه عبارة عن تشغيلات حقيقية كاملة وغير معدلة سُجلت من `xref.stripped` (`1,962,608` بايت، و `0` رموز، و `sha256:3f3ba3b311f3eca8e26a929285d4fc9ffef4e4b6e8fc015105766180a2a6869d`) وتم التحقق منها في CI لتطابق `docs/recorded-data.js` سطرًا بسطر (باستثناء المسافات البيضاء في نهايات الأسطر).

### 1. شبه كود C مهيكل ومحدد الأنواع مع تلميحات إزاحة الحقول (`xref c --fields`)

<div dir="ltr">

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

</div>

### 2. استعادة تخطيط البنى عبر الإجراءات (`xref layout --callees`)

<div dir="ltr">

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

</div>

### 3. تجزيء البرامج العكسي (`xref slice`)

<div dir="ltr">

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

</div>

### 4. نقل العناوين عبر البناءات وفروقات كود C المعياري (`xref diff-c`)

السطور المزاحة بمسافة `  ...` أدناه صادرة مباشرة من أمر `xref diff-c` لتمييز الأسطر المعيارية غير المتغيرة خارج مقطع الفروقات:

<div dir="ltr">

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

</div>

---

<a name="command-reference"></a>
## دليل الأوامر

تشرح [الخيارات المتقدمة](https://github.com/alex09x/xref/blob/main/docs/advanced-options.md) البحث عن إزاحات المكدس ووضع الإخراج الذي يحتفظ بتسميات القفز.

تتيح [الاستعلامات المهيكلة وMCP المحلي](https://github.com/alex09x/xref/blob/main/docs/mcp.md) الوصول البرمجي إلى نواة التحليل نفسها.

تربط [التحقيقات المحدودة](https://github.com/alex09x/xref/blob/main/docs/investigations.md) السلاسل والمراجع والاستدعاءات وأدلة الوسائط والشريحة المختارة صراحةً، مع الحفاظ على البدائل والحدود.

تميّز [تحقيقات أصل الحقول](https://github.com/alex09x/xref/blob/main/docs/field-origin.md) بين العناوين النسبية إلى سجل الدخول والقيم المحمّلة، وتحتفظ بأدلة تعليمات الذاكرة والدوال المستدعاة.

### الجرد والرموز والمراجع المتقاطعة

<div dir="ltr">

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

</div>

### تخطيط البنى والإزاحات ومخططات الاستدعاء

<div dir="ltr">

```text
xref -b BIN disp 0x20 0x28 --all                     # field loads/stores/leas (--write, --lea, --stride, --in FN)
xref -b BIN layout 0xa2270 --reg rsi --callees       # aggregate field offsets, widths, strides & 1-hop callees
xref -b BIN card 0xa2270                             # function summary card: inputs, exits, stores, callees (--json)
xref -b BIN field --keys c,m,e --write --writes-all-of m,e # serialized keys -> field layout & ranked writers
xref -b BIN callers 0xcafb0                          # direct calls/tail-jumps, address-taken & pointer-table xrefs
xref -b BIN calls 0xcafb0                            # outgoing calls and tail-jumps in instruction order
xref -b BIN args 0xa2270 --max 20                    # constant & symbolic arguments across all call sites
xref -b BIN args 0xa2270 --filter 'rdx == 0'         # preflight probe filter against call-site arguments
xref -b BIN path 0xc7fc0 0x160bb0 --depth 8          # shortest call chains between two functions
xref -b BIN tree 0xd0aa0 --callers --depth 2         # indented caller/callee tree with panic source anchors
```

</div>

### التفكيك، وشبه كود C، والتجزيء، وتصدير الحزم، والمقارنة

<div dir="ltr">

```text
xref -b BIN asm 0xc7d60 --from A --to B              # annotated Intel disassembly (strings, slots, targets)
xref -b BIN c 0x9a8a0 --fields                       # structured typed pseudo-C (--out DIR for parallel batch export)
xref -b BIN slice 0xc7d60 --to fn_160bb0 --fields    # backward slice to target call, hex IP, offset, or string
xref -b BIN slice 0xc7d60 --to-field "+0x10 of rax@0xc7d60" # slice focused on accesses to a struct field
xref -b BIN dump --out DIR --src src/loops.rs        # parallel modular .c export grouped by panic source paths
xref -b BIN match --other OLD_BIN 0xc7d60 --top 3    # relocate shifted stripped functions across two builds
xref -b BIN diff-c --other OLD_BIN 0xd57c0           # normalized cross-build pseudo-C LCS diff
```

</div>

### مواقع مصادر Rust وجداول قفز التعدادات (Enums)

<div dir="ltr">

```text
xref -b BIN src 0x9a8a0                              # core::panic::Location (file:line:col) descriptors in function
xref -b BIN where src/image.rs --line 46             # stripped functions referencing a Rust file (and line)
xref -b BIN files src/                               # distinct Rust source files recovered from panic descriptors
xref -b BIN error "invalid"                          # jump-table discriminant whose Display arm names text
xref -b BIN variant 0xc7fc0 1 2                      # inverse of error: texts referenced by jump-table arms
xref -b BIN arm 0xc8010                              # jump-table indices whose arm contains an address
```

</div>

### ملفات التعريف والتتبعات دون اتصال

<div dir="ltr">

```text
xref -b BIN profile report app.xprof --by function --top 30 # summarize a recorded or imported profile
xref -b BIN profile annotate app.xprof 0x1234 --c    # sample shares on pseudo-C (or assembly without --c)
xref -b BIN profile diff before.xprof after.xprof    # compare two profiles normalized by their sample counts
xref -b BIN profile import perf.data --out app.xprof # native perf.data / perf script import (bounded Intel PT)
xref -b BIN symbolize --input addresses.txt --base 0x555555554000 # saved addresses/stacks -> static functions
xref -b BIN edges import --format perf --input stacks.perf.txt --out observed.json # observed call edges for callers/tree/path
```

</div>

---

<a name="architecture"></a>
## البنية المعمارية

<div dir="ltr">

```mermaid
flowchart LR
    ELF["x86-64 ELF / Mach-O Image\n(load maps, unwind, linkage)"] --> Span["Span & Runtime Discovery\n(.eh_frame FDEs + fallback,\npanic Location & helper map)"]
    Span --> Decode["Parallel Decode (rayon)\niced-x86 instruction stream\n& jump-table recovery"]
    Decode --> Xref["Direct Xref & Layout Queries\nrefs / disp / layout / find /\ncallers / args / match"]
    Decode --> CFG["CFG & Region Structurer\nnatural loops, cold noreturn\ninlining & skip-flag guards"]
    CFG --> SSA["SSA Webs & Lifting\n128-bit widening ALU, carry/borrow,\nbidirectional types & SIB arrays"]
    SSA --> Emit["C Emitter, Slicer & Differ\nxref c / slice / dump / diff-c"]
```

</div>

---

<a name="recorded-performance"></a>
## الأداء المسجل

أوقات التنفيذ الفعلية لأوامر CLI كما سجلتها أداة `xref 0.0.5` (عبر `stderr`) على معالج `AMD Ryzen 9 9950X` (بـ 16 نواة / 32 خيط معالجة، على Linux 6.8 `x86_64`، مع ذاكرة تخزين مؤقت دافئة لصفحات نظام التشغيل) أثناء تحليل الملف الثنائي المجرد `xref.stripped` بحجم (`1.96 MB`، و `1,974` دالة، و `0` رموز):

| العملية | الأمر | تحميل ELF | الوقت الإجمالي |
|---|---|---:|---:|
| جرد الملف الثنائي (`1,974` دالة، `588` موقع ذعر) | `xref -b xref.stripped stats` | `0.84 ms` | **`2.2 ms`** |
| مسح المراجع المتقاطعة للنصوص والمؤشرات عبر كامل الملف الثنائي | `xref -b xref.stripped refs "goto L_"` | `0.80 ms` | **`3.9 ms`** |
| مطابقة وحدات Rust من مواقع الذعر المضمنة | `xref -b xref.stripped where src/loops.rs` | `0.79 ms` | **`3.4 ms`** |
| استعادة تخطيط البنى عبر الإجراءات (دوال من المستوى الأول) | `xref -b xref.stripped layout 0xa2270 --reg rsi --callees` | `0.81 ms` | **`2.6 ms`** |
| تجزيء البرنامج العكسي + تلميحات إزاحة الحقول | `xref -b xref.stripped slice 0xc7d60 --to fn_160bb0 --fields` | `0.81 ms` | **`5.1 ms`** |
| مطابقة الدوال عبر البناءات ومقارنة كود C المعياري | `xref -b xref.stripped diff-c --other xref-v0.0.2.stripped 0xc7d60` | `0.86 ms` | **`13.4 ms`** |

---

<a name="scope--limitations"></a>
## النطاق والقيود

- **المدخلات المدعومة:** ملفات ELF الثنائية والمكتبات المشتركة `x86-64` (`ET_EXEC` و `ET_DYN`). يدعم الإصدار v0.2.0 وما بعده أيضًا ملفات Mach-O التنفيذية وdylib وbundle من نوع thin little-endian x86-64 مع DWARF unwind؛ راجع [مدخلات Mach-O](https://github.com/alex09x/xref/blob/main/docs/macho.md). الإصدار المنشور v0.1.0 يدعم ELF فقط. لا تُدعم ARM64 أو PE أو fat/universal أو الملفات التي تحتوي على compact unwind فقط.
- **تحديد حدود الدوال:** تُستخرج نطاقات الدوال الدقيقة من جداول تتبع المكدس `.eh_frame` (المولدة افتراضيًا بواسطة `rustc` و `clang` و `gcc` على معماريات `x86-64` حتى بعد تنفيذ `strip --strip-all`)، مع الرجوع التلقائي إلى الفجوات وعناوين أهداف الاستدعاء عند غياب سجلات التتبع. وتعتمد الملفات الثنائية التي حُذفت منها سجلات `.eh_frame` تمامًا (`strip -R .eh_frame`) على حدود النطاقات الاستدلالية.
- **التحليل المباشر:** يقتصر على Linux x86-64، وملف تنفيذي هدف واحد لكل جلسة. تُصنَّف تعليمات الكتابة والمستدعيات داخل المكتبات المشتركة على أنها خارج الملف التنفيذي الهدف، دون دالة استاتيكية أو قيمة مكتوبة. تتطلب `probe` و `watch` و `trace` وصولًا مميزًا إلى perf أو tracefs وتضيف مصائد (traps) إلى العملية المرصودة. أما إمكانية تشغيل `profile` دون صلاحيات مميزة فتعتمد على سياسة النواة `perf_event_paranoid` وصلاحية ptrace على العملية الهدف والأحداث المختارة؛ ويتطلب وضع `--trigger-probe` وصولًا إلى perf على مستوى النظام و tracefs قابلًا للكتابة.
- **البحث عن الحقول المُسلسلة:** ترتيب الدوال الكاتبة استدلال تقريبي مبني على أدلة التعليمات، وليس إثباتًا أن دالة ما تتعامل مع كائن معين. فحص الصورة الكاملة محدود (262,144 دالة، و128 MiB من الشيفرة، وميزانيات للحواف و30 ثانية)، ويُبلغ في التغطية عند بلوغ أي حد.
- **شبه كود C الثابت واستنتاج الإزاحات:** تمثل تواقيع المعاملات (`arg_*`)، والأنواع المستنتجة للمؤشرات والأعداد الصحيحة (`const void *` و `usize` و `unk64` وغيرها)، وتلميحات إزاحة الحقول مع المعامل `--fields` (`->f_<off>`) عمليات إعادة بناء استاتيكية متحفظة مشتقة من استخدامات كود الآلة، وليست أنواع DWARF الأصلية المصدرية. كما يُحتفظ بتعليمات SIMD وتعليمات النظام غير المنمذجة بشكل صريح كتعليقات تجميعية `/* 0xaddr: ... */` مدمجة بدلاً من إسقاطها بصمت — تحقق دائمًا من الفرضيات الأساسية عبر `xref asm`.

---

<a name="development--testing"></a>
## التطوير والاختبار

يجب أن يكون `rustc` متاحًا في متغير البيئة `PATH` عند تشغيل الاختبارات: تقوم حزمة الاختبارات الشاملة (end-to-end) بترجمة `tests/fixtures/sample.rs` إلى ملف ELF تجريبي مؤقت وتتحقق من صحة أوامر CLI الفرعية عليه.

<div dir="ltr">

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

</div>

---

<a name="citation"></a>
## الاقتباس

القيد أدناه يمثل أحدث لقطة مؤرشفة (`v0.4.0`)؛ اللقطة المؤرشفة السابقة للإصدار `v0.3.0`: [10.5281/zenodo.23932112](https://doi.org/10.5281/zenodo.23932112)؛ `v0.2.0`: [10.5281/zenodo.23902824](https://doi.org/10.5281/zenodo.23902824)؛ واللقطة `v0.1.0`: [10.5281/zenodo.23878790](https://doi.org/10.5281/zenodo.23878790).

```bibtex
@software{panasenko_2026_23968336,
  author       = {Panasenko, Alexander},
  title        = {XRef — Ultra Blazing Fast x86-64 ELF and Mach-O
                   Analysis, Live Linux Process Inspection, Pseudo-C
                   and Local MCP
                  },
  month        = nov,
  year         = 2026,
  publisher    = {Zenodo},
  version      = {0.4.0},
  doi          = {10.5281/zenodo.23968336},
  url          = {https://doi.org/10.5281/zenodo.23968336}
}
```

</div>

- Alexander Panasenko (2026). *XRef — Ultra Blazing Fast x86-64 ELF and Mach-O Analysis, Live Linux Process Inspection, Pseudo-C and Local MCP* (v0.4.0). Zenodo. https://doi.org/10.5281/zenodo.23968336 ([معرّف DOI الجامع لجميع الإصدارات: 10.5281/zenodo.23878789](https://doi.org/10.5281/zenodo.23878789))

---

<a name="license"></a>
## الترخيص

حقوق النشر © 2026 [Alexander Panasenko](https://prod.codes/about/) (`alex@prod.codes`).

مرخص بترخيص مزدوج تحت أي من:
- **رخصة أباتشي، الإصدار 2.0** ([`LICENSE-APACHE`](../LICENSE-APACHE) أو http://www.apache.org/licenses/LICENSE-2.0)
- **رخصة MIT** ([`LICENSE-MIT`](../LICENSE-MIT) أو http://opensource.org/licenses/MIT)

حسب اختيارك.

</div>
