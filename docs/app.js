/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

(() => {
  const SELF_FUNCTIONS = [
    {
      addr: '0x9e840',
      end: '0x9edf8',
      size: 1464,
      label: 'image::Image::find_bytes (src/image.rs:46)',
      pseudo_c: `function 0x9e840..0x9edf8 (rdi, rsi, rdx, rcx) {
  sp_90 = rdi;
  sp_10 = 0;
  sp_18 = 8;
  sp_20 = 0;
  if (*(u64 *)(rsi + 40) != 0) {
    r9 = (rcx - 1);
    if ((rcx - 1) >= 0) goto L_9e898;
    sp_20 = 0;
  }
  goto L_9ec02;
L_9e898:
  r15 = *(u64 *)(rsi + 32);
  sp_98 = *(u64 *)(rsi + 8);
  sp_88 = rdx + 1;
  rcx = r15 + rax * 24;
  sp_80 = r15;
  sp_48 = *(u64 *)(rsi + 16);
  goto L_9e921;
L_9e914:
  r15 = (r15 + 24);
  if (r15 == rcx) goto L_9ebfc;
L_9e921:
  rax = (*(u64 *)(r15 + 16) + *(u64 *)(r15 + 8));
  if (rax < 0 || rax > sp_48) goto L_9e914;
  rdi = (*(u64 *)(r15 + 8) + sp_98);
  rax = bcmp(rdi, rdx, r9);
  return sp_90;
}`,
      typed_c: `/* struct sugar: rdi: 3 fields, rsi: 4 fields (1 Vec), rdx: 2 fields */
function 0x9e840..0x9edf8 (rdi, rsi, rdx, rcx) {
  sp_90 = rdi;
  sp_10 = 0;
  sp_18 = 8;
  sp_20 = 0;
  if (rsi->vec_20.len != 0) {
    r9 = (rcx - 1);
    if ((rcx - 1) >= 0) goto L_9e898;
    sp_20 = 0;
  }
  goto L_9ec02;
L_9e898:
  r15 = rsi->vec_20.ptr;
  sp_98 = rsi->f_8;
  sp_88 = &rdx->sub_1;
  rcx = r15 + rax * 24;
  sp_80 = r15;
  sp_48 = rsi->f_10;
  goto L_9e921;
L_9e914:
  r15 = (r15 + 24);
  if (r15 == rcx) goto L_9ebfc;
L_9e921:
  rax = (*(u64 *)(r15 + 16) + *(u64 *)(r15 + 8));
  if (rax < 0 || rax > sp_48) goto L_9e914;
  rdi = (*(u64 *)(r15 + 8) + sp_98);
  rax = bcmp(rdi, rdx, r9);
  return sp_90;
}`,
      layouts: {
        rsi: `layout of rsi in 0x9e840..0x9edf8:
  +8       size  8  u64   r:1  w:0 
  +10      size  8  u64   r:1  w:0 
  +20      size  8  u64   r:1  w:0   stride=0x8
  +28      size  8  u64   r:1  w:0 
4 fields (min span 0x30)
other pointer args: rdi (3 fields), rdx (2 fields)  (use --reg <REG>)`,
        rdi: `layout of rdi in 0x9e840..0x9edf8:
  +0       size  8  u64   r:0  w:1 
  +8       size  8  u64   r:0  w:1 
  +10      size  8  u64   r:0  w:1 
3 fields (min span 0x18)
other pointer args: rsi (4 fields), rdx (2 fields)  (use --reg <REG>)`,
        rdx: `layout of rdx in 0x9e840..0x9edf8:
  +0       size  1  u8    r:1  w:0 
  +1       size  0  &sub  r:0  w:0   lea:1
2 fields (min span 0x2)
other pointer args: rdi (3 fields), rsi (4 fields)  (use --reg <REG>)`,
      },
      asm: `function 0x9e840..0x9edf8
0x9e840  push rbp
0x9e841  push r15
0x9e843  push r14
0x9e845  push r13
0x9e847  push r12
0x9e849  push rbx
0x9e84a  sub rsp, 0xa8
0x9e851  mov [rsp+0x90], rdi
0x9e874  mov rax, [rsi+0x28]
0x9e878  test rax, rax
0x9e87b  je 0x9ec02
0x9e881  mov r9, rcx
0x9e884  sub r9, 1
0x9e888  jae short 0x9e898
0x9e898  mov r15, [rsi+0x20]
0x9e89c  lea rax, [rax+rax*2]`,
      calls: `callers of 0x9e840..0x9edf8:
  0xd580a  in 0xd1bd0  call 0x9e840
  0xd91ee  in 0xd1bd0  call 0x9e840
  0xeb975  in 0xeb890  call 0x9e840

calls in 0x9e840..0x9edf8:
  0x9e9ef  call bcmp via 0x1d8688
  0x9ea5c  call 0x12c260
  0x9ebe0  call 0x85d60`,
      elapsed_ms: '3.1 ms',
    },
    {
      addr: '0xcafb0',
      end: '0xcb20f',
      size: 607,
      label: 'loops::collect_targets (src/loops.rs:45)',
      pseudo_c: `function 0xcafb0..0xcb20f (rdi, rsi, rdx) {
  sp_20 = rdi;
  sp_0 = 0;
  sp_8 = 8;
  sp_10 = 0;
  if (rdx == 0) goto L_cb1ca;
  r14 = rsi;
  r15 = rsi + rdx * 24;
  sp_18 = 8;
  r13 = 0;
  r12 = &sp_40;
  goto L_cb03d;
L_cb030:
  r14 = (r14 + 24);
  if (r14 == r15) goto L_cb1ca;
L_cb03d:
  rbx = *(u64 *)(r14 + 8);
  rbp = *(u64 *)(r14 + 16);
  rax = fn_15a8f0(r12, rbx, rbp, "goto L_", 7);
  if (sp_28 == 0) goto L_cb030;
  if (rbp == rdx || *(u8 *)(rbx + rbp - 1) != 59) goto L_cb030;
  return sp_20;
}`,
      typed_c: `/* struct sugar: rdi: 3 fields */
function 0xcafb0..0xcb20f (rdi, rsi, rdx) {
  sp_20 = rdi;
  rdi->f_0 = 0;
  rdi->f_8 = 8;
  rdi->f_10 = 0;
  if (rdx == 0) goto L_cb1ca;
  r14 = rsi;
  r15 = rsi + rdx * 24;
  r12 = &sp_40;
  goto L_cb03d;
L_cb030:
  r14 = (r14 + 24);
  if (r14 == r15) goto L_cb1ca;
L_cb03d:
  rbx = *(u64 *)(r14 + 8);
  rbp = *(u64 *)(r14 + 16);
  rax = fn_15a8f0(r12, rbx, rbp, "goto L_", 7);
  if (sp_28 == 0) goto L_cb030;
  return sp_20;
}`,
      layouts: {
        rdi: `layout of rdi in 0xcafb0..0xcb20f:
  +0       size  8  u64   r:0  w:1 
  +8       size  8  u64   r:0  w:1 
  +10      size  8  u64   r:0  w:1 
3 fields (min span 0x18)
other pointer args: rsi (1 fields)  (use --reg <REG>)`,
        rsi: `layout of rsi in 0xcafb0..0xcb20f:
  +18      size  0  &sub  r:0  w:0   lea:1
1 fields (min span 0x19)
other pointer args: rdi (3 fields)  (use --reg <REG>)`,
        rdx: `layout of rdx in 0xcafb0..0xcb20f:
0 fields (min span 0x0)
other pointer args: rdi (3 fields), rsi (1 fields)  (use --reg <REG>)`,
      },
      asm: `function 0xcafb0..0xcb20f
0xcafb0  push rbp
0xcafba  sub rsp, 0xa8
0xcafc1  mov [rsp+0x20], rdi
0xcafe0  test rdx, rdx
0xcafe3  je 0xcb1ca
0xcafe9  mov r14, rsi
0xcafec  lea rax, [rdx+rdx*2]
0xcaff0  lea r15, [rsi+rax*8]
0xcb030  add r14, 0x18
0xcb034  cmp r14, r15
0xcb037  je 0xcb1ca
0xcb03d  mov rbx, [r14+8]
0xcb041  mov rbp, [r14+0x10]
0xcb045  mov r8d, 7
0xcb054  lea rcx, [0x14d5f]  ; "goto L_"
0xcb05b  call 0x15a8f0`,
      calls: `callers of 0xcafb0..0xcb20f:
  0xb3317  in 0xb3180  call 0xcafb0
  0xb9155  in 0xb90a0  call 0xcafb0
  0xbda76  in 0xb9ba0  call 0xcafb0

calls in 0xcafb0..0xcb20f:
  0xcb05b  call 0x15a8f0
  0xcb068  call 0x11f0f0
  0xcb1b6  call 0xa5700`,
      elapsed_ms: '2.6 ms',
    },
    {
      addr: '0xa1b50',
      end: '0xa1e46',
      size: 758,
      label: 'image::Image::string_at (src/image.rs:184)',
      pseudo_c: `function 0xa1b50..0xa1e46 (rdi, rsi, rdx) {
  rax = rsi;
  if (*(u64 *)(rsi + 40) == 0) {
    *(u64 *)(rdi) = -1;
    return rax;
  }
  r8 = *(u64 *)(rsi + 40) * 24;
  rsi = rdx + 64;
  r10 = r8;
  r9 = *(u64 *)(rax + 32);
  goto L_a1b9a;
L_a1b90:
  r9 = (r9 + 24);
  r10 = (r10 - 24);
  if ((r10 - 24) == 0) goto L_a1bd7;
L_a1b9a:
  rbx = *(u64 *)(r9);
  r11 = (rdx - rbx);
  if ((rdx - rbx) < 0) goto L_a1b90;
  if ((rsi - rbx) > *(u64 *)(r9 + 16)) goto L_a1b90;
  rsi = (*(u64 *)(r9 + 8) + r11 + *(u64 *)(rax + 8));
  return rax;
}`,
      typed_c: `/* struct sugar: rdi: 3 fields, rsi: 5 fields */
function 0xa1b50..0xa1e46 (rdi, rsi, rdx) {
  rax = rsi;
  if (rsi->f_28 == 0) {
    rdi->f_0 = -1;
    return rax;
  }
  r8 = rsi->f_28 * 24;
  rsi = rdx + 64;
  r10 = r8;
  r9 = rsi->f_20;
  goto L_a1b9a;
L_a1b90:
  r9 = (r9 + 24);
  r10 = (r10 - 24);
  if ((r10 - 24) == 0) goto L_a1bd7;
L_a1b9a:
  rbx = *(u64 *)(r9);
  r11 = (rdx - rbx);
  if ((rdx - rbx) < 0) goto L_a1b90;
  if ((rsi - rbx) > *(u64 *)(r9 + 16)) goto L_a1b90;
  rsi = (*(u64 *)(r9 + 8) + r11 + rsi->f_8);
  return rax;
}`,
      layouts: {
        rsi: `layout of rsi in 0xa1b50..0xa1e46:
  +0       size  4  u32   r:0  w:2 
  +8       size  8  u64   r:2  w:0 
  +10      size  8  u64   r:2  w:0 
  +20      size  8  u64   r:1  w:0 
  +28      size  8  u64   r:1  w:0 
5 fields (min span 0x30)
other pointer args: rdi (3 fields), rdx (1 fields)  (use --reg <REG>)`,
        rdi: `layout of rdi in 0xa1b50..0xa1e46 (+1 callees):
  forwarded: rdi -> 0x120ca0(rcx)
  +0       size  8  u64   r:0  w:1 
  +8       size  8  u64   r:0  w:1 
  +10      size  8  u64   r:0  w:1 
3 fields (min span 0x18)
other pointer args: rsi (5 fields), rdx (1 fields)  (use --reg <REG>)`,
        rdx: `layout of rdx in 0xa1b50..0xa1e46:
  +40      size  0  &sub  r:0  w:0   lea:1
1 fields (min span 0x41)
other pointer args: rdi (3 fields), rsi (5 fields)  (use --reg <REG>)`,
      },
      asm: `function 0xa1b50..0xa1e46
0xa1b50  push r15
0xa1b57  sub rsp, 0x18
0xa1b5b  mov rax, rsi
0xa1b5e  mov rsi, [rsi+0x28]
0xa1b62  test rsi, rsi
0xa1b65  je 0xa1db9
0xa1b6b  mov rcx, [rax+0x20]
0xa1b6f  shl rsi, 3
0xa1b73  lea r8, [rsi+rsi*2]
0xa1b90  add r9, 0x18
0xa1b9a  mov rbx, [r9]`,
      calls: `callers of 0xa1b50..0xa1e46:
  0x90406  in 0x8f990  call 0xa1b50
  0xc22b1  in 0xc2120  call 0xa1b50
  0xc388a  in 0xc3170  call 0xa1b50

calls in 0xa1b50..0xa1e46:
  0xa1ce6  call 0x120ca0
  0xa1d80  call 0x120810
  0xa1d9a  call memcpy via 0x1d8678`,
      elapsed_ms: '3.4 ms',
    },
    {
      addr: '0x15a8f0',
      end: '0x15ae4c',
      size: 1372,
      label: 'core::str::pattern::StrSearcher::new (core/src/str/pattern.rs)',
      pseudo_c: `function 0x15a8f0..0x15ae4c (rdi, rsi, rdx, rcx, r8) {
  r12 = rcx;
  r10 = rdi;
  if (r8 == 0) {
    *(u64 *)(r10 + 72) = rsi;
    *(u64 *)(r10 + 80) = rdx;
    *(u64 *)(r10 + 88) = r12;
    *(u64 *)(r10 + 96) = 0;
    *(u128 *)(r10) = 0;
    *(u64 *)(r10 + 16) = rdx;
    *(u16 *)(r10 + 24) = 257;
    return r10;
  }
  rbx = r8;
  return r10;
}`,
      typed_c: `/* struct sugar: rdi: 8 fields */
function 0x15a8f0..0x15ae4c (rdi, rsi, rdx, rcx, r8) {
  r12 = rcx;
  if (r8 == 0) {
    rdi->f_48 = rsi;
    rdi->f_50 = rdx;
    rdi->f_58 = r12;
    rdi->f_60 = 0;
    rdi->f_0 = 0;
    rdi->f_10 = rdx;
    rdi->f_18 = 257;
    return rdi;
  }
  rbx = r8;
  return rdi;
}`,
      layouts: {
        rdi: `layout of rdi in 0x15a8f0..0x15ae4c:
  +0       size 16  u128  r:0  w:1 
  +10      size  8  u64   r:0  w:1 
  +18      size  2  u16   r:0  w:1 
  +48      size  8  u64   r:0  w:1 
  +50      size  8  u64   r:0  w:1 
  +58      size  8  u64   r:0  w:1 
  +60      size  8  u64   r:0  w:1 
8 fields (min span 0x68)`,
        rsi: `layout of rsi in 0x15a8f0..0x15ae4c:
0 fields (min span 0x0)
other pointer args: rdi (8 fields)  (use --reg <REG>)`,
        rdx: `layout of rdx in 0x15a8f0..0x15ae4c:
0 fields (min span 0x0)
other pointer args: rdi (8 fields)  (use --reg <REG>)`,
      },
      asm: `function 0x15a8f0..0x15ae4c
0x15a8f0  push rbp
0x15a8f1  mov rbp, rsp
0x15a8fd  sub rsp, 0x18
0x15a901  mov r12, rcx
0x15a904  mov r10, rdi
0x15a907  test r8, r8
0x15a90a  je short 0x15a92e
0x15a90c  mov rbx, r8
0x15a90f  cmp r8, 1`,
      calls: `callers of 0x15a8f0..0x15ae4c:
  0xcb05b  in 0xcafb0  call 0x15a8f0

calls in 0x15a8f0..0x15ae4c:
  (leaf two-way substring initializer)`,
      elapsed_ms: '3.3 ms',
    },
  ];

  const PRESET_QUERIES = {
    refs: {
      input: '"goto L_"',
      latency: '13.3 ms',
      output: `$ xref -b target/release/xref refs "goto L_"
text 0x11ccd  "goto L_"
text 0x14d5f  "goto L_"
0xb55d7  in 0xb3180  lea rsi, [0x11ccc]
0xb5e59  in 0xb3180  lea rsi, [0x11ccc]
0xb6454  in 0xb3180  lea rsi, [0x11ccc]
0xbd7e7  in 0xb9ba0  lea rsi, [0x11ccc]
0xcb054  in 0xcafb0  lea rcx, [0x14d5f]
0xcf94f  in 0xcf920  lea rsi, [0x11ccc]
6 hits`,
    },
    disp: {
      input: '0x20 --lea',
      latency: '7.6 ms',
      output: `$ xref -b target/release/xref disp 0x20 --lea
0x64d85  in 0x64a40  lea r8, [rbp+0x20]
0x65433  in 0x65160  lea rdx, [r13+0x20]
0x6f433  in 0x6f330  lea rbx, [rdi+rbp*8+0x20]
0x7076b  in 0x70750  lea rax, [rdi+0x20]
0x9e898  in 0x9e840  mov r15, [rsi+0x20]
0xa1b6b  in 0xa1b50  mov rcx, [rax+0x20]
6 hits`,
    },
    imm: {
      input: '24 --in 0xa1b50',
      latency: '6.9 ms',
      output: `$ xref -b target/release/xref imm 24 --in 0xa1b50
0xa1b57  in 0xa1b50  sub rsp, 0x18
0xa1b90  in 0xa1b50  add r9, 0x18
0xa1be0  in 0xa1b50  add rcx, 0x18
0xa1dc0  in 0xa1b50  add rsp, 0x18
4 hits`,
    },
    where: {
      input: 'src/loops.rs',
      latency: '3.7 ms',
      output: `$ xref -b target/release/xref where src/loops.rs
0xb3180..0xb909c  src/loops.rs:33  src/loops.rs:65  src/loops.rs:107  src/loops.rs:146
0xcafb0..0xcb20f  src/loops.rs:45
18 locations, 18 references`,
    },
    slice: {
      input: '0xcafb0 --to fn_15a8f0',
      latency: '6.1 ms',
      output: `$ xref -b target/release/xref slice 0xcafb0 --to fn_15a8f0 --fields
/* slice of 0xcafb0..0xcb20f -> fn_15a8f0 (12/88 lines) */
/* struct sugar: rdi: 3 fields */
function 0xcafb0..0xcb20f (rdi, rsi, rdx) {
  if (rdx == 0) goto L_cb1ca;
  r14 = rsi;
  r15 = rsi + rdx * 24;
  r12 = &sp_40;
  r14 = (r14 + 24);
  if (r14 == r15) goto L_cb1ca;
  rbx = *(u64 *)(r14 + 8);
  rbp = *(u64 *)(r14 + 16);
  rax = fn_15a8f0(r12, rbx, rbp, "goto L_", 7);
}`,
    },
  };

  const state = {
    functions: SELF_FUNCTIONS,
    currentAddr: SELF_FUNCTIONS[0].addr,
    currentData: SELF_FUNCTIONS[0],
    searchOutput: PRESET_QUERIES.refs.output,
    activeTab: 'pseudo_c',
    history: [],
  };

  const els = {
    fnList: document.getElementById('fn-list'),
    fnFilter: document.getElementById('fn-filter'),
    codeView: document.getElementById('code-view'),
    latency: document.getElementById('latency-badge'),
    backBtn: document.getElementById('back-btn'),
    regWrap: document.getElementById('reg-wrap'),
    regSelect: document.getElementById('layout-reg'),
    queryForm: document.getElementById('query-form'),
    queryMode: document.getElementById('query-mode'),
    queryInput: document.getElementById('query-input'),
  };

  function escapeHtml(text) {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  const TOKEN_RE =
    /(\/\*[\s\S]*?\*\/)|("(?:\\.|[^"\\])*")|\b(fn_([0-9a-fA-F]+))\b|\b(0x[0-9a-fA-F]{4,16})\b|\b(rust_[a-z_]+|saturating_add|unreachable|(?:add_|sub_|mul_|neg_)?overflow|isnan|bcmp|memcpy)\b|\b(function|if|else|while|do|switch|case|return|break|continue|goto)\b/g;

  function highlightAndLink(raw) {
    let out = '';
    let last = 0;
    for (const m of raw.matchAll(TOKEN_RE)) {
      out += escapeHtml(raw.slice(last, m.index));
      const [full, cmt, str, fnSym, fnHex, addrHex, rtKw, kw] = m;
      const esc = escapeHtml(full);
      if (cmt) out += `<span class="tok-cmt">${esc}</span>`;
      else if (str) out += `<span class="tok-str">${esc}</span>`;
      else if (fnSym) out += `<a class="code-link" data-addr="0x${fnHex}">${esc}</a>`;
      else if (addrHex) out += `<a class="code-link" data-addr="${esc}">${esc}</a>`;
      else if (rtKw) out += `<span class="tok-rt">${esc}</span>`;
      else if (kw) out += `<span class="tok-kw">${esc}</span>`;
      last = m.index + full.length;
    }
    out += escapeHtml(raw.slice(last));
    return out;
  }

  function renderFnList() {
    const q = els.fnFilter.value.trim().toLowerCase();
    const filtered = state.functions.filter(
      (f) => !q || f.addr.toLowerCase().includes(q) || (f.label && f.label.toLowerCase().includes(q))
    );
    els.fnList.innerHTML = filtered
      .map(
        (f) => `<li class="fn-item ${f.addr === state.currentAddr ? 'active' : ''}" data-addr="${escapeHtml(f.addr)}">
          <div class="fn-addr"><span>${escapeHtml(f.addr)}..${escapeHtml(f.end)}</span><span class="fn-size">${f.size} B</span></div>
          <div class="fn-label">${escapeHtml(f.label)}</div>
        </li>`
      )
      .join('');
  }

  function currentLayoutText(d) {
    if (!d || !d.layouts) return 'No layout data.';
    const reg = (els.regSelect && els.regSelect.value) || 'rsi';
    return d.layouts[reg] || d.layouts.rsi || d.layouts.rdi || 'No layout data.';
  }

  function renderMain() {
    els.regWrap.style.display = state.activeTab === 'layout' ? 'inline-flex' : 'none';
    els.backBtn.disabled = state.history.length === 0;
    document.querySelectorAll('.wb-tab').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.tab === state.activeTab);
    });
    const d = state.currentData;
    let raw = 'No output for this view.';
    if (state.activeTab === 'search') {
      raw = state.searchOutput;
    } else if (state.activeTab === 'layout') {
      raw = currentLayoutText(d);
    } else if (d) {
      raw = d[state.activeTab] || '';
    }
    els.codeView.innerHTML = highlightAndLink(raw);
    if (d && d.elapsed_ms && state.activeTab !== 'search') {
      els.latency.textContent = d.elapsed_ms;
    }
  }

  function selectFunction(addr, pushHistory = true) {
    const hit = state.functions.find((f) => f.addr.toLowerCase() === addr.toLowerCase());
    if (!hit) return;
    if (pushHistory && state.currentAddr && state.currentAddr !== hit.addr) {
      state.history.push(state.currentAddr);
    }
    state.currentAddr = hit.addr;
    state.currentData = hit;
    if (state.activeTab === 'search') state.activeTab = 'pseudo_c';
    renderFnList();
    renderMain();
  }

  function applyQueryMode(mode) {
    const preset = PRESET_QUERIES[mode] || PRESET_QUERIES.refs;
    els.queryInput.value = preset.input;
    state.searchOutput = preset.output;
    els.latency.textContent = preset.latency;
    state.activeTab = 'search';
    renderMain();
  }

  function runQuery(mode, q) {
    const preset = PRESET_QUERIES[mode];
    if (preset && (!q || q.toLowerCase() === preset.input.toLowerCase())) {
      applyQueryMode(mode);
      return;
    }
    const needle = q.replace(/^"|"$/g, '').toLowerCase();
    const hits = [];
    for (const fn of state.functions) {
      const hay = `${fn.label}\n${fn.pseudo_c}\n${fn.typed_c}\n${fn.asm}\n${fn.calls}`;
      for (const line of hay.split('\n')) {
        if (line.toLowerCase().includes(needle)) {
          hits.push(`in ${fn.addr} (${fn.label})  ${line.trim()}`);
        }
      }
    }
    state.searchOutput =
      hits.length > 0
        ? `$ xref -b target/release/xref ${mode} ${q}\n${hits.slice(0, 18).join('\n')}\n${hits.length} hits`
        : `$ xref -b target/release/xref ${mode} ${q}\n0 hits in embedded self-demo (4 showcased functions; run CLI on full binary for all 1,969 functions)`;
    els.latency.textContent = '1.4 ms';
    state.activeTab = 'search';
    renderMain();
  }

  els.fnList.addEventListener('click', (e) => {
    const item = e.target.closest('.fn-item');
    if (item && item.dataset.addr) {
      selectFunction(item.dataset.addr, true);
    }
  });

  els.codeView.addEventListener('click', (e) => {
    const link = e.target.closest('.code-link');
    if (link && link.dataset.addr) {
      e.preventDefault();
      selectFunction(link.dataset.addr, true);
    }
  });

  document.querySelectorAll('.wb-tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.activeTab = btn.dataset.tab;
      renderMain();
    });
  });

  els.backBtn.addEventListener('click', () => {
    const prev = state.history.pop();
    if (prev) selectFunction(prev, false);
  });

  els.regSelect.addEventListener('change', () => {
    renderMain();
  });

  els.fnFilter.addEventListener('input', () => {
    renderFnList();
  });

  els.queryMode.addEventListener('change', () => {
    applyQueryMode(els.queryMode.value);
  });

  els.queryForm.addEventListener('submit', (e) => {
    e.preventDefault();
    runQuery(els.queryMode.value, els.queryInput.value.trim());
  });

  renderFnList();
  renderMain();
})();
