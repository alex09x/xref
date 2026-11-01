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
  const DEMO_FUNCTIONS = [
    {
      addr: '0x24100',
      end: '0x24310',
      size: 528,
      label: 'engine::transfer::apply_delta (src/engine/transfer.rs:84)',
      pseudo_c: `function 0x24100..0x24310 (rdi, rsi, rdx, rcx, r8, r9, arg7) {
  r13 = rdi;
  r12 = rsi;
  *(u64 *)(rdi + 0xab0) = saturating_add(*(u64 *)(rdi + 0xab0), 1);
  if (arg7 >= *(u64 *)(r13 + 0x7d0)) {
    sp_20 = 342;
    rax = rust_unwrap_failed("called \`Result::unwrap()\` on an \`Err\` value", 43, &sp_20, fn_3e1f0, "src/engine/registry.rs:11:29");
    unreachable();
  }
  rbp = memcmp;
  while (1) {
    r14 = -1;
    rsi = rcx + 0x7f0;
    do {
      rax = memcmp(&sp_20, rsi, 20);
      r14 = (r14 + 1);
      rsi = rsi + 20;
    } while ((i64)rax > 0);
    if (r13 < 0) break;
    rcx = *(u64 *)(rcx + r14 * 8 + 0x8d0);
  }
  rax = fn_24500(r13 + 0x9f8, r12, rdx);
  return (rax, r12);
}`,
      layout: `layout of rdi in 0x24100..0x24310 (+3 callees):
  +58      size  8  u64   r:2  w:2   lea:1  -> 0x24500
  +60      size  8  u64   r:2  w:0   stride=0x8
  +68      size  8  u64   r:2  w:1 
  +7c8     size  8  u64   r:4  w:0   stride=0x510
  +7d0     size  8  u64   r:4  w:0 
  +9f8     size  0  &sub  r:0  w:0   lea:2  -> 0x24500
  +ab0     size  8  u64   r:1  w:1 
7 fields (min span 0xab8)`,
      asm: `function 0x24100..0x24310 (0x210 bytes)
  0x24100  push rbp
  0x24101  push r15
  0x24103  push r14
  0x24105  push r13
  0x24107  mov r13, rdi
  0x2410a  add qword ptr [rdi+0xab0], 1
  0x24112  mov rax, -1
  0x24119  cmovae rax, [rdi+0xab0]
  0x24121  lea rdi, [r13+0x9f8]
  0x24128  call 0x24500  ; -> fn_24500`,
      calls: `callers of 0x24100..0x24310:
  0x21840  in 0x21700  call 0x24100

calls in 0x24100..0x24310:
  0x24184  call 0x62480  ; rust_unwrap_failed
  0x24210  call rbp      ; memcmp
  0x242f4  call 0x24500  ; fn_24500`,
      elapsed_ms: '0.41 ms',
    },
    {
      addr: '0x24500',
      end: '0x24620',
      size: 288,
      label: 'collections::slot_vec::push_entry (src/collections/slot.rs:42)',
      pseudo_c: `function 0x24500..0x24620 (rdi, rsi, rdx) {
  rax = *(u64 *)(rdi + 8);
  if (rax == *(u64 *)(rdi)) {
    rax = fn_62100(rdi, 1);
  }
  rcx = *(u64 *)(rdi + 16);
  *(u64 *)(rcx + rax * 8) = rsi;
  *(u64 *)(rdi + 8) = (rax + 1);
  return (rax + 1);
}`,
      layout: `layout of rdi in 0x24500..0x24620:
  +0       size  8  u64   r:1  w:0 
  +8       size  8  u64   r:1  w:1 
  +10      size  8  u64   r:1  w:0   stride=0x8
3 fields (min span 0x18)`,
      asm: `function 0x24500..0x24620 (0x120 bytes)
  0x24500  mov rax, [rdi+8]
  0x24504  cmp rax, [rdi]
  0x24507  je 0x24520
  0x24509  mov rcx, [rdi+0x10]
  0x2450d  mov [rcx+rax*8], rsi
  0x24511  inc rax
  0x24514  mov [rdi+8], rax
  0x24518  ret`,
      calls: `callers of 0x24500..0x24620:
  0x242f4  in 0x24100  call 0x24500

calls in 0x24500..0x24620:
  0x24524  call 0x62100  ; reserve_for_push`,
      elapsed_ms: '0.14 ms',
    },
    {
      addr: '0x62400',
      end: '0x624a5',
      size: 165,
      label: '/* rust_dealloc */ tcache_fast_free',
      pseudo_c: `/* rust_dealloc */ function 0x62400..0x624a5 (rdi, rsi, rdx) {
  if (((rsi <= 0x1000 && rdx == 0) && (rdi & 0xfff) != 0) && *(u64 *)(fs:-0xd60) < *(u64 *)(fs:-0xd58)) {
    r9 = *(u64 *)(*(u64 *)(fs:0) + ((u8 *)0x660d780)[(rsi + 7 >> 3)] * 24 - 0xd40);
    *(u64 *)(r9 - 8) = rdi;
    return *(u64 *)(fs:0);
  }
  return fn_62300(rdi, rsi, rdx);
}`,
      layout: `layout of rdi in 0x62400..0x624a5:
0 fields (min span 0x0)`,
      asm: `function 0x62400..0x624a5 (0xa5 bytes)
  0x62400  cmp rsi, 0x1000
  0x62407  ja 0x62498
  0x6240d  test rdx, rdx
  0x62410  jne 0x62498
  0x62416  mov rax, fs:[0]
  0x62498  jmp 0x62300`,
      calls: `callers of 0x62400..0x624a5:
  1842 direct call sites

calls in 0x62400..0x624a5:
  0x62498  jmp 0x62300  ; tail`,
      elapsed_ms: '0.09 ms',
    },
  ];

  const state = {
    live: false,
    functions: DEMO_FUNCTIONS,
    currentAddr: DEMO_FUNCTIONS[0].addr,
    currentData: DEMO_FUNCTIONS[0],
    searchOutput: 'Run any refs / disp --lea / imm / where query in the bar above.',
    activeTab: 'pseudo_c',
    history: [],
  };

  const els = {
    pill: document.getElementById('engine-pill'),
    meta: document.getElementById('binary-meta'),
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
    mLoad: document.getElementById('m-load'),
    mLoadLbl: document.getElementById('m-load-lbl'),
    mFns: document.getElementById('m-fns'),
    mFnsLbl: document.getElementById('m-fns-lbl'),
  };

  function escapeHtml(text) {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  const TOKEN_RE =
    /(\/\*[\s\S]*?\*\/)|("(?:\\.|[^"\\])*")|\b(fn_([0-9a-fA-F]+))\b|\b(0x[0-9a-fA-F]{4,16})\b|\b(rust_[a-z_]+|saturating_add|unreachable|overflow|isnan)\b|\b(function|if|else|while|do|switch|case|return|break|continue|goto)\b/g;

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
          <div class="fn-label">${escapeHtml(f.label || 'anonymous function')}</div>
        </li>`
      )
      .join('');
  }

  function renderMain() {
    els.regWrap.style.display = state.activeTab === 'layout' ? 'inline-flex' : 'none';
    els.backBtn.disabled = state.history.length === 0;
    document.querySelectorAll('.wb-tab').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.tab === state.activeTab);
    });
    const d = state.currentData;
    const raw =
      state.activeTab === 'search'
        ? state.searchOutput
        : (d && d[state.activeTab]) || 'No output for this view.';
    els.codeView.innerHTML = highlightAndLink(raw);
    if (d && d.elapsed_ms && state.activeTab !== 'search') {
      els.latency.textContent = d.elapsed_ms;
    }
  }

  async function selectFunction(addr, pushHistory = true) {
    if (pushHistory && state.currentAddr && state.currentAddr !== addr) {
      state.history.push(state.currentAddr);
    }
    state.currentAddr = addr;
    if (!state.live) {
      const hit = state.functions.find((f) => f.addr.toLowerCase() === addr.toLowerCase());
      if (hit) {
        state.currentData = hit;
        if (state.activeTab === 'search') state.activeTab = 'pseudo_c';
      }
      renderFnList();
      renderMain();
      return;
    }
    try {
      const reg = encodeURIComponent(els.regSelect.value || 'rdi');
      const res = await fetch(`/api/inspect?addr=${encodeURIComponent(addr)}&reg=${reg}`);
      if (!res.ok) return;
      const data = await res.json();
      state.currentAddr = data.addr;
      state.currentData = data;
      if (state.activeTab === 'search') state.activeTab = 'pseudo_c';
      renderFnList();
      renderMain();
    } catch (_) {}
  }

  async function loadLiveFunctions(q = '') {
    if (!state.live) {
      renderFnList();
      return;
    }
    try {
      const res = await fetch(`/api/functions?q=${encodeURIComponent(q)}`);
      if (!res.ok) return;
      const data = await res.json();
      state.functions = data.functions || [];
      renderFnList();
    } catch (_) {}
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
    if (state.live && state.currentAddr) {
      selectFunction(state.currentAddr, false);
    }
  });

  let filterTimer = null;
  els.fnFilter.addEventListener('input', () => {
    if (!state.live) {
      renderFnList();
      return;
    }
    clearTimeout(filterTimer);
    filterTimer = setTimeout(() => loadLiveFunctions(els.fnFilter.value.trim()), 90);
  });

  els.queryForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const mode = els.queryMode.value;
    const q = els.queryInput.value.trim();
    if (!q) return;
    if (!state.live) {
      state.searchOutput = `[showcase mode] Launch 'xref -b <ELF> web' locally to run live '${mode}' scans across your binary.\n\nExample output for '${mode} ${q}':\n0x24121  in 0x24100  lea rdi, [r13+0x9f8]  ; -> 0x24500\n1 hits`;
      state.activeTab = 'search';
      renderMain();
      return;
    }
    const res = await fetch(`/api/search?mode=${encodeURIComponent(mode)}&q=${encodeURIComponent(q)}`);
    if (!res.ok) return;
    const data = await res.json();
    state.searchOutput = data.output || '0 hits';
    els.latency.textContent = data.elapsed_ms || '0.1 ms';
    state.activeTab = 'search';
    renderMain();
  });

  async function boot() {
    renderFnList();
    renderMain();
    try {
      const res = await fetch('/api/stats');
      if (!res.ok) return;
      const stats = await res.json();
      state.live = true;
      els.pill.className = 'pill pill-live';
      els.pill.textContent = '● LIVE IN-MEMORY ENGINE';
      els.meta.textContent = `${stats.binary} · ${stats.functions.toLocaleString()} functions · ${stats.locations.toLocaleString()} panic locs · loaded in ${stats.load_ms}`;
      els.mLoad.textContent = stats.load_ms;
      els.mLoadLbl.textContent = `Cold load · ${stats.binary}`;
      els.mFns.textContent = stats.functions.toLocaleString();
      els.mFnsLbl.textContent = `${(stats.code_bytes / (1024 * 1024)).toFixed(2)} MB .text · ${stats.files} source files`;
      state.functions = stats.initial_functions || [];
      renderFnList();
      if (state.functions.length > 0) {
        await selectFunction(state.functions[0].addr, false);
      }
    } catch (_) {
      // Static showcase mode on xrefcode.com
    }
  }

  boot();
})();
