/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

(function () {
  'use strict';

  var DATA = window.XREF_RECORDED;
  if (!DATA) return;

  var ART = DATA.artifacts;
  var GROUPS = DATA.scenarioGroups;
  var FNS = DATA.functions;
  var FN_BY_ID = {};
  FNS.forEach(function (fn) { FN_BY_ID[fn.id] = fn; });

  var ALL_SCENARIOS = [];
  GROUPS.forEach(function (g) {
    g.items.forEach(function (it) { ALL_SCENARIOS.push({ group: g.group, item: it }); });
  });

  var state = {
    scId: ALL_SCENARIOS[0].item.id,
    scVarIdx: 0,
    scFilter: '',
    fnId: FNS[0].id,
    fnView: 'pseudo_c',
    fnVarIdx: 0,
    fnFilter: '',
    fnHistory: []
  };

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function formatBinaryBadge(binaryKey) {
    var p = ART.primary;
    if (binaryKey === 'pair') {
      var o = ART.other;
      return 'Inputs: ' + p.name + ' (' + p.commit + ' · sha256:' + p.sha256.slice(0, 8) + '…) + ' +
        o.name + ' (' + o.commit + ' · sha256:' + o.sha256.slice(0, 8) + '…)';
    }
    return 'Input: ' + p.name + ' (' + p.commit + ' · ' + p.sizeHuman + ' · sha256:' + p.sha256.slice(0, 8) + '…)';
  }

  function formatMeta(variant) {
    var parts = [variant.lines + (variant.lines === 1 ? ' line' : ' lines')];
    if (variant.stderr) parts.push('recorded stderr: ' + variant.stderr);
    return parts.join(' · ');
  }

  function renderJumpBar(container, text, excludeId, scrollToWorkbench) {
    container.textContent = '';
    var hits = FNS.filter(function (fn) {
      if (fn.id === excludeId) return false;
      return text.indexOf(fn.id) !== -1 || text.indexOf('fn_' + fn.id.slice(2)) !== -1;
    });
    container.hidden = hits.length === 0;
    if (!hits.length) return;
    container.appendChild(el('span', '', 'Inspect referenced function:'));
    hits.forEach(function (fn) {
      var btn = el('button', 'jump-chip', fn.id + ' (' + fn.panicHint + ')');
      btn.type = 'button';
      btn.addEventListener('click', function () {
        selectFunction(fn.id, true);
        if (scrollToWorkbench && $('workbench')) {
          $('workbench').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      });
      container.appendChild(btn);
    });
  }

  function bindCopy(btn, getText) {
    btn.addEventListener('click', function () {
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(getText()).then(function () {
        var prev = btn.textContent;
        btn.textContent = 'Copied';
        setTimeout(function () { btn.textContent = prev; }, 1200);
      });
    });
  }

  function makeSideItem(active, leftText, rightText, subText, onClick) {
    var btn = el('button', 'fn-item' + (active ? ' active' : ''));
    btn.type = 'button';
    var top = el('div', 'fn-addr');
    top.appendChild(el('span', '', leftText));
    top.appendChild(el('span', 'fn-size', rightText));
    btn.appendChild(top);
    btn.appendChild(el('div', 'fn-label', subText));
    btn.addEventListener('click', onClick);
    return btn;
  }

  /* 1. Scenario Explorer */
  function currentScenario() {
    for (var i = 0; i < ALL_SCENARIOS.length; i++) {
      if (ALL_SCENARIOS[i].item.id === state.scId) return ALL_SCENARIOS[i].item;
    }
    return ALL_SCENARIOS[0].item;
  }

  function renderScenarioSidebar() {
    var host = $('sc-list');
    host.textContent = '';
    var q = state.scFilter.trim().toLowerCase();
    var any = false;

    GROUPS.forEach(function (g) {
      var matching = g.items.filter(function (it) {
        if (!q) return true;
        var hay = (g.group + ' ' + it.title + ' ' + it.badge + ' ' + it.summary + ' ' +
          it.variants.map(function (v) { return v.label + ' ' + v.cmd; }).join(' ')).toLowerCase();
        return hay.indexOf(q) !== -1;
      });
      if (!matching.length) return;
      any = true;
      host.appendChild(el('div', 'side-group-lbl', g.group));
      matching.forEach(function (it) {
        var cnt = it.variants.length + (it.variants.length === 1 ? ' run' : ' runs');
        host.appendChild(makeSideItem(it.id === state.scId, it.badge, cnt, it.title, function () {
          state.scId = it.id;
          state.scVarIdx = 0;
          renderScenarioSidebar();
          renderScenarioViewer();
        }));
      });
    });

    if (!any) host.appendChild(el('div', 'side-group-lbl', 'No matching scenarios'));
  }

  function renderScenarioViewer() {
    var sc = currentScenario();
    var idx = Math.min(state.scVarIdx, sc.variants.length - 1);
    var v = sc.variants[idx];

    $('sc-title').textContent = sc.title;
    $('sc-summary').textContent = sc.summary;
    $('sc-bin').textContent = formatBinaryBadge(v.binary);
    $('sc-note').textContent = v.note;
    $('sc-cmd').textContent = v.cmd;
    $('sc-meta').textContent = formatMeta(v);
    $('sc-out').textContent = v.stdout;

    var pills = $('sc-variants');
    pills.textContent = '';
    sc.variants.forEach(function (cand, i) {
      var p = el('button', 'variant-pill' + (i === idx ? ' active' : ''), cand.label);
      p.type = 'button';
      p.addEventListener('click', function () {
        state.scVarIdx = i;
        renderScenarioViewer();
      });
      pills.appendChild(p);
    });

    var fw = $('sc-file-wrap');
    fw.hidden = !v.filePreview;
    if (v.filePreview) {
      $('sc-file-title').textContent = 'GENERATED FILE PREVIEW (NOT STDOUT) · ' +
        v.filePreview.path + ' (' + v.filePreview.shownLines + ')';
      $('sc-file-out').textContent = v.filePreview.content;
    } else {
      $('sc-file-out').textContent = '';
    }
    renderJumpBar($('sc-jumps'), v.stdout, null, true);
  }

  /* 2. Multi-Function Inspector */
  function selectFunction(fnId, pushHistory) {
    if (!FN_BY_ID[fnId]) return;
    if (pushHistory && fnId !== state.fnId) state.fnHistory.push(state.fnId);
    state.fnId = fnId;
    state.fnVarIdx = 0;
    var fn = FN_BY_ID[fnId];
    if (!fn.views[state.fnView] || !fn.views[state.fnView].length) state.fnView = 'pseudo_c';
    $('fn-back').disabled = state.fnHistory.length === 0;
    renderFunctionSidebar();
    renderFunctionViewer();
  }

  function renderFunctionSidebar() {
    var host = $('fn-list');
    host.textContent = '';
    var q = state.fnFilter.trim().toLowerCase();
    var matching = FNS.filter(function (fn) {
      if (!q) return true;
      return (fn.id + ' ' + fn.range + ' ' + fn.panicHint + ' ' + fn.roleHint).toLowerCase().indexOf(q) !== -1;
    });
    if (!matching.length) {
      host.appendChild(el('div', 'side-group-lbl', 'No matching functions'));
      return;
    }
    matching.forEach(function (fn) {
      host.appendChild(makeSideItem(
        fn.id === state.fnId,
        fn.range,
        fn.sizeBytes + ' B',
        fn.panicHint + ' · ' + fn.roleHint,
        function () { selectFunction(fn.id, true); }
      ));
    });
  }

  function renderFunctionViewer() {
    var fn = FN_BY_ID[state.fnId] || FNS[0];
    $('fn-heading').textContent = fn.range + '  (' + fn.sizeBytes + ' bytes)';
    $('fn-annot').textContent = 'Annotation (via panic Location ' + fn.panicHint + '): ' + fn.roleHint;

    document.querySelectorAll('.fn-tab').forEach(function (btn) {
      var viewKey = btn.getAttribute('data-view');
      var avail = fn.views[viewKey] && fn.views[viewKey].length > 0;
      btn.disabled = !avail;
      btn.title = avail ? '' : 'No distinct pointer/field layout recorded for this function';
      btn.classList.toggle('active', viewKey === state.fnView);
    });

    var variants = fn.views[state.fnView] || fn.views.pseudo_c;
    var idx = Math.min(state.fnVarIdx, variants.length - 1);
    var v = variants[idx];

    var vBar = $('fn-variant-bar');
    var pills = $('fn-variants');
    pills.textContent = '';
    vBar.hidden = variants.length <= 1;
    variants.forEach(function (cand, i) {
      var p = el('button', 'variant-pill' + (i === idx ? ' active' : ''), cand.label);
      p.type = 'button';
      p.addEventListener('click', function () {
        state.fnVarIdx = i;
        renderFunctionViewer();
      });
      pills.appendChild(p);
    });

    $('fn-heuristic').hidden = !(
      state.fnView === 'pseudo_c' || state.fnView === 'fields_c' || state.fnView === 'slice'
    );
    $('fn-bin').textContent = formatBinaryBadge(v.binary);
    $('fn-cmd').textContent = v.cmd;
    $('fn-meta').textContent = formatMeta(v);
    $('fn-out').textContent = v.stdout;
    renderJumpBar($('fn-jumps'), v.stdout, fn.id, false);
  }

  $('sc-filter').addEventListener('input', function (e) { state.scFilter = e.target.value; renderScenarioSidebar(); });
  $('fn-filter').addEventListener('input', function (e) { state.fnFilter = e.target.value; renderFunctionSidebar(); });
  document.querySelectorAll('.fn-tab').forEach(function (btn) {
    btn.addEventListener('click', function () {
      if (btn.disabled) return;
      state.fnView = btn.getAttribute('data-view');
      state.fnVarIdx = 0;
      renderFunctionViewer();
    });
  });
  $('fn-back').addEventListener('click', function () {
    if (state.fnHistory.length) selectFunction(state.fnHistory.pop(), false);
  });
  bindCopy($('sc-copy'), function () { return $('sc-cmd').textContent; });
  bindCopy($('fn-copy'), function () { return $('fn-cmd').textContent; });

  renderScenarioSidebar();
  renderScenarioViewer();
  renderFunctionSidebar();
  renderFunctionViewer();
})();
