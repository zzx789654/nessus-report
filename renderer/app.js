'use strict';
/*
 * Nessus Diff — renderer 主邏輯（純前端、零外部相依）
 *
 * 設計要點：
 *  - 不記憶：不使用任何 localStorage / sessionStorage / IndexedDB / cookie；資料只放在此模組的變數，
 *    關窗即由 GC 回收；另提供「清除資料」主動釋放。
 *  - 安全顯示：所有使用者資料一律用 textContent / 節點建立寫入 DOM，或用 escapeXml 進報表字串，杜絕 XSS。
 *  - 大資料量：CSV 分塊解析、差異表虛擬捲動（只渲染可見列）、圖表限制資料點、統計一次算好快取。
 */
(function () {
  // ---------------------------------------------------------------------------
  // 0. 小工具
  // ---------------------------------------------------------------------------
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const SVGNS = 'http://www.w3.org/2000/svg';

  // 純邏輯（解析/欄位對應/diff/評分）集中於 core.js，此處共用同一份實作
  const NCore = window.NCore;
  const { escapeXml, num, parseCSV, mapColumns, normalize, findingKey, REQUIRED } = NCore;
  function svgEl(name, attrs, text) {
    const e = document.createElementNS(SVGNS, name);
    if (attrs) for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (text != null) e.textContent = String(text);
    return e;
  }
  function fmt(n) { return (n == null || n === '') ? '—' : (typeof n === 'number' ? n.toLocaleString('en-US') : String(n)); }
  function debounce(fn, ms) { let t; return function () { clearTimeout(t); const a = arguments, c = this; t = setTimeout(() => fn.apply(c, a), ms); }; }

  // 圖表用浮動提示（跟隨游標；比原生 SVG <title> 更即時可見）
  let _tipEl = null;
  function tipEl() { if (!_tipEl) { _tipEl = document.createElement('div'); _tipEl.className = 'chart-tip'; _tipEl.hidden = true; document.body.appendChild(_tipEl); } return _tipEl; }
  function showTip(text, e) { const t = tipEl(); t.textContent = text; t.hidden = false; moveTip(e); }
  function moveTip(e) { const t = tipEl(); if (t.hidden) return; const w = t.offsetWidth || 200; let x = e.clientX + 14, y = e.clientY + 14; if (x + w > window.innerWidth - 8) x = e.clientX - w - 14; t.style.left = x + 'px'; t.style.top = y + 'px'; }
  function hideTip() { if (_tipEl) _tipEl.hidden = true; }

  // ---------------------------------------------------------------------------
  // 1. Log 模組（分級 / 攔截未捕捉錯誤 / 匯出）
  // ---------------------------------------------------------------------------
  const Log = (function () {
    const LEVELS = { DEBUG: 10, INFO: 20, WARN: 30, ERROR: 40 };
    const buf = [];           // {t, lvl, msg}
    const MAX = 5000;         // 環狀上限，避免長時間執行吃記憶體
    let errorCount = 0;
    const view = () => $('#log-view');

    function push(lvl, msg) {
      const entry = { t: new Date(), lvl, msg: String(msg) };
      buf.push(entry);
      if (buf.length > MAX) buf.shift();
      if (lvl === 'ERROR') { errorCount++; updateBadge(); }
      appendLine(entry);
    }
    function updateBadge() {
      const b = $('#log-badge');
      if (!b) return;
      if (errorCount > 0) { b.hidden = false; b.textContent = String(errorCount); }
    }
    function appendLine(e) {
      const v = view();
      if (!v) return;
      const sel = $('#log-level').value;
      if (!passLevel(e.lvl, sel)) return;
      v.appendChild(makeLine(e));
      // 僅在接近底部時自動捲動
      if (v.scrollHeight - v.scrollTop - v.clientHeight < 60) v.scrollTop = v.scrollHeight;
    }
    function makeLine(e) {
      const div = document.createElement('div');
      div.className = 'log-line';
      const time = document.createElement('span');
      time.className = 'log-time';
      time.textContent = e.t.toISOString().replace('T', ' ').replace('Z', '') + ' ';
      const lvl = document.createElement('span');
      lvl.className = 'lvl-' + e.lvl;
      lvl.textContent = '[' + e.lvl + '] ';
      const msg = document.createElement('span');
      msg.textContent = e.msg;   // textContent → 防 XSS
      div.appendChild(time); div.appendChild(lvl); div.appendChild(msg);
      return div;
    }
    function passLevel(lvl, sel) {
      if (sel === 'ALL') return true;
      return LEVELS[lvl] >= LEVELS[sel];
    }
    function rerender() {
      const v = view(); if (!v) return;
      v.replaceChildren();
      const sel = $('#log-level').value;
      const frag = document.createDocumentFragment();
      for (const e of buf) if (passLevel(e.lvl, sel)) frag.appendChild(makeLine(e));
      v.appendChild(frag);
      v.scrollTop = v.scrollHeight;
    }
    function toText() {
      return buf.map(e => `${e.t.toISOString()} [${e.lvl}] ${e.msg}`).join('\n');
    }
    function clear() { buf.length = 0; errorCount = 0; const b = $('#log-badge'); if (b) b.hidden = true; rerender(); }
    return {
      debug: (m) => push('DEBUG', m), info: (m) => push('INFO', m),
      warn: (m) => push('WARN', m), error: (m) => push('ERROR', m),
      rerender, toText, clear
    };
  })();

  // 全域錯誤攔截 → 進 Log（方便修 bug）
  window.addEventListener('error', (e) => {
    Log.error(`未捕捉錯誤：${e.message} @ ${e.filename}:${e.lineno}:${e.colno}`);
  });
  window.addEventListener('unhandledrejection', (e) => {
    Log.error(`未處理的 Promise rejection：${e.reason && e.reason.message ? e.reason.message : e.reason}`);
  });

  // ---------------------------------------------------------------------------
  // 4. 全域狀態（唯一資料來源，關閉即釋放）
  // ---------------------------------------------------------------------------
  const S = {
    old: null,   // {name, recs, map, missingOpt:[]}
    new: null,
    rows: [],        // 差異列（diff rows）
    filtered: [],    // 篩選後
    sortKey: 'priority', sortDir: -1,
    colFilters: {},   // 差異比對矩陣「各欄標題」的獨立篩選：{ 欄位key: 篩選值 }
    prioritySort: { key: 'score', dir: -1 },
    stats: null,
    hostPriority: [],
    // 風險明細分頁（每個 CVE 一列）
    viewSource: 'new',   // 全域資料來源：'old'（基準）或 'new'（當前）；驅動風險圖表單一來源圖與風險明細
    detailSort: { key: 'risk', dir: -1 },
    detailColFilters: {},   // 風險明細矩陣各欄標題的下拉複選篩選
    detailRows: [],
    detailFiltered: [],
    qmode: 'finding',
    qx: 'epss',  // 四象限橫軸：'epss' 或 'vpr'（縱軸固定 CVSS v2.0）
    // 風險圖表的 IP 篩選（多選）；為所選主機集合，size===主機總數 表示全選
    chartHosts: new Set(),
    ipSort: 'risk',  // IP 選單排序：'risk'（風險降序）或 'ip'（IP 降序）
    heatMetric: 'vpr',  // 熱力圖數值：'vpr'（Σ VPR）或 'epss'（Σ EPSS）
    cancelImport: false, // 匯入取消旗標
    scanTime: { old: '', new: '' } // 由 Scan Information plugin 擷取的掃描時間
  };

  // ---------------------------------------------------------------------------
  // 5~6. Diff / 統計 / 優先分數 → 由 core.js（NCore）提供純邏輯
  //   S.rows        = NCore.computeRows(oldRecs, newRecs)
  //   S.stats       = NCore.computeStats(oldRecs, newRecs, rows)
  //   S.hostPriority= NCore.computeHostPriority(oldRecs, newRecs, rows)
  // 見 recompute()。
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // 7. SVG 圖表
  // ---------------------------------------------------------------------------
  const RISK_COLORS = { Critical: '#ff5d8f', High: '#ff9e64', Medium: '#ffd166', Low: '#5bc8e0', Info: '#b7c0e6' };

  function chartSeverity(oldSev, newSev, mode) {
    const cats = ['Critical', 'High', 'Medium', 'Low', 'Info'];
    const W = 600, H = 300, pad = { l: 40, r: 16, t: 38, b: 40 };
    const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'xMidYMid meet', role: 'img' });
    const maxV = Math.max(1, ...cats.map(c => Math.max(oldSev[c] || 0, newSev[c] || 0)));
    const plotW = W - pad.l - pad.r, plotH = H - pad.t - pad.b;
    const y = v => pad.t + plotH - (v / maxV) * plotH;
    // Y 軸格線
    for (let g = 0; g <= 4; g++) {
      const val = Math.round(maxV * g / 4), yy = y(val);
      svg.appendChild(svgEl('line', { x1: pad.l, y1: yy, x2: W - pad.r, y2: yy, class: 'grid-line' }));
      svg.appendChild(svgEl('text', { x: pad.l - 6, y: yy + 3, 'text-anchor': 'end' }, val));
    }
    const groupW = plotW / cats.length;
    const twoBars = mode === 'diff';
    const barW = twoBars ? groupW * 0.3 : groupW * 0.45;
    cats.forEach((c, i) => {
      const gx = pad.l + i * groupW + groupW / 2;
      if (twoBars) {
        const ov = oldSev[c] || 0, nv = newSev[c] || 0;
        svg.appendChild(svgEl('rect', { x: gx - barW - 2, y: y(ov), width: barW, height: pad.t + plotH - y(ov), fill: RISK_COLORS[c], opacity: 0.45, rx: 2 }));
        svg.appendChild(svgEl('rect', { x: gx + 2, y: y(nv), width: barW, height: pad.t + plotH - y(nv), fill: RISK_COLORS[c], rx: 2 }));
        // 每根直條都標數字（含 0）
        svg.appendChild(svgEl('text', { x: gx - barW / 2 - 2, y: y(ov) - 4, 'text-anchor': 'middle', class: 'bar-label' }, ov));
        svg.appendChild(svgEl('text', { x: gx + 2 + barW / 2, y: y(nv) - 4, 'text-anchor': 'middle', class: 'bar-label' }, nv));
      } else {
        const nv = newSev[c] || 0;
        svg.appendChild(svgEl('rect', { x: gx - barW / 2, y: y(nv), width: barW, height: pad.t + plotH - y(nv), fill: RISK_COLORS[c], rx: 2 }));
        svg.appendChild(svgEl('text', { x: gx, y: y(nv) - 4, 'text-anchor': 'middle', class: 'bar-label' }, nv));
      }
      svg.appendChild(svgEl('text', { x: gx, y: H - pad.b + 16, 'text-anchor': 'middle' }, c));
    });
    if (twoBars) {
      svg.appendChild(svgEl('rect', { x: pad.l, y: 8, width: 10, height: 10, fill: '#888', opacity: 0.45 }));
      svg.appendChild(svgEl('text', { x: pad.l + 14, y: 17 }, '舊版'));
      svg.appendChild(svgEl('rect', { x: pad.l + 60, y: 8, width: 10, height: 10, fill: '#888' }));
      svg.appendChild(svgEl('text', { x: pad.l + 74, y: 17 }, '新版'));
    }
    return svg;
  }

  function chartDiff(st) {
    const items = st.mode === 'diff'
      ? [['新增', st.added, '#ff5d8f'], ['已修復', st.removed, '#5ce6b4'], ['持續', st.persistent, '#aab3dd'], ['變更', st.changed, '#ffd166']]
      : [['弱點', st.newTotal, '#4f8cff']];
    const W = 600, H = 300, pad = { l: 40, r: 16, t: 20, b: 40 };
    const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'xMidYMid meet', role: 'img' });
    const maxV = Math.max(1, ...items.map(it => it[1]));
    const plotW = W - pad.l - pad.r, plotH = H - pad.t - pad.b;
    const y = v => pad.t + plotH - (v / maxV) * plotH;
    for (let g = 0; g <= 4; g++) {
      const val = Math.round(maxV * g / 4), yy = y(val);
      svg.appendChild(svgEl('line', { x1: pad.l, y1: yy, x2: W - pad.r, y2: yy, class: 'grid-line' }));
      svg.appendChild(svgEl('text', { x: pad.l - 6, y: yy + 3, 'text-anchor': 'end' }, val));
    }
    const groupW = plotW / items.length, barW = Math.min(80, groupW * 0.5);
    items.forEach((it, i) => {
      const gx = pad.l + i * groupW + groupW / 2;
      svg.appendChild(svgEl('rect', { x: gx - barW / 2, y: y(it[1]), width: barW, height: pad.t + plotH - y(it[1]), fill: it[2], rx: 3 }));
      svg.appendChild(svgEl('text', { x: gx, y: y(it[1]) - 5, 'text-anchor': 'middle', class: 'bar-label' }, fmt(it[1])));
      svg.appendChild(svgEl('text', { x: gx, y: H - pad.b + 16, 'text-anchor': 'middle' }, it[0]));
    });
    return svg;
  }

  // 漏洞總數與各嚴重度比較（基準 vs 當前）— 分組長條，含數值與增減量
  function chartTotalsCompare(st) {
    const twoBars = st.mode === 'diff';
    const cats = [
      ['總數', st.oldTotal, st.newTotal, '#4f8cff'],
      ['Critical', st.oldSev.Critical, st.newSev.Critical, RISK_COLORS.Critical],
      ['High', st.oldSev.High, st.newSev.High, RISK_COLORS.High],
      ['Medium', st.oldSev.Medium, st.newSev.Medium, RISK_COLORS.Medium],
      ['Low', st.oldSev.Low, st.newSev.Low, RISK_COLORS.Low],
      ['Info', st.oldSev.Info, st.newSev.Info, RISK_COLORS.Info]
    ];
    const W = 640, H = 330, pad = { l: 44, r: 16, t: 42, b: 52 };
    const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'xMidYMid meet', role: 'img' });
    const maxV = Math.max(1, ...cats.map(c => Math.max(c[1], c[2])));
    const plotW = W - pad.l - pad.r, plotH = H - pad.t - pad.b;
    const y = v => pad.t + plotH - (v / maxV) * plotH;
    // Y 格線
    for (let g = 0; g <= 4; g++) {
      const val = Math.round(maxV * g / 4), yy = y(val);
      svg.appendChild(svgEl('line', { x1: pad.l, y1: yy, x2: W - pad.r, y2: yy, class: 'grid-line' }));
      svg.appendChild(svgEl('text', { x: pad.l - 6, y: yy + 3, 'text-anchor': 'end' }, val));
    }
    const groupW = plotW / cats.length;
    const barW = twoBars ? groupW * 0.28 : groupW * 0.42;
    cats.forEach((c, i) => {
      const gx = pad.l + i * groupW + groupW / 2;
      const ov = c[1], nv = c[2], color = c[3];
      if (twoBars) {
        svg.appendChild(svgEl('rect', { x: gx - barW - 3, y: y(ov), width: barW, height: pad.t + plotH - y(ov), fill: color, opacity: 0.42, rx: 2 }));
        svg.appendChild(svgEl('text', { x: gx - barW / 2 - 3, y: y(ov) - 4, 'text-anchor': 'middle', class: 'bar-label' }, fmt(ov)));
        svg.appendChild(svgEl('rect', { x: gx + 3, y: y(nv), width: barW, height: pad.t + plotH - y(nv), fill: color, rx: 2 }));
        svg.appendChild(svgEl('text', { x: gx + barW / 2 + 3, y: y(nv) - 4, 'text-anchor': 'middle', class: 'bar-label' }, fmt(nv)));
        // 增減量
        const d = nv - ov;
        const dtxt = d > 0 ? '▲+' + d : (d < 0 ? '▼' + d : '＝');
        const dcolor = d > 0 ? '#ff6b81' : (d < 0 ? '#2dd4a7' : '#8892a8');
        svg.appendChild(svgEl('text', { x: gx, y: H - pad.b + 30, 'text-anchor': 'middle', fill: dcolor, 'font-size': '10.5' }, dtxt));
      } else {
        svg.appendChild(svgEl('rect', { x: gx - barW / 2, y: y(nv), width: barW, height: pad.t + plotH - y(nv), fill: color, rx: 2 }));
        svg.appendChild(svgEl('text', { x: gx, y: y(nv) - 4, 'text-anchor': 'middle', class: 'bar-label' }, fmt(nv)));
      }
      svg.appendChild(svgEl('text', { x: gx, y: H - pad.b + 16, 'text-anchor': 'middle' }, c[0]));
    });
    // 圖例
    if (twoBars) {
      svg.appendChild(svgEl('rect', { x: pad.l, y: 8, width: 10, height: 10, fill: '#888', opacity: 0.42 }));
      svg.appendChild(svgEl('text', { x: pad.l + 14, y: 17 }, '舊版'));
      svg.appendChild(svgEl('rect', { x: pad.l + 60, y: 8, width: 10, height: 10, fill: '#888' }));
      svg.appendChild(svgEl('text', { x: pad.l + 74, y: 17 }, '新版'));
    }
    return svg;
  }

  // Top 風險主機：依「弱點總數」排序，單一長條依嚴重度堆疊（Info/Low/Medium/High/Critical）
  // 使用者指定色：Info=藍、Low=綠、Medium=黃、High=紅、Critical=橘（Aurora 調和色）
  const TOP_SEV = [
    { k: 'Info', c: '#5b9bff' }, { k: 'Low', c: '#5ce6b4' }, { k: 'Medium', c: '#ffd166' },
    { k: 'High', c: '#ff5d8f' }, { k: 'Critical', c: '#ff9e64' }
  ];
  function chartTopHosts(priority) {
    const top = priority.slice().sort((a, b) => b.count - a.count).slice(0, 10);
    const W = 640, rowH = 26, legendH = 22, pad = { l: 132, r: 48, t: 10 + legendH, b: 12 };
    const H = Math.max(120, top.length * rowH + pad.t + pad.b);
    const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'xMidYMid meet', role: 'img' });
    if (!top.length) { svg.appendChild(svgEl('text', { x: W / 2, y: H / 2, 'text-anchor': 'middle' }, '無資料')); return svg; }
    // 圖例（堆疊順序由左到右：Critical→Info，故圖例也照此顯示）
    let lx = pad.l;
    for (let i = TOP_SEV.length - 1; i >= 0; i--) {
      const s = TOP_SEV[i];
      svg.appendChild(svgEl('rect', { x: lx, y: 4, width: 10, height: 10, fill: s.c, rx: 2 }));
      svg.appendChild(svgEl('text', { x: lx + 14, y: 13 }, s.k));
      lx += 20 + s.k.length * 8 + 12;
    }
    const maxV = Math.max(1, ...top.map(h => h.count));
    const plotW = W - pad.l - pad.r;
    top.forEach((h, i) => {
      const yy = pad.t + i * rowH;
      svg.appendChild(svgEl('text', { x: pad.l - 8, y: yy + rowH / 2 + 3, 'text-anchor': 'end' }, h.host.length > 20 ? h.host.slice(0, 19) + '…' : h.host));
      // 由左到右堆疊：Critical, High, Medium, Low, Info
      let x = pad.l;
      for (let j = TOP_SEV.length - 1; j >= 0; j--) {
        const s = TOP_SEV[j], n = h.sev[s.k] || 0;
        if (!n) continue;
        const w = (n / maxV) * plotW;
        const rect = svgEl('rect', { x, y: yy + 4, width: Math.max(0.5, w), height: rowH - 10, fill: s.c });
        rect.appendChild(svgEl('title', null, `${h.host} · ${s.k} ${n}`));
        svg.appendChild(rect);
        x += w;
      }
      svg.appendChild(svgEl('text', { x: x + 5, y: yy + rowH / 2 + 3, class: 'bar-label' }, fmt(h.count)));
    });
    return svg;
  }

  // 軸定義（定義域上限、標題、刻度格式、預設門檻）
  // ticks：刻度值陣列（避免用 max/5 產生醜刻度）。CVSS 上限設 11 留頭部空間，避免 CVSS=10 的點貼齊上緣/被裁切。
  const AXES = {
    epss:  { max: 1,  ticks: [0, 0.2, 0.4, 0.6, 0.8, 1], label: 'EPSS（被利用機率）', tick: v => v.toFixed(1), th: 0.5 },
    vpr:   { max: 10, ticks: [0, 2, 4, 6, 8, 10], label: 'VPR（漏洞優先分數）', tick: v => String(v), th: 7 },
    cvss2: { max: 11, ticks: [0, 2, 4, 6, 8, 10], label: 'CVSS v2.0', tick: v => String(v), th: 7 },
    cvss3: { max: 11, ticks: [0, 2, 4, 6, 8, 10], label: 'CVSS v3.0（v2.0 缺）', tick: v => String(v), th: 7 }
  };

  // 四象限：縱軸固定 CVSS v2.0（整份缺 v2.0 時降級用 v3.0），橫軸可切 EPSS / VPR。
  // cfg = { xKey:'epss'|'vpr', xThresh, yThresh, addedOnly, mode:'finding'|'host' }
  function chartQuadrant(cfg) {
    cfg = cfg || {};
    const xKey = (cfg.xKey === 'vpr') ? 'vpr' : 'epss';
    const mode = (cfg.mode === 'host') ? 'host' : 'finding';
    const addedOnly = !!cfg.addedOnly;
    // 可由呼叫端傳入已依 IP 篩選的資料；未傳則用全量
    const recs = cfg.recs || ((S.new && S.new.recs.length) ? S.new.recs : (S.old ? S.old.recs : []));
    const rows = cfg.rows || S.rows;

    // Y 軸：固定 CVSS v2.0；若整份都沒有 v2.0 才降級用 v3.0
    const hasV2 = recs.some(r => r.cvss2 != null);
    const yKey = hasV2 ? 'cvss2' : 'cvss3';
    const xAx = AXES[xKey], yAx = AXES[yKey];
    let xThresh = cfg.xThresh != null ? cfg.xThresh : xAx.th;
    let yThresh = cfg.yThresh != null ? cfg.yThresh : 7;

    let pts = [], missing = 0;
    if (mode === 'host') {
      // 一點 = 一台主機（取該主機 x/y 的最大值）→ 大量主機時避免點重疊
      const byHost = new Map();
      const addedHosts = new Set(rows.filter(r => r.status === 'added').map(r => r.host));
      for (const r of recs) {
        const xv = r[xKey], yv = r[yKey];
        if (xv == null || yv == null) continue;
        let h = byHost.get(r.host);
        if (!h) { h = { host: r.host, x: 0, y: 0, crit: 0, high: 0, count: 0 }; byHost.set(r.host, h); }
        h.x = Math.max(h.x, xv); h.y = Math.max(h.y, yv); h.count++;
        if (r.risk === 'Critical') h.crit++; else if (r.risk === 'High') h.high++;
      }
      for (const h of byHost.values()) {
        if (addedOnly && !addedHosts.has(h.host)) continue;
        const risk = h.crit ? 'Critical' : (h.high ? 'High' : 'Medium');
        pts.push({ x: h.x, y: h.y, risk, host: h.host, name: `${h.count} 筆弱點`, added: addedHosts.has(h.host), w: (h.x / xAx.max) * (h.y / yAx.max) });
      }
    } else {
      const addedKeys = new Set(rows.filter(r => r.status === 'added').map(r => r.host + '|' + findingKey(r)));
      for (const r of recs) {
        const xv = r[xKey], yv = r[yKey];
        if (xv == null || yv == null) { missing++; continue; }
        const isAdded = addedKeys.has(r.host + '|' + findingKey(r));
        if (addedOnly && !isAdded) continue;
        pts.push({ x: xv, y: yv, risk: r.risk, host: r.host, name: r.name, cve: r.cve, added: isAdded, w: (xv / xAx.max) * (yv / yAx.max) });
      }
    }
    const MAXPTS = 800;
    let capped = false;
    if (pts.length > MAXPTS) { pts.sort((a, b) => b.w - a.w); pts = pts.slice(0, MAXPTS); capped = true; }

    // 防禦性夾範圍：門檻與座標一律限制在定義域內，避免異常值使點/線跑出畫面被裁掉
    xThresh = Math.max(0, Math.min(xAx.max, xThresh));
    yThresh = Math.max(0, Math.min(yAx.max, yThresh));
    const W = 600, H = 420, pad = { l: 48, r: 20, t: 20, b: 44 };
    const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'xMidYMid meet', role: 'img' });
    const plotW = W - pad.l - pad.r, plotH = H - pad.t - pad.b;
    const X = v => pad.l + (Math.max(0, Math.min(xAx.max, v)) / xAx.max) * plotW;
    const Y = v => pad.t + plotH - (Math.max(0, Math.min(yAx.max, v)) / yAx.max) * plotH;
    // 象限背景（右上=優先；上緣到 y 門檻）
    svg.appendChild(svgEl('rect', { x: X(xThresh), y: Y(yAx.max), width: X(xAx.max) - X(xThresh), height: Y(yThresh) - Y(yAx.max), fill: 'rgba(255,77,109,0.08)' }));
    // 格線 + Y 刻度
    for (const vy of yAx.ticks) {
      const yy = Y(vy);
      svg.appendChild(svgEl('line', { x1: pad.l, y1: yy, x2: W - pad.r, y2: yy, class: 'grid-line' }));
      svg.appendChild(svgEl('text', { x: pad.l - 6, y: yy + 3, 'text-anchor': 'end' }, yAx.tick(vy)));
    }
    // X 刻度
    for (const vx of xAx.ticks) {
      const xx = X(vx);
      svg.appendChild(svgEl('text', { x: xx, y: H - pad.b + 16, 'text-anchor': 'middle' }, xAx.tick(vx)));
    }
    // 門檻參考線
    svg.appendChild(svgEl('line', { x1: X(xThresh), y1: pad.t, x2: X(xThresh), y2: pad.t + plotH, class: 'ref-line' }));
    svg.appendChild(svgEl('line', { x1: pad.l, y1: Y(yThresh), x2: W - pad.r, y2: Y(yThresh), class: 'ref-line' }));
    // 點（含透明較大命中區 + 游標提示，確保滑到弱點/主機時顯示 CVE 或 IP）
    for (const p of pts) {
      const cx = X(p.x), cy = Y(p.y), color = RISK_COLORS[p.risk] || '#888';
      let node;
      if (p.added) { const s = 4; node = svgEl('path', { d: `M${cx} ${cy - s}L${cx + s} ${cy}L${cx} ${cy + s}L${cx - s} ${cy}Z`, fill: color, opacity: 0.9 }); }
      else { node = svgEl('circle', { cx, cy, r: 3.2, fill: color, opacity: 0.72 }); }
      svg.appendChild(node);
      const tipText = (mode === 'host')
        ? `主機 ${p.host}\n${p.name}\n${yAx.label} ${p.y} · ${xAx.label} ${p.x}`
        : `${p.host}${p.cve ? '\nCVE: ' + p.cve : ''}\n${p.name}\n${yAx.label} ${p.y} · ${xAx.label} ${p.x}`;
      const hit = svgEl('circle', { cx, cy, r: 8, fill: 'transparent' });
      hit.style.cursor = 'pointer';
      // 僅在「產報表」時附上原生 <title>（靜態 HTML 無 JS 事件）；畫面上改用自繪浮動提示，避免與原生 tooltip 重複出現
      if (cfg.forReport) hit.appendChild(svgEl('title', null, tipText));
      hit.addEventListener('mouseenter', e => showTip(tipText, e));
      hit.addEventListener('mousemove', moveTip);
      hit.addEventListener('mouseleave', hideTip);
      svg.appendChild(hit);
    }
    // 軸標題與象限標籤（優先處理標籤放在上緣，避免壓到右上角資料點）
    svg.appendChild(svgEl('text', { x: pad.l + plotW / 2, y: H - 6, 'text-anchor': 'middle' }, xAx.label + ' →'));
    svg.appendChild(svgEl('text', { x: 12, y: pad.t + plotH / 2, 'text-anchor': 'middle', transform: `rotate(-90 12 ${pad.t + plotH / 2})` }, yAx.label + ' →'));
    svg.appendChild(svgEl('text', { x: W - pad.r, y: 13, 'text-anchor': 'end', class: 'quad-label' }, '⚠ 右上＝優先處理'));
    if (capped) svg.appendChild(svgEl('text', { x: pad.l + 2, y: 13, class: 'quad-label' }, `僅顯示風險最高的 ${MAXPTS} 點`));
    if (missing > 0) svg.appendChild(svgEl('text', { x: pad.l + 2, y: capped ? 26 : 13, class: 'quad-label' }, `${missing} 筆缺 ${xAx.label}/${yAx.label} 未繪`));
    return svg;
  }

  // 主機風險熱力圖：每格一台主機，色階由優先分數決定。以 DOM 色塊呈現（輕量），
  // 大量主機時只畫前 N 格避免 DOM 膨脹。
  function heatColor(t) { // t: 0..1
    const stops = [[45, 212, 167], [255, 210, 63], [255, 140, 66], [255, 77, 109]];
    const x = Math.max(0, Math.min(1, t)) * (stops.length - 1);
    const i = Math.floor(x), f = x - i, a = stops[i], b = stops[Math.min(i + 1, stops.length - 1)];
    return `rgb(${Math.round(a[0] + (b[0] - a[0]) * f)},${Math.round(a[1] + (b[1] - a[1]) * f)},${Math.round(a[2] + (b[2] - a[2]) * f)})`;
  }
  // 熱力圖：每格一台主機，數值 = 該主機 Σ VPR 或 Σ EPSS（面板內可切換）
  function chartHeatmap(priority, metric) {
    metric = metric === 'epss' ? 'epss' : 'vpr';
    const valOf = h => metric === 'epss' ? h.sumEpss : h.sumVpr;
    const fmtVal = v => metric === 'epss' ? v.toFixed(2) : v.toFixed(1);
    const metricLabel = metric === 'epss' ? 'Σ EPSS' : 'Σ VPR';
    const wrap = document.createElement('div');
    if (!priority.length) { const e = document.createElement('div'); e.className = 'empty-state small'; e.textContent = '（尚無主機資料）'; wrap.appendChild(e); return wrap; }
    const CAP = 400;
    // 依所選指標由大到小排序後取前 N，讓高值主機集中在前
    const list = priority.slice().sort((a, b) => valOf(b) - valOf(a)).slice(0, CAP);
    const maxV = Math.max(0.0001, ...list.map(valOf));
    const grid = document.createElement('div'); grid.className = 'heatmap-grid';
    for (const h of list) {
      const v = valOf(h), t = v / maxV;
      const tile = document.createElement('div'); tile.className = 'heat-tile';
      tile.style.background = heatColor(t);
      tile.style.color = heatText(t);
      const ip = document.createElement('div'); ip.className = 'ht-ip'; ip.textContent = h.host;
      const sc = document.createElement('div'); sc.className = 'ht-score'; sc.textContent = `${metricLabel} ${fmtVal(v)}`;
      tile.appendChild(ip); tile.appendChild(sc);
      tile.title = `${h.host}\nΣ VPR ${h.sumVpr.toFixed(1)} · Σ EPSS ${h.sumEpss.toFixed(2)}\nCritical ${h.sev.Critical} · High ${h.sev.High} · Medium ${h.sev.Medium} · Low ${h.sev.Low} · Info ${h.sev.Info} · 弱點 ${h.count}`;
      grid.appendChild(tile);
    }
    wrap.appendChild(grid);
    const legend = document.createElement('div'); legend.className = 'heat-legend';
    legend.appendChild(document.createTextNode(`低（${metricLabel}） `));
    const scale = document.createElement('span'); scale.className = 'heat-scale'; legend.appendChild(scale);
    legend.appendChild(document.createTextNode(` 高 · 共 ${priority.length} 台`));
    wrap.appendChild(legend);
    if (priority.length > CAP) { const more = document.createElement('div'); more.className = 'heat-more'; more.textContent = `僅顯示 ${metricLabel} 最高的前 ${CAP} 台。`; wrap.appendChild(more); }
    return wrap;
  }
  function heatText(t) { // 高風險(紅)用白字，低風險(綠/黃)用深字
    return t > 0.55 ? '#fff' : '#10151f';
  }

  // ---------------------------------------------------------------------------
  // 8. 差異表（虛擬捲動）
  // ---------------------------------------------------------------------------
  const COLS = [
    { key: 'status', label: '狀態', w: '150px', type: 'status' },
    { key: 'host', label: '主機 / IP', w: '150px' },
    { key: 'pluginId', label: 'Plugin', w: '78px' },
    { key: 'name', label: '弱點名稱', w: 'minmax(200px,1.6fr)' },
    { key: 'risk', label: '嚴重度', w: '96px', type: 'risk' },
    { key: 'port', label: 'Port', w: '64px' },
    { key: 'vpr', label: 'VPR', w: '68px', type: 'num' },
    { key: 'epss', label: 'EPSS', w: '78px', type: 'epss' },
    { key: 'cve', label: 'CVE', w: '150px' }
  ];
  const ROW_H = 27;
  const STATUS_LABEL = { added: '🔴 新增', removed: '🟢 已修復', persistent: '⚪ 持續', changed: '🟡 變更', single: '本份' };

  function gridTemplate() { return COLS.map(c => c.w).join(' '); }

  // 差異矩陣欄位標題篩選：全部採「下拉 + 核取方塊複選」。
  // VPR/EPSS 這類連續數值改為區間分級複選；其餘欄位以「該欄實際出現過的值」為選項。
  const VPR_BUCKETS = [
    { id: '9-10', label: '9–10（極高）', test: v => v >= 9 },
    { id: '7-9', label: '7–9（高）', test: v => v >= 7 && v < 9 },
    { id: '4-7', label: '4–7（中）', test: v => v >= 4 && v < 7 },
    { id: '0-4', label: '0–4（低）', test: v => v >= 0 && v < 4 }
  ];
  const EPSS_BUCKETS = [
    { id: 'e90', label: '≥ 90%', test: v => v >= 0.9 },
    { id: 'e50', label: '50–90%', test: v => v >= 0.5 && v < 0.9 },
    { id: 'e10', label: '10–50%', test: v => v >= 0.1 && v < 0.5 },
    { id: 'e0', label: '< 10%', test: v => v >= 0 && v < 0.1 }
  ];
  function bucketsFor(c) { return c.key === 'vpr' ? VPR_BUCKETS : (c.key === 'epss' ? EPSS_BUCKETS : null); }

  // IP 感知排序（IPv4 逐段比較，其餘退回字串比較）
  function ipCompare(a, b) {
    const ma = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(a), mb = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(b);
    if (ma && mb) { for (let i = 1; i <= 4; i++) { const d = (+ma[i]) - (+mb[i]); if (d) return d; } return 0; }
    if (ma && !mb) return -1; if (!ma && mb) return 1;
    return a.localeCompare(b);
  }

  // 取一列在某欄的「選項鍵」集合（CVE 一列可能多個 → 多鍵；數值 → 對應區間；空值 → 特殊鍵）
  function colKeysOf(c, r) {
    const bk = bucketsFor(c);
    if (bk) { const v = r[c.key]; if (v == null) return ['__none__']; for (const b of bk) if (b.test(v)) return [b.id]; return ['__none__']; }
    if (c.key === 'cve') {
      const toks = String(r.cve || '').split(/[,;\s]+/).filter(x => /^CVE-/i.test(x)).map(x => x.toUpperCase());
      return toks.length ? Array.from(new Set(toks)) : ['__none__'];
    }
    const val = r[c.key];
    return [(val == null || val === '') ? '__blank__' : String(val)];
  }

  function colKeyLabel(c, key) {
    if (key === '__none__') return c.key === 'cve' ? '（無 CVE）' : '（無數值）';
    if (key === '__blank__') return '（空白）';
    if (c.key === 'status') return STATUS_LABEL[key] || key;
    const bk = bucketsFor(c); if (bk) { const b = bk.find(x => x.id === key); return b ? b.label : key; }
    return key;
  }

  // 列出某欄可選項（依實際出現的值，固定/數值排序），空值/無值置於最後
  function colOptions(c, rows) {
    const present = new Set();
    for (const r of rows) for (const k of colKeysOf(c, r)) present.add(k);
    let ordered;
    if (c.key === 'status') ordered = ['added', 'removed', 'persistent', 'changed', 'single'];
    else if (c.key === 'risk') ordered = ['Critical', 'High', 'Medium', 'Low', 'Info'];
    else if (bucketsFor(c)) ordered = bucketsFor(c).map(b => b.id);
    else {
      ordered = Array.from(present).filter(k => k !== '__none__' && k !== '__blank__');
      if (c.key === 'port' || c.key === 'pluginId') ordered.sort((a, b) => (parseFloat(a) || 0) - (parseFloat(b) || 0));
      else if (c.key === 'host') ordered.sort(ipCompare);
      else ordered.sort((a, b) => a.localeCompare(b));
    }
    const res = ordered.filter(k => present.has(k));
    if (present.has('__blank__')) res.push('__blank__');
    if (present.has('__none__')) res.push('__none__');
    return res;
  }

  let _colMenu = null;
  function closeColMenu() { if (_colMenu) { _colMenu.remove(); _colMenu = null; document.removeEventListener('pointerdown', onColMenuOutside, true); } }
  function onColMenuOutside(e) { if (_colMenu && !_colMenu.contains(e.target) && !e.target.closest('.cf-btn')) closeColMenu(); }

  // 通用「矩陣標題 + 各欄下拉複選」建構器；由 cfg 描述某個矩陣（差異比對 / 風險明細共用）
  //   cfg = { id, cols, headEl(), gridTemplate(), rows(), getState(), apply(), rebuild(),
  //           sortActive(c), sortArrow(), onSort(c) }
  function buildMatrixHeader(cfg) {
    closeColMenu();
    const head = cfg.headEl();
    head.replaceChildren();
    head.style.gridTemplateColumns = cfg.gridTemplate();
    const state = cfg.getState();
    // 第一列：可排序的欄位標題
    for (const c of cfg.cols) {
      const th = document.createElement('div');
      th.className = 'th';
      const sel = state[c.key];
      const active = Array.isArray(sel) && sel.length > 0;
      if (active) th.classList.add('filtered');
      th.append(c.label);
      if (cfg.sortActive(c)) { const a = document.createElement('span'); a.className = 'arrow'; a.textContent = cfg.sortArrow(); th.appendChild(a); }
      if (active) { const dot = document.createElement('span'); dot.className = 'thf-dot'; dot.title = '此欄已套用篩選'; th.appendChild(dot); }
      th.addEventListener('click', () => cfg.onSort(c));
      head.appendChild(th);
    }
    // 第二列：各欄下拉複選按鈕（grid 自動換到第二排，與上方欄位對齊）
    for (const c of cfg.cols) head.appendChild(makeColFilterCell(cfg, c));
  }

  function makeColFilterCell(cfg, c) {
    const cell = document.createElement('div');
    cell.className = 'thf';
    cell.addEventListener('click', e => e.stopPropagation()); // 不觸發上方標題排序
    const sel = cfg.getState()[c.key];
    const n = Array.isArray(sel) ? sel.length : 0;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'cf-btn' + (n ? ' active' : '');
    btn.textContent = n ? `${n} 項 ▾` : '全部 ▾';
    btn.title = n ? '已選 ' + n + ' 項，點擊調整' : '點擊選取要顯示的項目（可複選）';
    const mkey = cfg.id + '/' + c.key;
    btn.addEventListener('click', () => { if (_colMenu && _colMenu._key === mkey) closeColMenu(); else openColMenu(cfg, c, btn); });
    cell.appendChild(btn);
    return cell;
  }

  function openColMenu(cfg, c, btn) {
    closeColMenu();
    const opts = colOptions(c, cfg.rows());
    const selected = new Set(Array.isArray(cfg.getState()[c.key]) ? cfg.getState()[c.key] : []);
    const menu = document.createElement('div');
    menu.className = 'cf-menu'; menu._key = cfg.id + '/' + c.key;
    // 工具列：全選 / 清除
    const tools = document.createElement('div'); tools.className = 'cf-tools';
    const bAll = document.createElement('button'); bAll.type = 'button'; bAll.className = 'btn btn-ghost'; bAll.textContent = '全選';
    const bClr = document.createElement('button'); bClr.type = 'button'; bClr.className = 'btn btn-ghost'; bClr.textContent = '清除';
    const cnt = document.createElement('span'); cnt.className = 'cf-count';
    tools.appendChild(bAll); tools.appendChild(bClr); tools.appendChild(cnt);
    menu.appendChild(tools);
    // 選項多時提供搜尋
    let search = null;
    if (opts.length > 8) {
      search = document.createElement('input');
      search.className = 'cf-search input'; search.type = 'search'; search.placeholder = '搜尋選項…'; search.autocomplete = 'off';
      menu.appendChild(search);
    }
    const list = document.createElement('div'); list.className = 'cf-list';
    menu.appendChild(list);

    const apply = () => {
      const st = cfg.getState();
      if (selected.size === 0) delete st[c.key];
      else st[c.key] = Array.from(selected);
      const nn = selected.size;
      btn.textContent = nn ? `${nn} 項 ▾` : '全部 ▾';
      btn.classList.toggle('active', nn > 0);
      const idx = cfg.cols.indexOf(c); const th = cfg.headEl().children[idx];
      if (th) th.classList.toggle('filtered', nn > 0);
      cnt.textContent = nn ? `已選 ${nn}/${opts.length}` : `共 ${opts.length} 項`;
      cfg.apply();
    };
    const renderList = () => {
      const q = search ? search.value.trim().toLowerCase() : '';
      list.replaceChildren();
      let shown = 0;
      for (const key of opts) {
        const label = colKeyLabel(c, key);
        if (q && label.toLowerCase().indexOf(q) === -1) continue;
        shown++;
        const row = document.createElement('label'); row.className = 'cf-row';
        const cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = selected.has(key);
        cb.addEventListener('change', () => { if (cb.checked) selected.add(key); else selected.delete(key); apply(); });
        const txt = document.createElement('span'); txt.className = 'cf-txt'; txt.textContent = label;
        row.appendChild(cb); row.appendChild(txt); list.appendChild(row);
      }
      if (!shown) { const e = document.createElement('div'); e.className = 'cf-empty'; e.textContent = '無相符選項'; list.appendChild(e); }
    };
    bAll.addEventListener('click', () => { for (const k of opts) selected.add(k); renderList(); apply(); });
    bClr.addEventListener('click', () => { selected.clear(); renderList(); apply(); });
    if (search) search.addEventListener('input', debounce(renderList, 120));
    cnt.textContent = selected.size ? `已選 ${selected.size}/${opts.length}` : `共 ${opts.length} 項`;
    renderList();

    document.body.appendChild(menu);
    // 以按鈕位置定位（fixed，避免被表格 overflow 裁切）；靠右不超出視窗
    const r = btn.getBoundingClientRect();
    const mw = Math.min(280, Math.max(200, r.width * 2));
    let left = r.left; if (left + mw > window.innerWidth - 8) left = window.innerWidth - mw - 8;
    menu.style.left = Math.max(8, left) + 'px';
    menu.style.top = (r.bottom + 4) + 'px';
    menu.style.width = mw + 'px';
    _colMenu = menu;
    if (search) search.focus();
    setTimeout(() => document.addEventListener('pointerdown', onColMenuOutside, true), 0);
  }
  // 表格捲動 / 視窗縮放時關閉選單（fixed 定位不隨捲動）
  window.addEventListener('resize', closeColMenu);

  // 依 cfg 收集「有選取」的欄位篩選；欄內多鍵為 OR、跨欄為 AND
  function activeColFilters(cfg) {
    const state = cfg.getState(), arr = [];
    for (const c of cfg.cols) { const sel = state[c.key]; if (Array.isArray(sel) && sel.length) arr.push({ c, set: new Set(sel) }); }
    return arr;
  }
  function rowPassesColFilters(colF, r) {
    for (const f of colF) {
      const keys = colKeysOf(f.c, r);
      let hit = false;
      for (const k of keys) if (f.set.has(k)) { hit = true; break; }
      if (!hit) return false;
    }
    return true;
  }

  // 差異比對矩陣的篩選設定
  const diffFilterCfg = {
    id: 'diff', cols: COLS,
    headEl: () => $('#vthead'), gridTemplate: () => gridTemplate(),
    rows: () => S.rows, getState: () => S.colFilters,
    apply: () => applyFilterSort(),
    sortActive: (c) => S.sortKey === c.key, sortArrow: () => S.sortDir > 0 ? '▲' : '▼',
    onSort: (c) => {
      if (S.sortKey === c.key) S.sortDir = -S.sortDir;
      else { S.sortKey = c.key; S.sortDir = (c.type === 'num' || c.type === 'epss') ? -1 : 1; }
      applyFilterSort(); buildHeader();
    }
  };
  function buildHeader() { buildMatrixHeader(diffFilterCfg); }

  function sortRows(rows) {
    const key = S.sortKey, dir = S.sortDir;
    rows.sort((a, b) => {
      let av, bv;
      if (key === 'priority') { av = a.priority; bv = b.priority; }
      else { av = a[key]; bv = b[key]; }
      if (key === 'risk') { av = a.riskLevel; bv = b.riskLevel; }
      if (av == null) av = -Infinity; if (bv == null) bv = -Infinity;
      if (typeof av === 'string' && typeof bv === 'string') return dir * av.localeCompare(bv);
      return dir * (av > bv ? 1 : av < bv ? -1 : 0);
    });
    return rows;
  }

  // 差異比對：僅由各欄標題的下拉複選篩選（欄內 OR、跨欄 AND），排序沿用點欄標題
  function applyFilterSort() {
    const colF = activeColFilters(diffFilterCfg);
    const out = [];
    for (const r of S.rows) if (rowPassesColFilters(colF, r)) out.push(r);
    sortRows(out);
    S.filtered = out;
    $('#diff-count').textContent = `${fmt(out.length)} 筆（共 ${fmt(S.rows.length)}）`;
    renderVirtual();
  }

  let vScrollBound = false;
  function renderVirtual() {
    const viewport = $('#vviewport'), spacer = $('#vspacer'), emptyEl = $('#diff-empty');
    spacer.style.height = (S.filtered.length * ROW_H) + 'px';
    emptyEl.hidden = S.filtered.length > 0;
    if (!vScrollBound) {
      viewport.addEventListener('scroll', paintDiffRows, { passive: true });
      vScrollBound = true;
    }
    viewport.scrollTop = 0;
    paintDiffRows();
  }
  // 模組層級：每次都即時讀取 S.filtered 與視窗高度，避免捕捉到過期的 total（否則捲到底會渲染不到）
  function paintDiffRows() {
    const viewport = $('#vviewport'), rowsEl = $('#vrows');
    const total = S.filtered.length;
    const scrollTop = viewport.scrollTop, vh = viewport.clientHeight;
    const start = Math.max(0, Math.floor(scrollTop / ROW_H) - 4);
    const end = Math.min(total, Math.ceil((scrollTop + vh) / ROW_H) + 4);
    rowsEl.style.transform = `translateY(${start * ROW_H}px)`;
    const frag = document.createDocumentFragment();
    const tmpl = gridTemplate();
    for (let i = start; i < end; i++) frag.appendChild(makeRow(S.filtered[i], tmpl));
    rowsEl.replaceChildren(frag);
  }

  function makeRow(r, tmpl) {
    const row = document.createElement('div');
    row.className = 'vrow';
    row.style.gridTemplateColumns = tmpl;
    row.style.height = ROW_H + 'px';
    for (const c of COLS) {
      const td = document.createElement('div');
      td.className = 'td' + (c.type === 'num' || c.type === 'epss' ? ' num' : '');
      if (c.type === 'status') {
        const s = document.createElement('span');
        s.className = 'st-' + r.status + ' st-dot';
        let label = STATUS_LABEL[r.status] || r.status;
        if (r.status === 'changed' && r.changeTypes && r.changeTypes.length) { label += `（${r.changeTypes.join('/')}）`; td.title = '變更內容：' + r.changeTypes.join('、') + (r.oldRisk ? `；原嚴重度 ${r.oldRisk}` : ''); }
        s.textContent = label;
        td.appendChild(s);
      } else if (c.type === 'risk') {
        const p = document.createElement('span');
        p.className = 'pill risk-' + r.risk;
        p.textContent = r.risk;
        td.appendChild(p);
      } else if (c.type === 'epss') {
        td.textContent = r.epss == null ? '—' : (r.epss * 100).toFixed(1) + '%';
      } else if (c.type === 'num') {
        td.textContent = r[c.key] == null ? '—' : r[c.key];
      } else {
        const val = r[c.key];
        td.textContent = (val === '' || val == null) ? '—' : val;
        if (c.key === 'name' || c.key === 'cve') td.title = val || '';
      }
      row.appendChild(td);
    }
    return row;
  }

  // ---------------------------------------------------------------------------
  // 9. 迷你表（優先主機）
  // ---------------------------------------------------------------------------
  function renderPriorityTable(containerSel, priority, limit) {
    const cont = $(containerSel);
    cont.replaceChildren();
    if (!priority.length) { cont.textContent = '（無資料）'; return; }
    const cols = [
      { k: 'host', label: '主機 / IP', num: false },
      { k: 'maxVpr', label: '最高VPR', num: true, fmt: v => v ? v.toFixed(1) : '—' },
      { k: 'maxEpss', label: '最高EPSS', num: true, fmt: v => v ? (v * 100).toFixed(1) + '%' : '—' },
      { k: 'urgent', label: '緊急', num: true, hint: 'VPR≥7 且 EPSS≥50%' },
      { k: 'crit', label: 'Critical', num: true },
      { k: 'high', label: 'High', num: true },
      { k: 'count', label: '弱點數', num: true }
    ];
    if (S.stats && S.stats.mode === 'diff') cols.push({ k: 'added', label: '本次新增', num: true });

    const data = priority.slice(0, limit || priority.length);
    const table = document.createElement('table');
    table.className = 'centered';
    const thead = document.createElement('thead');
    const htr = document.createElement('tr');
    for (const col of cols) {
      const th = document.createElement('th');
      th.textContent = col.label;
      if (col.hint) th.title = col.hint;
      if (col.num) th.className = 'num';
      th.addEventListener('click', () => {
        if (S.prioritySort.key === col.k) S.prioritySort.dir = -S.prioritySort.dir;
        else { S.prioritySort.key = col.k; S.prioritySort.dir = col.num ? -1 : 1; }
        const dir = S.prioritySort.dir, k = S.prioritySort.key;
        S.hostPriority.sort((a, b) => (typeof a[k] === 'string') ? dir * a[k].localeCompare(b[k]) : dir * ((a[k] > b[k]) ? 1 : (a[k] < b[k] ? -1 : 0)));
        renderPriorityTable(containerSel, S.hostPriority, limit);
      });
      htr.appendChild(th);
    }
    thead.appendChild(htr); table.appendChild(thead);
    const tbody = document.createElement('tbody');
    for (const d of data) {
      const tr = document.createElement('tr');
      for (const col of cols) {
        const td = document.createElement('td');
        if (col.num) td.className = 'num';
        const val = d[col.k];
        td.textContent = col.fmt ? col.fmt(val) : (val === '' || val == null ? '—' : val);
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    cont.appendChild(table);
  }

  // ---------------------------------------------------------------------------
  // 9b. 風險明細分頁：每個 CVE 一列（詳細資訊 + 處理方式），可選 CSV、篩選、排序
  // ---------------------------------------------------------------------------
  const DCOLS = [
    { key: 'cve', label: 'CVE', w: '150px' },
    { key: 'host', label: '主機 / IP', w: '148px' },
    { key: 'risk', label: '嚴重度', w: '96px', type: 'risk' },
    { key: 'cvss', label: 'CVSS', w: '66px', type: 'num' },
    { key: 'vpr', label: 'VPR', w: '62px', type: 'num' },
    { key: 'epss', label: 'EPSS', w: '76px', type: 'epss' },
    { key: 'port', label: 'Port', w: '58px' },
    { key: 'name', label: '弱點名稱', w: 'minmax(170px,1.3fr)' },
    { key: 'solution', label: '處理方式', w: 'minmax(200px,1.8fr)' }
  ];
  const DROW_H = 27;
  function dgridTemplate() { return DCOLS.map(c => c.w).join(' '); }

  // ── 風險明細列建構：① 延遲＋快取（只在首次開啟分頁或資料/來源變更時建構）
  //                    ② 排序一次（換排序鍵才重排）  ③ 大量資料分塊建構＋進度 ──
  let _detailBuildSeq = 0;         // 建構序號：新建構會使進行中的舊建構自動放棄
  let _detailBuiltToken = null;    // 已建構的資料識別（dataVersion|viewSource）
  let _detailSortCache = null;     // 已排序的鍵（key:dir）；避免每次篩選重排

  function _detailRecs() { return S.viewSource === 'old' ? (S.old ? S.old.recs : []) : (S.new ? S.new.recs : []); }
  function _detailToken() { return (S.dataVersion || 0) + '|' + S.viewSource; }

  // 將單筆 rec 展開為「每個 CVE 一列」並推入 out（一個 plugin 多個 CVE → 多列）
  function _expandRec(r, out) {
    const base = {
      host: r.host, risk: r.risk, riskLevel: r.riskLevel, cvss: r.cvss, vpr: r.vpr, epss: r.epss,
      port: r.port, protocol: r.protocol || '', name: r.name, solution: r.solution || '', synopsis: r.synopsis || '',
      description: r.description || '', pluginOutput: r.pluginOutput || '', seeAlso: r.seeAlso || '',
      dnsName: r.dnsName || '', os: r.os || '', mac: r.mac || '',
      disposition: r.disposition || '', exception: r.exception || '', owner: r.owner || '', note: r.note || ''
    };
    const cves = String(r.cve || '').split(/[,;\s]+/).filter(c => /^CVE-/i.test(c)).map(c => c.toUpperCase());
    if (cves.length) { for (const cve of cves) out.push(Object.assign({ cve, _hay: (cve + ' ' + r.host + ' ' + r.name).toLowerCase() }, base)); }
    else { out.push(Object.assign({ cve: '—', _hay: (r.host + ' ' + r.name).toLowerCase() }, base)); }
  }

  // 使快取失效（資料或來源變更時）；下次開啟分頁會重建
  function invalidateDetail() { _detailBuiltToken = null; }

  // 確保 detailRows 已依目前資料/來源建構；完成後呼叫 done。>3000 筆時分塊建構並於計數處顯示進度。
  function ensureDetailRows(done) {
    const token = _detailToken();
    if (_detailBuiltToken === token && Array.isArray(S.detailRows)) { done(); return; }
    const recs = _detailRecs(), N = recs.length, out = [], CHUNK = 2000, my = ++_detailBuildSeq;
    const finish = () => { S.detailRows = out; _detailBuiltToken = token; _detailSortCache = null; done(); };
    if (N <= 3000) { for (const r of recs) _expandRec(r, out); finish(); return; }
    let i = 0; const count = $('#d-count');
    const step = () => {
      if (my !== _detailBuildSeq) return;                 // 被較新的建構取代 → 放棄
      const end = Math.min(N, i + CHUNK);
      for (; i < end; i++) _expandRec(recs[i], out);
      if (i < N) { if (count) count.textContent = `整理明細中… ${Math.round(i / N * 100)}%`; requestAnimationFrame(step); }
      else finish();
    };
    if (count) count.textContent = '整理明細中… 0%';
    requestAnimationFrame(step);
  }

  // 開啟/刷新風險明細分頁：延遲建構完成後套用篩選
  function openDetail() {
    $('#detail-expand').hidden = true;
    ensureDetailRows(() => applyDetailFilter());
  }

  // 風險明細矩陣的篩選設定（與差異比對共用同一套下拉複選機制）
  const detailFilterCfg = {
    id: 'detail', cols: DCOLS,
    headEl: () => $('#dthead'), gridTemplate: () => dgridTemplate(),
    rows: () => S.detailRows, getState: () => S.detailColFilters,
    apply: () => applyDetailFilter(),
    sortActive: (c) => S.detailSort.key === c.key, sortArrow: () => S.detailSort.dir > 0 ? '▲' : '▼',
    onSort: (c) => {
      if (S.detailSort.key === c.key) S.detailSort.dir = -S.detailSort.dir;
      else { S.detailSort.key = c.key; S.detailSort.dir = (c.type === 'num' || c.type === 'epss') ? -1 : 1; }
      applyDetailFilter(); buildDetailHeader();
    }
  };
  function buildDetailHeader() { buildMatrixHeader(detailFilterCfg); }

  // 只在排序鍵/方向改變時，對整份 detailRows 重排一次（O(N log N)）
  function sortDetailBase() {
    const key = S.detailSort.key, dir = S.detailSort.dir;
    S.detailRows.sort((a, b) => {
      let av = key === 'risk' ? a.riskLevel : a[key], bv = key === 'risk' ? b.riskLevel : b[key];
      if (av == null) av = -Infinity; if (bv == null) bv = -Infinity;
      if (typeof av === 'string' && typeof bv === 'string') return dir * av.localeCompare(bv);
      return dir * (av > bv ? 1 : av < bv ? -1 : 0);
    });
    _detailSortCache = key + ':' + dir;
  }
  function applyDetailFilter() {
    if (!Array.isArray(S.detailRows)) S.detailRows = [];
    const sk = S.detailSort.key + ':' + S.detailSort.dir;
    if (_detailSortCache !== sk) sortDetailBase();     // 排序一次；篩選沿用已排序順序，不再每次重排
    const colF = activeColFilters(detailFilterCfg);
    const out = [];
    for (const r of S.detailRows) if (rowPassesColFilters(colF, r)) out.push(r);   // 已是排序後順序
    S.detailFiltered = out;
    $('#d-count').textContent = `${fmt(out.length)} 筆（共 ${fmt(S.detailRows.length)}）`;
    renderDetailVirtual();
  }

  let dScrollBound = false;
  function renderDetailVirtual() {
    const viewport = $('#dviewport'), spacer = $('#dspacer'), emptyEl = $('#detail-empty');
    spacer.style.height = (S.detailFiltered.length * DROW_H) + 'px';
    emptyEl.hidden = S.detailFiltered.length > 0;
    if (!dScrollBound) { viewport.addEventListener('scroll', paintDetailRows, { passive: true }); dScrollBound = true; }
    viewport.scrollTop = 0; paintDetailRows();
  }
  // 模組層級：即時讀取 S.detailFiltered，避免捕捉過期 total 導致捲到底渲染不到
  function paintDetailRows() {
    const viewport = $('#dviewport'), rowsEl = $('#drows');
    const total = S.detailFiltered.length;
    const stp = viewport.scrollTop, vh = viewport.clientHeight;
    const start = Math.max(0, Math.floor(stp / DROW_H) - 4);
    const end = Math.min(total, Math.ceil((stp + vh) / DROW_H) + 4);
    rowsEl.style.transform = `translateY(${start * DROW_H}px)`;
    const tmpl = dgridTemplate(), frag = document.createDocumentFragment();
    for (let i = start; i < end; i++) frag.appendChild(makeDetailRow(S.detailFiltered[i], tmpl));
    rowsEl.replaceChildren(frag);
  }

  function makeDetailRow(r, tmpl) {
    const row = document.createElement('div'); row.className = 'vrow clickable'; row.style.gridTemplateColumns = tmpl; row.style.height = DROW_H + 'px';
    row.addEventListener('click', () => openDetailExpand(r));
    for (const c of DCOLS) {
      const td = document.createElement('div');
      td.className = 'td' + (c.type === 'num' || c.type === 'epss' ? ' num' : '');
      if (c.type === 'risk') { const p = document.createElement('span'); p.className = 'pill risk-' + r.risk; p.textContent = r.risk; td.appendChild(p); }
      else if (c.type === 'epss') td.textContent = r.epss == null ? '—' : (r.epss * 100).toFixed(1) + '%';
      else if (c.type === 'num') td.textContent = r[c.key] == null ? '—' : r[c.key];
      else { const v = r[c.key]; td.textContent = (v === '' || v == null) ? '—' : v; if (c.key === 'name' || c.key === 'solution' || c.key === 'cve') td.title = v || ''; }
      row.appendChild(td);
    }
    return row;
  }

  function openDetailExpand(r) {
    const box = $('#detail-expand'); box.hidden = false; box.replaceChildren();
    const head = document.createElement('div'); head.className = 'hd-head';
    const title = document.createElement('div'); title.className = 'hd-title'; title.textContent = `${r.cve} · ${r.host}`;
    const close = document.createElement('button'); close.className = 'hd-close'; close.textContent = '✕'; close.title = '關閉';
    close.addEventListener('click', () => { box.hidden = true; });
    head.appendChild(title); head.appendChild(close); box.appendChild(head);
    const meta = document.createElement('div'); meta.className = 'hd-meta';
    const portTxt = (r.port || '—') + (r.protocol ? ' / ' + r.protocol : '');
    meta.textContent = `嚴重度 ${r.risk} · CVSS ${r.cvss == null ? '—' : r.cvss} · VPR ${r.vpr == null ? '—' : r.vpr} · EPSS ${r.epss == null ? '—' : (r.epss * 100).toFixed(1) + '%'} · Port ${portTxt}`;
    box.appendChild(meta);
    function section(label, text, pre) {
      if (text == null || text === '') return;
      const wrap = document.createElement('div'); wrap.className = 'hd-sec';
      const l = document.createElement('div'); l.className = 'hd-label'; l.textContent = label;
      const t = document.createElement('div'); if (pre) t.className = 'hd-pre'; t.textContent = text;
      wrap.appendChild(l); wrap.appendChild(t); box.appendChild(wrap);
    }
    // 資產資訊（DNS / OS / MAC）合併一行呈現
    const asset = [r.dnsName && ('DNS：' + r.dnsName), r.os && ('OS：' + r.os), r.mac && ('MAC：' + r.mac)].filter(Boolean).join('　');
    if (asset) section('資產資訊', asset);
    section('弱點名稱', r.name);
    if (r.synopsis) section('摘要', r.synopsis);
    section('說明（Description）', r.description);
    section('處理方式（Solution）', r.solution);
    section('Plugin Output', r.pluginOutput, true);
    section('參考（See Also）', r.seeAlso);
    // 處理狀態 / 例外 / 負責人 / 備註（正式報告追蹤欄位）
    const track = [r.disposition && ('處理狀態：' + r.disposition), r.exception && ('例外原因：' + r.exception), r.owner && ('負責人：' + r.owner), r.note && ('備註：' + r.note)].filter(Boolean).join('　');
    if (track) section('處理追蹤', track);
    box.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }

  // 準備風險明細（資料載入後呼叫；DOM 於切到分頁時渲染）。資料來源由全域 S.viewSource 決定。
  function prepDetail() {
    $('#detail-expand').hidden = true;
    buildDetailHeader();
    invalidateDetail();                       // 標記需重建；實際展開延遲到「開啟該分頁」時才做
    S.detailFiltered = [];
    $('#d-count').textContent = '—';
    if ($('#tab-detail').classList.contains('active')) openDetail();  // 若正停在該分頁則立即刷新
  }

  // 全域資料來源切換（基準/當前）→ 驅動風險圖表單一來源圖與風險明細；差異比對維持對比不受影響
  function switchViewSource(src) {
    if (src === 'old' && !(S.old && S.old.recs.length)) return; // 無基準則忽略
    if (src === 'new' && !(S.new && S.new.recs.length)) return;
    S.viewSource = src;
    $$('#src-toggle .seg').forEach(b => b.classList.toggle('active', b.dataset.view === src));
    if (S.stats && $('#tab-charts').classList.contains('active')) renderCharts();
    if (S.stats && $('#tab-detail').classList.contains('active')) openDetail(); // token 含 viewSource，會自動重建
  }
  function syncSourceToggle() {
    const oldBtn = $('#src-toggle .seg[data-view="old"]'), newBtn = $('#src-toggle .seg[data-view="new"]');
    if (!oldBtn) return;
    oldBtn.disabled = !(S.old && S.old.recs.length);
    newBtn.disabled = !(S.new && S.new.recs.length);
    $$('#src-toggle .seg').forEach(b => b.classList.toggle('active', b.dataset.view === S.viewSource));
  }

  // ---------------------------------------------------------------------------
  // 10. KPI
  // ---------------------------------------------------------------------------
  function deltaSpan(delta) {
    const s = document.createElement('div');
    if (delta > 0) { s.className = 'd up'; s.textContent = '▲ +' + fmt(delta) + ' vs 舊版'; }
    else if (delta < 0) { s.className = 'd down'; s.textContent = '▼ ' + fmt(delta) + ' vs 舊版'; }
    else { s.className = 'd flat'; s.textContent = '＝ 無變化'; }
    return s;
  }
  function card(k, v, deltaNode) {
    const c = document.createElement('div'); c.className = 'stat-card';
    const kk = document.createElement('div'); kk.className = 'k'; kk.textContent = k;
    const vv = document.createElement('div'); vv.className = 'v'; vv.textContent = v;
    c.appendChild(kk); c.appendChild(vv);
    if (deltaNode) c.appendChild(deltaNode);
    return c;
  }
  function renderKPI(st) {
    const grid = $('#stat-grid'); grid.replaceChildren();
    const diff = st.mode === 'diff';
    grid.appendChild(card('新版弱點總數', fmt(st.newTotal), diff ? deltaSpan(st.newTotal - st.oldTotal) : null));
    grid.appendChild(card('受影響主機', fmt(st.newHosts), diff ? deltaSpan(st.newHosts - st.oldHosts) : null));
    if (diff) {
      grid.appendChild(card('🔴 本次新增', fmt(st.added), null));
      grid.appendChild(card('🟢 本次修復', fmt(st.removed), null));
    }
    grid.appendChild(card('Critical', fmt(st.newSev.Critical), diff ? deltaSpan(st.newSev.Critical - st.oldSev.Critical) : null));
    grid.appendChild(card('High', fmt(st.newSev.High), diff ? deltaSpan(st.newSev.High - st.oldSev.High) : null));
    if (diff) grid.appendChild(card('本次新增 CVE 數', fmt(st.newCVEs), null));
  }

  // ---------------------------------------------------------------------------
  // 11. 匯出（Electron 原生另存 / 瀏覽器下載）＋ CSV 防公式注入
  // ---------------------------------------------------------------------------
  const csvCell = NCore.csvCell; // 防公式注入（定義於 core.js）
  async function saveOutput(defaultName, ext, content) {
    try {
      if (window.desktop && window.desktop.saveFile) {
        const res = await window.desktop.saveFile(defaultName, ext, content);
        if (res && res.ok) { Log.info(`已匯出：${res.path}`); return true; }
        if (res && res.canceled) { Log.info('匯出已取消'); return false; }
        Log.error('匯出失敗：' + (res && res.error ? res.error : '未知錯誤')); return false;
      }
      // 瀏覽器備援：Blob 下載
      const mime = ext === 'html' ? 'text/html' : (ext === 'csv' ? 'text/csv' : 'text/plain');
      const bom = (ext === 'csv' || ext === 'log' || ext === 'txt') ? '﻿' : '';
      const blob = new Blob([bom + content], { type: mime + ';charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `${defaultName}.${ext}`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      Log.info(`已下載：${defaultName}.${ext}`);
      return true;
    } catch (err) { Log.error('匯出例外：' + err.message); return false; }
  }

  function exportDiffCSV() {
    if (!S.filtered.length) { Log.warn('無資料可匯出'); toast('目前沒有資料可匯出', 'warn'); return; }
    const header = ['Status', 'Host', 'PluginID', 'Name', 'Risk', 'Port', 'Protocol', 'CVSS', 'VPR', 'EPSS', 'CVE', 'PreviousRisk'];
    const lines = [header.map(csvCell).join(',')];
    for (const r of S.filtered) {
      lines.push([STATUS_LABEL[r.status] || r.status, r.host, r.pluginId, r.name, r.risk, r.port, r.protocol,
        r.cvss, r.vpr, r.epss == null ? '' : r.epss, r.cve, r.oldRisk || ''].map(csvCell).join(','));
    }
    saveOutput('nessus-diff-' + tsName(), 'csv', lines.join('\r\n'));
  }

  function tsName() { const d = new Date(); const p = n => String(n).padStart(2, '0'); return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`; }

  // ---------------------------------------------------------------------------
  // 12. 報表（HTML，含內嵌 SVG 圖表）
  // ---------------------------------------------------------------------------
  function serialize(svg) { return svg ? new XMLSerializer().serializeToString(svg) : ''; }

  function buildReport() {
    const st = S.stats;
    const title = $('#r-title').value.trim() || 'Nessus 弱點掃描比對報告';
    const org = $('#r-org').value.trim();
    const owner = $('#r-owner').value.trim();
    const notes = $('#r-notes').value.trim();
    const opt = {
      exec: $('#r-exec').checked, severity: $('#r-severity').checked, diffchart: $('#r-diffchart').checked,
      quadrant: $('#r-quadrant').checked, priority: $('#r-priority').checked, findings: $('#r-findings').checked,
      useFilter: $('#r-findings-filter').checked, highOnly: $('#r-findings-highonly').checked,
      track: $('#r-findings-track').checked
    };
    const now = new Date().toLocaleString('zh-TW');

    let body = '';
    body += `<h1>${escapeXml(title)}</h1>`;
    // 報表來源與產製資訊（來源檔名、掃描時間、產生時間、負責人）——正式報告可追溯性
    let metaLine = '';
    if (org) metaLine += '單位／專案：' + escapeXml(org) + ' · ';
    if (owner) metaLine += '負責人：' + escapeXml(owner) + ' · ';
    metaLine += '產生時間：' + escapeXml(now);
    body += `<p class="meta">${metaLine}</p>`;
    const oScan = S.scanTime && S.scanTime.old, nScan = S.scanTime && S.scanTime.new;
    body += `<p class="meta">舊版來源：${escapeXml(S.old ? S.old.name : '（無）')}${oScan ? '（掃描時間：' + escapeXml(oScan) + '）' : ''}` +
      ` · 新版來源：${escapeXml(S.new ? S.new.name : '（無）')}${nScan ? '（掃描時間：' + escapeXml(nScan) + '）' : ''}</p>`;
    if (notes) body += `<p class="note">備註：${escapeXml(notes)}</p>`;

    if (opt.exec) {
      body += `<h2>執行摘要</h2><div class="kpis">`;
      const kpi = (k, v) => `<div class="kpi"><div class="k">${escapeXml(k)}</div><div class="v">${escapeXml(v)}</div></div>`;
      body += kpi('新版弱點總數', fmt(st.newTotal));
      body += kpi('受影響主機', fmt(st.newHosts));
      if (st.mode === 'diff') { body += kpi('本次新增', fmt(st.added)); body += kpi('本次修復', fmt(st.removed)); }
      body += kpi('Critical', fmt(st.newSev.Critical));
      body += kpi('High', fmt(st.newSev.High));
      if (st.mode === 'diff') body += kpi('新增 CVE 數', fmt(st.newCVEs));
      const top = S.hostPriority[0];
      body += kpi('最高優先主機', top ? `${top.host}（${top.score.toFixed(2)}）` : '—');
      body += `</div>`;
      if (st.mode === 'diff') {
        body += `<p class="note">相較舊版，弱點總數${st.newTotal - st.oldTotal >= 0 ? '增加' : '減少'} ${Math.abs(st.newTotal - st.oldTotal)} 筆；` +
          `新增 ${st.added} 筆、修復 ${st.removed} 筆、持續存在 ${st.persistent} 筆、屬性變更 ${st.changed} 筆。</p>`;
      }
    }
    if (opt.severity) body += `<h2>漏洞總數與各嚴重度比較（舊版 vs 新版）</h2><div class="chart">${serialize(chartTotalsCompare(st))}</div><div class="chart">${serialize(chartSeverity(st.oldSev, st.newSev, st.mode))}</div>`;
    if (opt.diffchart && st.mode === 'diff') body += `<h2>差異總覽</h2><div class="chart">${serialize(chartDiff(st))}</div>`;
    if (opt.quadrant) {
      const xLabel = S.qx === 'vpr' ? 'VPR' : 'EPSS';
      body += `<h2>CVSS ×（${xLabel}）優先處理四象限</h2><p class="note">縱軸＝CVSS v2.0，橫軸＝${xLabel}；右上角（高嚴重度＋高${xLabel}）為最該優先處理者。</p><div class="chart">${serialize(chartQuadrant({ xKey: S.qx, mode: S.qmode, forReport: true }))}</div>`;
    }
    if (opt.priority) {
      body += `<h2>優先處理主機（Top 20）</h2>` + priorityTableHTML(S.hostPriority.slice(0, 20));
    }
    if (opt.findings) {
      let rows = opt.useFilter ? S.filtered : S.rows;
      if (opt.highOnly) rows = rows.filter(r => r.riskLevel >= 3);
      // 報表明細上限，避免產出過大檔案
      const CAP = 3000; let capped = false;
      if (rows.length > CAP) { rows = sortRows(rows.slice()).slice(0, CAP); capped = true; }
      body += `<h2>弱點明細${opt.highOnly ? '（僅 Critical / High）' : ''}${opt.useFilter ? '（套用目前篩選）' : ''}</h2>`;
      if (capped) body += `<p class="note">資料量大，僅列出風險最高的前 ${CAP} 筆。</p>`;
      body += findingsTableHTML(rows, opt.track);
    }

    const css = `
      body{font-family:"Segoe UI","Microsoft JhengHei",sans-serif;color:#1a2233;margin:32px;line-height:1.5}
      h1{font-size:24px;border-bottom:3px solid #4f8cff;padding-bottom:8px}
      h2{font-size:17px;margin-top:28px;color:#243049;border-left:4px solid #4f8cff;padding-left:8px}
      .meta{color:#667;font-size:12px}.note{color:#667;font-size:12px}
      .kpis{display:flex;flex-wrap:wrap;gap:12px;margin:12px 0}
      .kpi{border:1px solid #dde3ee;border-radius:8px;padding:10px 16px;min-width:120px}
      .kpi .k{font-size:11px;color:#778}.kpi .v{font-size:22px;font-weight:700}
      .chart{max-width:720px;margin:8px 0}svg{width:100%;height:auto;border:1px solid #eef1f7;border-radius:8px;background:#fff}
      table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}
      th,td{border:1px solid #e3e8f2;padding:5px 8px;text-align:left}th{background:#f2f5fb}
      td.num{text-align:right}
      .r-Critical{color:#c81e4b;font-weight:700}.r-High{color:#d9611c;font-weight:700}.r-Medium{color:#9a7d00}.r-Low{color:#1c7ea1}.r-Info{color:#667}
      .s-added{color:#c81e4b}.s-removed{color:#0a8f6b}.s-changed{color:#9a7d00}.s-persistent{color:#667}
      @media print{h2{page-break-after:avoid}tr{page-break-inside:avoid}}
    `;
    return `<!DOCTYPE html><html lang="zh-Hant"><head><meta charset="UTF-8"><title>${escapeXml(title)}</title><style>${css}</style></head><body>${body}<footer style="margin-top:32px;color:#99a;font-size:11px;border-top:1px solid #eee;padding-top:8px">由 Nessus Diff 產生 · 離線工具</footer></body></html>`;
  }

  function priorityTableHTML(list) {
    const diff = S.stats.mode === 'diff';
    let h = `<table><thead><tr><th>主機 / IP</th><th class="num">優先分數</th><th class="num">最高VPR</th><th class="num">最高EPSS</th><th class="num">緊急</th><th class="num">Critical</th><th class="num">High</th><th class="num">弱點數</th>${diff ? '<th class="num">本次新增</th>' : ''}</tr></thead><tbody>`;
    for (const d of list) {
      h += `<tr><td>${escapeXml(d.host)}</td><td class="num">${d.score.toFixed(2)}</td><td class="num">${d.maxVpr ? d.maxVpr.toFixed(1) : '—'}</td><td class="num">${d.maxEpss ? (d.maxEpss * 100).toFixed(1) + '%' : '—'}</td><td class="num">${d.urgent}</td><td class="num">${d.crit}</td><td class="num">${d.high}</td><td class="num">${d.count}</td>${diff ? '<td class="num">' + d.added + '</td>' : ''}</tr>`;
    }
    return h + '</tbody></table>';
  }
  function findingsTableHTML(rows, track) {
    const diff = S.stats.mode === 'diff';
    let h = `<table><thead><tr>${diff ? '<th>狀態</th>' : ''}<th>主機 / IP</th><th>Plugin</th><th>弱點名稱</th><th>嚴重度</th><th>Port</th><th class="num">VPR</th><th class="num">EPSS</th><th>CVE</th>${track ? '<th>處理狀態</th><th>負責人</th>' : ''}</tr></thead><tbody>`;
    for (const r of rows) {
      h += `<tr>${diff ? '<td class="s-' + r.status + '">' + escapeXml(STATUS_LABEL[r.status] || r.status) + '</td>' : ''}<td>${escapeXml(r.host)}</td><td>${escapeXml(r.pluginId)}</td><td>${escapeXml(r.name)}</td><td class="r-${r.risk}">${escapeXml(r.risk)}</td><td>${escapeXml(r.port)}</td><td class="num">${r.vpr == null ? '—' : r.vpr}</td><td class="num">${r.epss == null ? '—' : (r.epss * 100).toFixed(1) + '%'}</td><td>${escapeXml(r.cve)}</td>${track ? '<td>' + escapeXml(r.disposition || '—') + '</td><td>' + escapeXml(r.owner || '—') + '</td>' : ''}</tr>`;
    }
    return h + '</tbody></table>';
  }

  // ---------------------------------------------------------------------------
  // 13. 範例 CSV
  // ---------------------------------------------------------------------------
  function sampleCSV() {
    const header = ['Plugin ID', 'CVE', 'CVSS v2.0 Base Score', 'CVSS v3.0 Base Score', 'Risk', 'Host', 'Protocol', 'Port', 'Name', 'Synopsis', 'Solution', 'VPR Score', 'EPSS Score'];
    const rows = [
      ['19506', '', '', '', 'None', '192.168.1.10', 'tcp', '0', 'Nessus Scan Information', 'Info about the scan.', 'n/a', '', ''],
      ['153953', 'CVE-2021-44228', '9.3', '10.0', 'Critical', '192.168.1.10', 'tcp', '8080', 'Apache Log4j RCE (Log4Shell)', 'Remote code execution.', 'Upgrade Log4j to 2.17.1.', '9.8', '0.975'],
      ['42873', 'CVE-2013-2566', '4.3', '', 'Medium', '192.168.1.10', 'tcp', '443', 'SSL RC4 Cipher Suites Supported', 'Weak cipher.', 'Disable RC4.', '4.4', '0.012'],
      ['51192', 'CVE-2016-2183', '5.0', '7.5', 'High', '192.168.1.20', 'tcp', '3389', 'SSL Certificate Cannot Be Trusted', 'Untrusted cert.', 'Install a trusted cert.', '6.7', '0.31'],
      ['104743', 'CVE-2017-0144', '9.3', '8.1', 'Critical', '192.168.1.20', 'tcp', '445', 'MS17-010 EternalBlue SMB', 'Remote code execution via SMBv1.', 'Apply MS17-010 patches.', '9.6', '0.94']
    ];
    return [header.map(csvCell).join(',')].concat(rows.map(r => r.map(csvCell).join(','))).join('\r\n');
  }

  // ---------------------------------------------------------------------------
  // 14. UI：分頁 / 匯入 / 事件
  // ---------------------------------------------------------------------------
  function busy(on, text) {
    const b = $('#busy'); if (text) $('#busy-text').textContent = text;
    $('#busy-progress').hidden = true; $('#busy-cancel').hidden = true; $('#busy-sub').textContent = '';
    b.hidden = !on;
  }
  function showProgress(on, slot, fname) {
    const b = $('#busy');
    if (!on) { b.hidden = true; return; }
    $('#busy-text').textContent = `讀取${slot === 'old' ? '舊版' : '新版'}掃描：${fname}`;
    $('#busy-bar').style.width = '0%'; $('#busy-progress').hidden = false;
    $('#busy-sub').textContent = '0%'; $('#busy-cancel').hidden = false;
    b.hidden = false;
  }
  function updateProgress(frac, rows) {
    const pct = Math.round(Math.min(1, frac) * 100);
    $('#busy-bar').style.width = pct + '%';
    $('#busy-sub').textContent = `${pct}%　已讀 ${fmt(rows)} 列`;
  }
  function toast(msg, kind) { const m = $('#import-msg'); m.className = 'import-msg' + (kind ? ' ' + kind : ''); m.textContent = msg; }

  function switchTab(name) {
    $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
    $$('.tabpane').forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
    if (name === 'charts') renderCharts();
    if (name === 'diff' && S.stats) paintDiffRows();       // 以正確視窗高度重繪（首次渲染時分頁可能隱藏、高度為 0）
    if (name === 'detail' && S.stats) openDetail();        // 切到分頁時才建構（延遲）並以正確視窗高度重繪
    if (name === 'log') Log.rerender();
  }

  let pendingSlot = null;
  function pickFile(slot) { pendingSlot = slot; $('#file-input').value = ''; $('#file-input').click(); }

  const MAX_IMPORT_BYTES = 200 * 1024 * 1024; // 檔案大小上限 200 MB
  const raf = () => new Promise(r => requestAnimationFrame(() => r()));

  function handleFile(slot, file) {
    if (!file) return;
    if (!/\.csv$/i.test(file.name) && file.type && file.type.indexOf('csv') === -1) {
      toast('請選擇 .csv 檔案（Nessus 匯出）', 'error'); Log.warn('拒絕非 CSV 檔：' + file.name); return;
    }
    if (file.size > MAX_IMPORT_BYTES) {
      toast(`檔案過大：${(file.size / 1048576).toFixed(0)} MB，上限 ${MAX_IMPORT_BYTES / 1048576} MB。`, 'error');
      Log.error(`拒絕超大檔：${file.name}（${(file.size / 1048576).toFixed(0)} MB）`); return;
    }
    readAndParse(slot, file);
  }

  // 串流分塊讀取 + 解析：不阻塞 UI、顯示進度、可取消
  async function readAndParse(slot, file) {
    S.cancelImport = false;
    Log.info(`開始匯入（${slot === 'old' ? '舊版' : '新版'}）：${file.name}（${(file.size / 1024).toFixed(0)} KB）`);
    showProgress(true, slot, file.name);
    const t0 = performance.now();
    const rawRows = [];
    const parser = NCore.createStreamParser(r => rawRows.push(r));
    const dec = new TextDecoder('utf-8');
    const total = file.size || 1; let read = 0, lastPaint = 0;
    try {
      const reader = file.stream().getReader();
      while (true) {
        if (S.cancelImport) { try { await reader.cancel(); } catch (e) { } Log.warn('使用者取消匯入：' + file.name); showProgress(false); return; }
        const { done, value } = await reader.read();
        if (done) break;
        read += value.byteLength;
        parser.push(dec.decode(value, { stream: true }));
        const now = performance.now();
        if (now - lastPaint > 60) { lastPaint = now; updateProgress(read / total, rawRows.length); await raf(); }
      }
      parser.push(dec.decode()); parser.end();
    } catch (err) {
      Log.error('讀取/解析失敗：' + err.message); toast('讀取檔案失敗：' + err.message, 'error'); showProgress(false); return;
    }
    updateProgress(1, rawRows.length);
    Log.info(`串流讀取完成：${rawRows.length} 列、耗時 ${(performance.now() - t0).toFixed(0)}ms`);
    // 讓進度畫面收尾後再做正規化與重算
    setTimeout(() => {
      try { finishImport(slot, file.name, rawRows); }
      catch (err) { Log.error('解析例外：' + err.message); toast('解析失敗：' + err.message, 'error'); }
      finally { showProgress(false); }
    }, 20);
  }

  function finishImport(slot, fname, raw) {
    if (!raw.length) { toast('CSV 沒有內容（空檔）', 'error'); Log.warn('空 CSV：' + fname); return; }
    const headers = raw[0];
    const map = mapColumns(headers);
    const missingReq = REQUIRED.filter(k => map[k] < 0);
    if (missingReq.length) {
      const found = headers.map(h => String(h).trim()).filter(Boolean).join(', ');
      const need = missingReq.map(k => k === 'host' ? 'Host / IP Address' : 'Plugin ID').join('、');
      toast(`缺少必要欄位：${need}。請確認為 Nessus 匯出的 CSV（可點「下載範例 CSV」對照）。偵測到的欄位：${found.slice(0, 200)}`, 'error');
      Log.error(`匯入失敗：缺必要欄位 ${missingReq.join(',')}；表頭=[${headers.join(' | ')}]`);
      return;
    }
    const t0 = performance.now();
    const { recs, skipped, issues, issueCount, dupes } = normalize(raw, map);
    if (!recs.length) { toast('CSV 無有效資料列（皆缺 Host/Plugin ID）', 'error'); Log.warn('無有效列：' + fname); return; }
    const missingOpt = [];
    for (const k of ['name', 'risk', 'port', 'vpr', 'epss', 'cve']) if (map[k] < 0) missingOpt.push(k);
    S[slot] = { name: fname, recs, map, missingOpt, issueCount, dupes };
    S.scanTime[slot] = NCore.extractScanTime(recs);

    Log.info(`正規化完成（${slot === 'old' ? '舊版' : '新版'}）：${recs.length} 筆、${new Set(recs.map(r => r.host)).size} 台主機、耗時 ${(performance.now() - t0).toFixed(0)}ms`);
    if (skipped) Log.warn(`略過 ${skipped} 列（缺 Host 或 Plugin ID）`);
    if (dupes) Log.warn(`偵測到 ${dupes} 筆重複（相同 Host/Plugin/Port/Protocol）`);
    if (issueCount) { Log.warn(`數值異常 ${issueCount} 處，已標記為缺值（不夾值）`); issues.slice(0, 30).forEach(it => Log.warn(`  第 ${it.line} 列 ${it.field}="${it.raw}" → ${it.reason}`)); }
    if (missingOpt.length) Log.warn(`選用欄位缺少：${missingOpt.join(', ')}（相關圖表/欄位將降級顯示）`);

    const dz = $(slot === 'old' ? '#dz-old' : '#dz-new');
    dz.classList.add('loaded');
    $('[data-role=filename]', dz).textContent = `✓ ${fname}（${recs.length} 筆）`;

    let msg = `已載入 ${slot === 'old' ? '舊版' : '新版'}掃描：${recs.length} 筆。`;
    const notes = [];
    if (dupes) notes.push(`${dupes} 筆重複`);
    if (issueCount) notes.push(`${issueCount} 處數值異常已標記`);
    if (missingOpt.includes('vpr') || missingOpt.includes('epss')) notes.push('缺 ' + ['vpr', 'epss'].filter(x => missingOpt.includes(x)).map(x => x.toUpperCase()).join('/') + '（圖表降級）');
    if (notes.length) msg += ' 註：' + notes.join('；') + '（詳見執行 Log）。';
    toast(msg, notes.length ? 'warn' : 'ok');

    recompute();
  }

  function recompute() {
    const t0 = performance.now();
    const oldRecs = S.old ? S.old.recs : [];
    const newRecs = S.new ? S.new.recs : [];
    S.rows = NCore.computeRows(oldRecs, newRecs);
    S.stats = NCore.computeStats(oldRecs, newRecs, S.rows);
    S.hostPriority = NCore.computeHostPriority(oldRecs, newRecs, S.rows);
    S.prioritySort = { key: 'score', dir: -1 };

    // 差異表搜尋預建小寫索引（大資料量時省每鍵重算）
    for (const r of S.rows) r._hay = (r.host + ' ' + r.name + ' ' + r.cve + ' ' + r.pluginId).toLowerCase();
    Log.info(`比對計算完成：${S.rows.length} 筆差異列，耗時 ${(performance.now() - t0).toFixed(0)}ms（新增 ${S.stats.added}／修復 ${S.stats.removed}／持續 ${S.stats.persistent}／變更 ${S.stats.changed}）`);

    // 顯示總覽
    $('#overview-empty').hidden = true;
    $('#overview-body').hidden = false;
    renderKPI(S.stats);
    renderOverviewCharts();
    renderPriorityTable('#overview-priority', S.hostPriority, 10);

    // 差異表
    buildHeader();
    S.sortKey = 'priority'; S.sortDir = -1;
    applyFilterSort();

    // 全域資料來源：有當前預設當前，否則用基準（每次匯入重設）
    S.viewSource = (S.new && S.new.recs.length) ? 'new' : 'old';
    syncSourceToggle();

    // 風險明細分頁（延遲建構：只標記需重建 + 計數，實際展開於切到該分頁時才做）
    S.dataVersion = (S.dataVersion || 0) + 1;   // 資料變更 → 明細快取失效
    prepDetail();

    // 風險圖表 IP 篩選（預設全選）；若正處於圖表分頁則即時重繪
    initIpFilter();
    if ($('#tab-charts').classList.contains('active')) renderCharts();
  }

  function renderOverviewCharts() {
    $('#chart-severity').replaceChildren(chartSeverity(S.stats.oldSev, S.stats.newSev, S.stats.mode));
    $('#chart-diff').replaceChildren(chartDiff(S.stats));
  }
  function renderCharts() {
    if (!S.stats) return;
    hideTip();
    // 依 IP 篩選即時計算本分頁圖表的資料集（未選任何主機 → 顯示提示，不畫）
    const sel = S.chartHosts;
    const allHosts = S.hostPriority.length;
    const useAll = sel.size === allHosts && allHosts > 0;
    const keep = r => useAll || sel.has(r.host);
    const oldRecs = (S.old ? S.old.recs : []).filter(keep);
    const newRecs = (S.new ? S.new.recs : []).filter(keep);
    const rows = useAll ? S.rows : S.rows.filter(keep);
    const stats = NCore.computeStats(oldRecs, newRecs, rows);
    // 單一來源圖（四象限/熱力圖/Top 主機）依全域資料來源；比較圖（總數/嚴重度）仍用兩份對比
    const srcNew = S.viewSource === 'new';
    const recs = srcNew ? newRecs : oldRecs;
    const priority = NCore.computeHostPriority(srcNew ? [] : oldRecs, srcNew ? newRecs : [], rows);

    const empty = (sel.size === 0 && allHosts > 0);
    if (empty) {
      ['#chart-quadrant', '#chart-totals', '#chart-heatmap', '#chart-severity2', '#chart-tophosts'].forEach(s => {
        const el = $(s); el.replaceChildren(); const d = document.createElement('div'); d.className = 'empty-state small'; d.textContent = '未選取任何主機，請於上方「IP 篩選」勾選。'; el.appendChild(d);
      });
      return;
    }
    $('#chart-quadrant').replaceChildren(chartQuadrant({
      xKey: S.qx, mode: S.qmode, addedOnly: $('#q-added-only').checked,
      xThresh: num($('#q-xthresh').value), yThresh: num($('#q-ythresh').value),
      recs, rows
    }));
    $('#chart-totals').replaceChildren(chartTotalsCompare(stats));
    $('#chart-heatmap').replaceChildren(chartHeatmap(priority, S.heatMetric));
    $('#chart-severity2').replaceChildren(chartSeverity(stats.oldSev, stats.newSev, stats.mode));
    $('#chart-tophosts').replaceChildren(chartTopHosts(priority));
    // 標示各圖資料來源
    const single = chartSourceLabel();
    setText('#src-quadrant', '資料來源：' + single);
    setText('#src-heatmap', '資料來源：' + single);
    setText('#src-tophosts', '資料來源：' + single);
    const both = (S.stats.mode === 'diff') ? '資料來源：舊版 vs 新版（對比）' : '資料來源：' + single;
    setText('#src-totals', both);
    setText('#src-severity', both);
  }
  function setText(sel, txt) { const el = $(sel); if (el) el.textContent = txt; }
  // 單一資料集圖表的來源（依全域 viewSource）
  function chartSourceLabel() {
    if (S.viewSource === 'old' && S.old && S.old.recs.length) return `舊版掃描（${S.old.name}）`;
    if (S.viewSource === 'new' && S.new && S.new.recs.length) return `新版掃描（${S.new.name}）`;
    if (S.new && S.new.recs.length) return `新版掃描（${S.new.name}）`;
    if (S.old && S.old.recs.length) return `舊版掃描（${S.old.name}）`;
    return '—';
  }

  // --- 風險圖表 IP 多選篩選器 ---
  const scheduleChartRender = debounce(renderCharts, 150);

  function ipToNum(host) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(host).trim());
    if (!m) return -1; // 非 IPv4 → 降序時排最後
    return (+m[1]) * 16777216 + (+m[2]) * 65536 + (+m[3]) * 256 + (+m[4]);
  }
  function sortedHostList() {
    const arr = S.hostPriority.slice();
    if (S.ipSort === 'ip') arr.sort((a, b) => ipToNum(b.host) - ipToNum(a.host) || b.host.localeCompare(a.host));
    else arr.sort((a, b) => b.score - a.score); // 風險降序
    return arr;
  }
  function updateIpButton() {
    const total = S.hostPriority.length, sel = S.chartHosts.size;
    const btn = $('#ip-ms-btn');
    btn.textContent = (total > 0 && sel === total) ? `全部主機（${fmt(total)}）▾` : `已選 ${fmt(sel)} / ${fmt(total)} 台 ▾`;
    const sc = $('#ip-selcount'); if (sc) sc.textContent = `已選 ${fmt(sel)} / ${fmt(total)}`;
  }
  function buildIpFilter() {
    const list = $('#ip-ms-list'); list.replaceChildren();
    const q = $('#ip-ms-search').value.trim().toLowerCase();
    let arr = sortedHostList();
    if (q) arr = arr.filter(h => h.host.toLowerCase().indexOf(q) !== -1);
    const CAP = 500; let capped = false;
    if (arr.length > CAP) { arr = arr.slice(0, CAP); capped = true; }
    const frag = document.createDocumentFragment();
    for (const h of arr) {
      const row = document.createElement('label'); row.className = 'ms-row';
      const cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = S.chartHosts.has(h.host);
      cb.addEventListener('change', () => { if (cb.checked) S.chartHosts.add(h.host); else S.chartHosts.delete(h.host); updateIpButton(); scheduleChartRender(); });
      const dot = document.createElement('span'); dot.className = 'ms-dot'; dot.style.background = h.crit ? RISK_COLORS.Critical : (h.high ? RISK_COLORS.High : RISK_COLORS.Medium);
      const ip = document.createElement('span'); ip.className = 'ms-ip'; ip.textContent = h.host;
      const sc = document.createElement('span'); sc.className = 'ms-score'; sc.textContent = h.score.toFixed(2);
      row.appendChild(cb); row.appendChild(dot); row.appendChild(ip); row.appendChild(sc);
      frag.appendChild(row);
    }
    list.appendChild(frag);
    if (capped) { const m = document.createElement('div'); m.className = 'ms-more'; m.textContent = `僅顯示前 ${CAP} 台，請用搜尋縮小範圍。`; list.appendChild(m); }
    updateIpButton();
  }
  function toggleIpPanel(show) {
    const panel = $('#ip-ms-panel'), btn = $('#ip-ms-btn');
    const willShow = (show != null) ? show : panel.hidden;
    panel.hidden = !willShow; btn.setAttribute('aria-expanded', String(willShow));
    if (willShow) buildIpFilter();
  }
  // 資料載入後初始化 IP 篩選（預設全選）
  function initIpFilter() {
    S.chartHosts = new Set(S.hostPriority.map(h => h.host));
    updateIpButton();
    if ($('#ip-ms-panel') && !$('#ip-ms-panel').hidden) buildIpFilter();
  }

  // ---------------------------------------------------------------------------
  // 15. 綁定事件
  // ---------------------------------------------------------------------------
  function bind() {
    // 分頁
    $$('.tab').forEach(t => t.addEventListener('click', () => switchTab(t.dataset.tab)));

    // 拖放區
    ['dz-old', 'dz-new'].forEach(id => {
      const dz = $('#' + id), slot = dz.dataset.slot;
      dz.addEventListener('click', () => pickFile(slot));
      dz.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pickFile(slot); } });
      dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('dragover'); });
      dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
      dz.addEventListener('drop', e => {
        e.preventDefault(); dz.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files[0]) handleFile(slot, e.dataTransfer.files[0]);
      });
    });
    $('#file-input').addEventListener('change', e => { if (e.target.files[0]) handleFile(pendingSlot, e.target.files[0]); });
    $('#busy-cancel').addEventListener('click', () => { S.cancelImport = true; });

    // 篩選
    // 差異比對：篩選全部改由各欄標題的下拉複選；此按鈕清空所有欄位篩選
    $('#f-reset').addEventListener('click', () => {
      S.colFilters = {};
      applyFilterSort();
      buildHeader();            // 重建標題列以清空篩選控制項與標記
    });

    // 圖表控制
    ['#q-xthresh', '#q-ythresh'].forEach(s => $(s).addEventListener('input', debounce(renderCharts, 200)));
    $('#q-added-only').addEventListener('change', renderCharts);
    // 聚合切換（弱點 / 主機）
    $$('#tab-charts .viewtoggle .seg[data-qmode]').forEach(b => b.addEventListener('click', () => {
      S.qmode = b.dataset.qmode;
      $$('#tab-charts .viewtoggle .seg[data-qmode]').forEach(x => x.classList.toggle('active', x === b));
      renderCharts();
    }));
    // 熱力圖指標切換（Σ VPR / Σ EPSS）→ 只重繪熱力圖
    $$('#tab-charts .viewtoggle .seg[data-heat]').forEach(b => b.addEventListener('click', () => {
      S.heatMetric = b.dataset.heat;
      $$('#tab-charts .viewtoggle .seg[data-heat]').forEach(x => x.classList.toggle('active', x === b));
      if (S.stats) renderCharts();
    }));
    // 橫軸切換（EPSS / VPR）→ 同步門檻輸入的範圍與預設值
    $$('#tab-charts .viewtoggle .seg[data-qx]').forEach(b => b.addEventListener('click', () => {
      S.qx = b.dataset.qx;
      $$('#tab-charts .viewtoggle .seg[data-qx]').forEach(x => x.classList.toggle('active', x === b));
      const xt = $('#q-xthresh');
      if (S.qx === 'vpr') { xt.max = '10'; xt.step = '0.5'; xt.value = '7'; }
      else { xt.max = '1'; xt.step = '0.05'; xt.value = '0.5'; }
      renderCharts();
    }));

    // IP 篩選（風險圖表）
    $('#ip-ms-btn').addEventListener('click', (e) => { e.stopPropagation(); toggleIpPanel(); });
    $('#ip-ms-panel').addEventListener('click', (e) => e.stopPropagation());
    document.addEventListener('click', () => { if (!$('#ip-ms-panel').hidden) toggleIpPanel(false); });
    $('#ip-ms-search').addEventListener('input', debounce(buildIpFilter, 150));
    $('#ip-all').addEventListener('click', () => { S.chartHosts = new Set(S.hostPriority.map(h => h.host)); buildIpFilter(); scheduleChartRender(); });
    $('#ip-none').addEventListener('click', () => { S.chartHosts.clear(); buildIpFilter(); scheduleChartRender(); });
    $$('#ip-ms-panel .viewtoggle .seg').forEach(b => b.addEventListener('click', () => {
      S.ipSort = b.dataset.ipsort;
      $$('#ip-ms-panel .viewtoggle .seg').forEach(x => x.classList.toggle('active', x === b));
      buildIpFilter();
    }));

    // 全域資料來源切換（基準/當前）
    $$('#src-toggle .seg').forEach(b => b.addEventListener('click', () => switchViewSource(b.dataset.view)));

    // 風險明細分頁：篩選全部改由各欄標題的下拉複選；此按鈕清空所有欄位篩選
    $('#d-reset').addEventListener('click', () => {
      S.detailColFilters = {};
      applyDetailFilter();
      buildDetailHeader();
    });

    // 匯出
    $('#btn-export-csv').addEventListener('click', exportDiffCSV);
    $('#btn-sample').addEventListener('click', () => saveOutput('nessus-sample', 'csv', sampleCSV()));

    // 報表
    $('#btn-report').addEventListener('click', () => {
      if (!S.stats) { toast('請先匯入資料', 'warn'); return; }
      busy(true, '產生報表中…');
      setTimeout(() => { try { saveOutput('nessus-report-' + tsName(), 'html', buildReport()); } catch (e) { Log.error('報表產生失敗：' + e.message); } finally { busy(false); } }, 30);
    });
    $('#btn-report-preview').addEventListener('click', () => {
      if (!S.stats) { toast('請先匯入資料', 'warn'); return; }
      try {
        const html = buildReport();
        const w = window.open('', '_blank');
        if (w) { w.document.open(); w.document.write(html); w.document.close(); }
        else toast('無法開啟預覽視窗（請改用「產出 HTML 報表」）', 'warn');
      } catch (e) { Log.error('預覽失敗：' + e.message); }
    });

    // Log
    $('#log-level').addEventListener('change', Log.rerender);
    $('#btn-log-export').addEventListener('click', () => saveOutput('nessus-diff-' + tsName(), 'log', Log.toText()));
    $('#btn-log-clear').addEventListener('click', Log.clear);
  }

  // ---------------------------------------------------------------------------
  // 16. 啟動
  // ---------------------------------------------------------------------------
  document.addEventListener('DOMContentLoaded', () => {
    bind();
    Log.info('Nessus Diff 啟動' + (window.desktop && window.desktop.isDesktop ? '（Electron 桌面模式）' : '（瀏覽器模式）'));
    Log.info('提示：所有資料僅存於記憶體，關閉視窗即釋放；本工具不做任何持久化。');
  });
})();
