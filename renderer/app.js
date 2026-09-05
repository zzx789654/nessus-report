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
    prioritySort: { key: 'score', dir: -1 },
    stats: null,
    hostPriority: [],
    // 大資料量：主機聚合 / 網段彙總 / 明細索引
    rowsByHost: new Map(),
    subnets: [],
    hview: 'host',
    hostSort: { key: 'score', dir: -1 },
    hostFiltered: [],
    selectedHost: null,
    qmode: 'finding',
    qx: 'epss',  // 四象限橫軸：'epss' 或 'vpr'（縱軸固定 CVSS v2.0）
    // 風險圖表的 IP 篩選（多選）；為所選主機集合，size===主機總數 表示全選
    chartHosts: new Set(),
    ipSort: 'risk'  // IP 選單排序：'risk'（風險降序）或 'ip'（IP 降序）
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
  const RISK_COLORS = { Critical: '#ff4d6d', High: '#ff8c42', Medium: '#ffd23f', Low: '#4cc9f0', Info: '#7d8aa8' };

  function chartSeverity(oldSev, newSev, mode) {
    const cats = ['Critical', 'High', 'Medium', 'Low', 'Info'];
    const W = 600, H = 300, pad = { l: 40, r: 16, t: 20, b: 40 };
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
        if (nv) svg.appendChild(svgEl('text', { x: gx + 2 + barW / 2, y: y(nv) - 4, 'text-anchor': 'middle', class: 'bar-label' }, nv));
      } else {
        const nv = newSev[c] || 0;
        svg.appendChild(svgEl('rect', { x: gx - barW / 2, y: y(nv), width: barW, height: pad.t + plotH - y(nv), fill: RISK_COLORS[c], rx: 2 }));
        if (nv) svg.appendChild(svgEl('text', { x: gx, y: y(nv) - 4, 'text-anchor': 'middle', class: 'bar-label' }, nv));
      }
      svg.appendChild(svgEl('text', { x: gx, y: H - pad.b + 16, 'text-anchor': 'middle' }, c));
    });
    if (twoBars) {
      svg.appendChild(svgEl('rect', { x: pad.l, y: 4, width: 10, height: 10, fill: '#888', opacity: 0.45 }));
      svg.appendChild(svgEl('text', { x: pad.l + 14, y: 13 }, '基準'));
      svg.appendChild(svgEl('rect', { x: pad.l + 60, y: 4, width: 10, height: 10, fill: '#888' }));
      svg.appendChild(svgEl('text', { x: pad.l + 74, y: 13 }, '當前'));
    }
    return svg;
  }

  function chartDiff(st) {
    const items = st.mode === 'diff'
      ? [['新增', st.added, '#ff4d6d'], ['已修復', st.removed, '#2dd4a7'], ['持續', st.persistent, '#8892a8'], ['變更', st.changed, '#ffd23f']]
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
    const W = 640, H = 320, pad = { l: 44, r: 16, t: 24, b: 52 };
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
      svg.appendChild(svgEl('rect', { x: pad.l, y: 6, width: 10, height: 10, fill: '#888', opacity: 0.42 }));
      svg.appendChild(svgEl('text', { x: pad.l + 14, y: 15 }, '基準'));
      svg.appendChild(svgEl('rect', { x: pad.l + 60, y: 6, width: 10, height: 10, fill: '#888' }));
      svg.appendChild(svgEl('text', { x: pad.l + 74, y: 15 }, '當前'));
    }
    return svg;
  }

  function chartTopHosts(priority) {
    const top = priority.slice(0, 10);
    const W = 600, rowH = 26, H = Math.max(120, top.length * rowH + 40), pad = { l: 130, r: 40, t: 10, b: 20 };
    const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'xMidYMid meet', role: 'img' });
    if (!top.length) { svg.appendChild(svgEl('text', { x: W / 2, y: H / 2, 'text-anchor': 'middle' }, '無資料')); return svg; }
    const maxV = Math.max(0.0001, ...top.map(h => h.score));
    const plotW = W - pad.l - pad.r;
    top.forEach((h, i) => {
      const yy = pad.t + i * rowH;
      const w = (h.score / maxV) * plotW;
      const color = h.crit ? RISK_COLORS.Critical : (h.high ? RISK_COLORS.High : RISK_COLORS.Medium);
      svg.appendChild(svgEl('text', { x: pad.l - 8, y: yy + rowH / 2 + 3, 'text-anchor': 'end' }, h.host.length > 20 ? h.host.slice(0, 19) + '…' : h.host));
      svg.appendChild(svgEl('rect', { x: pad.l, y: yy + 4, width: Math.max(1, w), height: rowH - 10, fill: color, rx: 2 }));
      svg.appendChild(svgEl('text', { x: pad.l + Math.max(1, w) + 5, y: yy + rowH / 2 + 3, class: 'bar-label' }, h.score.toFixed(2)));
    });
    return svg;
  }

  // 軸定義（定義域上限、標題、刻度格式、預設門檻）
  const AXES = {
    epss:  { max: 1,  label: 'EPSS（被利用機率）', tick: v => v.toFixed(1), th: 0.5 },
    vpr:   { max: 10, label: 'VPR（漏洞優先分數）', tick: v => String(v), th: 7 },
    cvss2: { max: 10, label: 'CVSS v2.0', tick: v => String(v), th: 7 },
    cvss3: { max: 10, label: 'CVSS v3.0（v2.0 缺）', tick: v => String(v), th: 7 }
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
    // 象限背景（右上=優先）
    svg.appendChild(svgEl('rect', { x: X(xThresh), y: pad.t, width: X(xAx.max) - X(xThresh), height: Y(yThresh) - pad.t, fill: 'rgba(255,77,109,0.08)' }));
    // 格線 + Y 刻度
    for (let g = 0; g <= 5; g++) {
      const vy = yAx.max * g / 5, yy = Y(vy);
      svg.appendChild(svgEl('line', { x1: pad.l, y1: yy, x2: W - pad.r, y2: yy, class: 'grid-line' }));
      svg.appendChild(svgEl('text', { x: pad.l - 6, y: yy + 3, 'text-anchor': 'end' }, yAx.tick(Math.round(vy * 10) / 10)));
    }
    // X 刻度
    for (let g = 0; g <= 5; g++) {
      const vx = xAx.max * g / 5, xx = X(vx);
      svg.appendChild(svgEl('text', { x: xx, y: H - pad.b + 16, 'text-anchor': 'middle' }, xAx.tick(Math.round(vx * 100) / 100)));
    }
    // 門檻參考線
    svg.appendChild(svgEl('line', { x1: X(xThresh), y1: pad.t, x2: X(xThresh), y2: pad.t + plotH, class: 'ref-line' }));
    svg.appendChild(svgEl('line', { x1: pad.l, y1: Y(yThresh), x2: W - pad.r, y2: Y(yThresh), class: 'ref-line' }));
    // 點
    for (const p of pts) {
      const cx = X(p.x), cy = Y(p.y), color = RISK_COLORS[p.risk] || '#888';
      let node;
      if (p.added) { const s = 4; node = svgEl('path', { d: `M${cx} ${cy - s}L${cx + s} ${cy}L${cx} ${cy + s}L${cx - s} ${cy}Z`, fill: color, opacity: 0.9 }); }
      else { node = svgEl('circle', { cx, cy, r: 3.2, fill: color, opacity: 0.72 }); }
      const cveLine = p.cve ? `\nCVE: ${p.cve}` : '';
      node.appendChild(svgEl('title', null, `${p.host} · ${p.name}${cveLine}\n${yAx.label} ${p.y} · ${xAx.label} ${p.x}`));
      svg.appendChild(node);
    }
    // 軸標題與象限標籤
    svg.appendChild(svgEl('text', { x: pad.l + plotW / 2, y: H - 6, 'text-anchor': 'middle' }, xAx.label + ' →'));
    svg.appendChild(svgEl('text', { x: 12, y: pad.t + plotH / 2, 'text-anchor': 'middle', transform: `rotate(-90 12 ${pad.t + plotH / 2})` }, yAx.label + ' →'));
    svg.appendChild(svgEl('text', { x: X(xAx.max) - 4, y: pad.t + 14, 'text-anchor': 'end', class: 'quad-label' }, '⚠ 優先處理'));
    if (capped) svg.appendChild(svgEl('text', { x: pad.l + 2, y: pad.t + 12, class: 'quad-label' }, `僅顯示風險最高的 ${MAXPTS} 點`));
    if (missing > 0) svg.appendChild(svgEl('text', { x: pad.l + 2, y: pad.t + (capped ? 26 : 12), class: 'quad-label' }, `${missing} 筆缺 ${xAx.label}/${yAx.label} 未繪`));
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
  function chartHeatmap(priority) {
    const wrap = document.createElement('div');
    if (!priority.length) { wrap.textContent = '（無資料）'; return wrap; }
    const CAP = 600;
    const list = priority.slice(0, CAP);
    const maxScore = Math.max(0.0001, ...list.map(h => h.score));
    const grid = document.createElement('div'); grid.className = 'heatmap-grid';
    for (const h of list) {
      const cell = document.createElement('div'); cell.className = 'heat-cell';
      cell.style.background = heatColor(h.score / maxScore);
      cell.title = `${h.host}\n優先分數 ${h.score.toFixed(2)} · 最高VPR ${h.maxVpr.toFixed(1)} · 最高EPSS ${(h.maxEpss * 100).toFixed(0)}%\nCritical ${h.crit} · High ${h.high} · 弱點 ${h.count}`;
      cell.addEventListener('click', () => { switchTab('priority'); openHostDetail(h.host); });
      cell.style.cursor = 'pointer';
      grid.appendChild(cell);
    }
    wrap.appendChild(grid);
    const legend = document.createElement('div'); legend.className = 'heat-legend';
    legend.appendChild(document.createTextNode('低風險 '));
    const scale = document.createElement('span'); scale.className = 'heat-scale'; legend.appendChild(scale);
    legend.appendChild(document.createTextNode(' 高風險（點格子看主機明細）'));
    wrap.appendChild(legend);
    if (priority.length > CAP) { const more = document.createElement('div'); more.className = 'heat-more'; more.textContent = `共 ${priority.length} 台，僅顯示風險最高的前 ${CAP} 台。`; wrap.appendChild(more); }
    return wrap;
  }

  // ---------------------------------------------------------------------------
  // 8. 差異表（虛擬捲動）
  // ---------------------------------------------------------------------------
  const COLS = [
    { key: 'status', label: '狀態', w: '92px', type: 'status' },
    { key: 'host', label: '主機 / IP', w: '150px' },
    { key: 'pluginId', label: 'Plugin', w: '78px' },
    { key: 'name', label: '弱點名稱', w: 'minmax(200px,1.6fr)' },
    { key: 'risk', label: '嚴重度', w: '96px', type: 'risk' },
    { key: 'port', label: 'Port', w: '64px' },
    { key: 'vpr', label: 'VPR', w: '68px', type: 'num' },
    { key: 'epss', label: 'EPSS', w: '78px', type: 'epss' },
    { key: 'cve', label: 'CVE', w: '150px' }
  ];
  const ROW_H = 34;
  const STATUS_LABEL = { added: '🔴 新增', removed: '🟢 已修復', persistent: '⚪ 持續', changed: '🟡 變更', single: '本份' };

  function gridTemplate() { return COLS.map(c => c.w).join(' '); }

  function buildHeader() {
    const head = $('#vthead');
    head.replaceChildren();
    head.style.gridTemplateColumns = gridTemplate();
    for (const c of COLS) {
      const th = document.createElement('div');
      th.className = 'th';
      th.textContent = c.label;
      if (S.sortKey === c.key) {
        const a = document.createElement('span'); a.className = 'arrow'; a.textContent = S.sortDir > 0 ? '▲' : '▼';
        th.appendChild(a);
      }
      th.addEventListener('click', () => {
        if (S.sortKey === c.key) S.sortDir = -S.sortDir;
        else { S.sortKey = c.key; S.sortDir = (c.type === 'num' || c.type === 'epss') ? -1 : 1; }
        applyFilterSort();
        buildHeader();
      });
      head.appendChild(th);
    }
  }

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

  function applyFilterSort() {
    const q = $('#f-search').value.trim().toLowerCase();
    const fs = $('#f-status').value;
    const fr = $('#f-risk').value;
    const fvpr = num($('#f-vpr').value);
    const fepss = num($('#f-epss').value);
    const hideInfo = $('#f-hideinfo').checked;
    const actionOnly = $('#f-action').checked;
    const out = [];
    for (const r of S.rows) {
      if (hideInfo && r.riskLevel === 0) continue;                       // 收斂：隱藏 Info/None
      if (actionOnly && !(r.status === 'added' || r.status === 'changed' || r.riskLevel >= 3)) continue; // 只看需行動
      if (fs && r.status !== fs) continue;
      if (fr) { if (fr === 'Info') { if (r.risk !== 'Info') continue; } else if (r.risk !== fr) continue; }
      if (fvpr != null && (r.vpr == null || r.vpr < fvpr)) continue;
      if (fepss != null && (r.epss == null || r.epss < fepss)) continue;
      if (q && r._hay.indexOf(q) === -1) continue;                       // 用預建索引，省每鍵重算
      out.push(r);
    }
    // 排序：非明確欄位時預設用 priority
    if (S.sortKey === 'priority') sortRows(out); else sortRows(out);
    S.filtered = out;
    $('#diff-count').textContent = `${fmt(out.length)} 筆（共 ${fmt(S.rows.length)}）`;
    renderVirtual();
  }

  let vScrollBound = false;
  function renderVirtual() {
    const viewport = $('#vviewport'), spacer = $('#vspacer'), rowsEl = $('#vrows'), emptyEl = $('#diff-empty');
    const total = S.filtered.length;
    spacer.style.height = (total * ROW_H) + 'px';
    emptyEl.hidden = total > 0;
    if (!vScrollBound) {
      viewport.addEventListener('scroll', () => paintRows(), { passive: true });
      vScrollBound = true;
    }
    viewport.scrollTop = 0;
    paintRows();

    function paintRows() {
      const scrollTop = viewport.scrollTop;
      const vh = viewport.clientHeight;
      const start = Math.max(0, Math.floor(scrollTop / ROW_H) - 4);
      const end = Math.min(total, Math.ceil((scrollTop + vh) / ROW_H) + 4);
      rowsEl.style.transform = `translateY(${start * ROW_H}px)`;
      const frag = document.createDocumentFragment();
      const tmpl = gridTemplate();
      for (let i = start; i < end; i++) frag.appendChild(makeRow(S.filtered[i], tmpl));
      rowsEl.replaceChildren(frag);
    }
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
        s.textContent = STATUS_LABEL[r.status] || r.status;
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
      { k: 'score', label: '優先分數', num: true, fmt: v => v.toFixed(2), bar: true },
      { k: 'maxVpr', label: '最高VPR', num: true, fmt: v => v ? v.toFixed(1) : '—' },
      { k: 'maxEpss', label: '最高EPSS', num: true, fmt: v => v ? (v * 100).toFixed(1) + '%' : '—' },
      { k: 'urgent', label: '緊急', num: true, hint: 'VPR≥7 且 EPSS≥50%' },
      { k: 'crit', label: 'Critical', num: true },
      { k: 'high', label: 'High', num: true },
      { k: 'count', label: '弱點數', num: true }
    ];
    if (S.stats && S.stats.mode === 'diff') cols.push({ k: 'added', label: '本次新增', num: true });

    const data = priority.slice(0, limit || priority.length);
    const maxScore = Math.max(0.0001, ...data.map(d => d.score));
    const table = document.createElement('table');
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
        if (col.bar) {
          td.className = 'num bar-cell';
          const fill = document.createElement('span'); fill.className = 'bar-fill';
          fill.style.width = Math.round((val / maxScore) * 100) + '%';
          const s = document.createElement('span'); s.className = 'bar-val'; s.textContent = col.fmt(val);
          td.appendChild(fill); td.appendChild(s);
        } else {
          td.textContent = col.fmt ? col.fmt(val) : (val === '' || val == null ? '—' : val);
        }
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    cont.appendChild(table);
  }

  // ---------------------------------------------------------------------------
  // 9b. 優先主機分頁：主機聚合（虛擬捲動）/ 網段彙總 / 明細抽屜
  //     — 針對 300+ IP、上萬筆的收斂與導覽
  // ---------------------------------------------------------------------------
  const HCOLS = [
    { key: 'host', label: '主機 / IP', w: '180px' },
    { key: 'score', label: '優先分數', w: 'minmax(120px,1fr)', type: 'bar' },
    { key: 'maxVpr', label: '最高VPR', w: '84px', type: 'num', fmt: v => v ? v.toFixed(1) : '—' },
    { key: 'maxEpss', label: '最高EPSS', w: '92px', type: 'num', fmt: v => v ? (v * 100).toFixed(1) + '%' : '—' },
    { key: 'urgent', label: '緊急', w: '64px', type: 'num' },
    { key: 'crit', label: 'Critical', w: '78px', type: 'num' },
    { key: 'high', label: 'High', w: '64px', type: 'num' },
    { key: 'count', label: '弱點數', w: '76px', type: 'num' },
    { key: 'added', label: '本次新增', w: '84px', type: 'num', diffOnly: true }
  ];
  const HROW_H = 34;
  function hcols() { return HCOLS.filter(c => !c.diffOnly || (S.stats && S.stats.mode === 'diff')); }
  function hgridTemplate() { return hcols().map(c => c.w).join(' '); }

  function buildHostHeader() {
    const head = $('#hthead'); head.replaceChildren();
    head.style.gridTemplateColumns = hgridTemplate();
    for (const c of hcols()) {
      const th = document.createElement('div'); th.className = 'th'; th.textContent = c.label;
      if (S.hostSort.key === c.key) { const a = document.createElement('span'); a.className = 'arrow'; a.textContent = S.hostSort.dir > 0 ? '▲' : '▼'; th.appendChild(a); }
      th.addEventListener('click', () => {
        if (S.hostSort.key === c.key) S.hostSort.dir = -S.hostSort.dir;
        else { S.hostSort.key = c.key; S.hostSort.dir = (c.type === 'num' || c.type === 'bar') ? -1 : 1; }
        applyHostFilter(); buildHostHeader();
      });
      head.appendChild(th);
    }
  }

  function applyHostFilter() {
    const q = $('#h-search').value.trim().toLowerCase();
    const urgentOnly = $('#h-urgent-only').checked;
    const out = [];
    for (const h of S.hostPriority) {
      if (urgentOnly && !(h.urgent > 0 || h.added > 0)) continue;
      if (q && h.host.toLowerCase().indexOf(q) === -1 && NCore.subnetOf(h.host).toLowerCase().indexOf(q) === -1) continue;
      out.push(h);
    }
    const key = S.hostSort.key, dir = S.hostSort.dir;
    out.sort((a, b) => (typeof a[key] === 'string') ? dir * a[key].localeCompare(b[key]) : dir * ((a[key] > b[key]) ? 1 : (a[key] < b[key] ? -1 : 0)));
    S.hostFiltered = out;
    if (S.hview === 'host') { $('#h-count').textContent = `${fmt(out.length)} 台主機（共 ${fmt(S.hostPriority.length)}）`; renderHostVirtual(); }
    else renderSubnet();
  }

  let hScrollBound = false;
  function renderHostVirtual() {
    const viewport = $('#hviewport'), spacer = $('#hspacer'), rowsEl = $('#hrows');
    const total = S.hostFiltered.length;
    const maxScore = Math.max(0.0001, ...S.hostFiltered.map(h => h.score));
    spacer.style.height = (total * HROW_H) + 'px';
    if (!hScrollBound) { viewport.addEventListener('scroll', paint, { passive: true }); hScrollBound = true; }
    paint();
    function paint() {
      const st = viewport.scrollTop, vh = viewport.clientHeight;
      const start = Math.max(0, Math.floor(st / HROW_H) - 4);
      const end = Math.min(total, Math.ceil((st + vh) / HROW_H) + 4);
      rowsEl.style.transform = `translateY(${start * HROW_H}px)`;
      const tmpl = hgridTemplate(), frag = document.createDocumentFragment();
      for (let i = start; i < end; i++) frag.appendChild(makeHostRow(S.hostFiltered[i], tmpl, maxScore));
      rowsEl.replaceChildren(frag);
    }
  }

  function makeHostRow(h, tmpl, maxScore) {
    const row = document.createElement('div');
    row.className = 'vrow clickable' + (S.selectedHost === h.host ? ' selected' : '');
    row.style.gridTemplateColumns = tmpl; row.style.height = HROW_H + 'px';
    row.addEventListener('click', () => openHostDetail(h.host));
    for (const c of hcols()) {
      const td = document.createElement('div');
      td.className = 'td' + (c.type === 'num' ? ' num' : '');
      if (c.type === 'bar') {
        td.className = 'td num bar-cell';
        const fill = document.createElement('span'); fill.className = 'bar-fill'; fill.style.width = Math.round((h.score / maxScore) * 100) + '%';
        const s = document.createElement('span'); s.className = 'bar-val'; s.textContent = h.score.toFixed(2);
        td.appendChild(fill); td.appendChild(s);
      } else if (c.type === 'num') {
        td.textContent = c.fmt ? c.fmt(h[c.key]) : h[c.key];
        if (c.key === 'urgent' && h.urgent > 0) td.style.color = 'var(--crit)';
        if (c.key === 'added' && h.added > 0) td.style.color = 'var(--added)';
      } else {
        td.textContent = h[c.key]; td.title = h[c.key];
      }
      row.appendChild(td);
    }
    return row;
  }

  function openHostDetail(host) {
    S.selectedHost = host;
    // 標記選中列（僅更新可見列）
    renderHostVirtual();
    const box = $('#host-detail'); box.hidden = false; box.replaceChildren();
    const rows = (S.rowsByHost.get(host) || []).slice().sort((a, b) => b.priority - a.priority || b.riskLevel - a.riskLevel);
    const head = document.createElement('div'); head.className = 'hd-head';
    const title = document.createElement('div'); title.className = 'hd-title';
    title.textContent = `${host} — ${rows.length} 筆弱點（${NCore.subnetOf(host)}）`;
    const close = document.createElement('button'); close.className = 'hd-close'; close.textContent = '✕'; close.title = '關閉';
    close.addEventListener('click', () => { box.hidden = true; S.selectedHost = null; renderHostVirtual(); });
    head.appendChild(title); head.appendChild(close); box.appendChild(head);

    const diff = S.stats && S.stats.mode === 'diff';
    const tbl = document.createElement('div'); tbl.className = 'mini-table';
    const t = document.createElement('table');
    const thead = document.createElement('thead'); const htr = document.createElement('tr');
    (diff ? ['狀態', '弱點名稱', '嚴重度', 'Port', 'VPR', 'EPSS', 'CVE'] : ['弱點名稱', '嚴重度', 'Port', 'VPR', 'EPSS', 'CVE']).forEach(h => { const th = document.createElement('th'); th.textContent = h; htr.appendChild(th); });
    thead.appendChild(htr); t.appendChild(thead);
    const tb = document.createElement('tbody');
    for (const r of rows) {
      const tr = document.createElement('tr');
      const cells = [];
      if (diff) { const c = document.createElement('span'); c.className = 'st-' + r.status; c.textContent = STATUS_LABEL[r.status] || r.status; cells.push(c); }
      cells.push(txt(r.name));
      const pill = document.createElement('span'); pill.className = 'pill risk-' + r.risk; pill.textContent = r.risk; cells.push(pill);
      cells.push(txt(r.port || '—'));
      cells.push(txt(r.vpr == null ? '—' : r.vpr, true));
      cells.push(txt(r.epss == null ? '—' : (r.epss * 100).toFixed(1) + '%', true));
      cells.push(txt(r.cve || '—'));
      for (const cell of cells) { const td = document.createElement('td'); if (typeof cell === 'string') td.textContent = cell; else td.appendChild(cell); tr.appendChild(td); }
      tb.appendChild(tr);
    }
    t.appendChild(tb); tbl.appendChild(t); box.appendChild(tbl);
    box.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    function txt(v) { return String(v); }
  }

  function renderSubnet() {
    const cont = $('#subnet-mode'); cont.replaceChildren();
    const q = $('#h-search').value.trim().toLowerCase();
    const urgentOnly = $('#h-urgent-only').checked;
    let list = S.subnets.filter(s => (!q || s.subnet.toLowerCase().indexOf(q) !== -1) && (!urgentOnly || s.urgent > 0 || s.added > 0));
    $('#h-count').textContent = `${fmt(list.length)} 個網段（共 ${fmt(S.subnets.length)}）`;
    if (!list.length) { cont.textContent = '（無資料）'; return; }
    const diff = S.stats && S.stats.mode === 'diff';
    const maxScore = Math.max(0.0001, ...list.map(s => s.score));
    const table = document.createElement('table');
    const thead = document.createElement('thead'); const htr = document.createElement('tr');
    const cols = [['subnet', '網段 /24', false], ['score', '優先分數', true], ['hosts', '主機數', true], ['urgent', '緊急', true], ['crit', 'Critical', true], ['high', 'High', true], ['count', '弱點數', true]];
    if (diff) cols.push(['added', '本次新增', true]);
    for (const [, label, n] of cols) { const th = document.createElement('th'); th.textContent = label; if (n) th.className = 'num'; htr.appendChild(th); }
    thead.appendChild(htr); table.appendChild(thead);
    const tb = document.createElement('tbody');
    for (const s of list) {
      const tr = document.createElement('tr');
      for (const [k, , n] of cols) {
        const td = document.createElement('td');
        if (k === 'score') {
          td.className = 'num bar-cell';
          const fill = document.createElement('span'); fill.className = 'bar-fill'; fill.style.width = Math.round((s.score / maxScore) * 100) + '%';
          const val = document.createElement('span'); val.className = 'bar-val'; val.textContent = s.score.toFixed(2);
          td.appendChild(fill); td.appendChild(val);
        } else if (k === 'subnet') {
          const a = document.createElement('span'); a.textContent = s.subnet; a.style.cursor = 'pointer'; a.style.color = 'var(--accent)';
          a.title = '點擊：切到主機聚合並篩選此網段';
          a.addEventListener('click', () => { switchHostView('host'); $('#h-search').value = s.subnet.replace('.0/24', '.'); applyHostFilter(); });
          td.appendChild(a);
        } else { td.textContent = s[k]; if (n) td.className = 'num'; if (k === 'urgent' && s.urgent > 0) td.style.color = 'var(--crit)'; }
        tr.appendChild(td);
      }
      tb.appendChild(tr);
    }
    table.appendChild(tb); cont.appendChild(table);
  }

  function switchHostView(view) {
    S.hview = view;
    $$('#tab-priority .viewtoggle .seg').forEach(b => b.classList.toggle('active', b.dataset.hview === view));
    $('#host-mode').hidden = view !== 'host';
    $('#subnet-mode').hidden = view !== 'subnet';
    applyHostFilter();
  }

  // ---------------------------------------------------------------------------
  // 10. KPI
  // ---------------------------------------------------------------------------
  function deltaSpan(delta) {
    const s = document.createElement('div');
    if (delta > 0) { s.className = 'd up'; s.textContent = '▲ +' + fmt(delta) + ' vs 基準'; }
    else if (delta < 0) { s.className = 'd down'; s.textContent = '▼ ' + fmt(delta) + ' vs 基準'; }
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
    grid.appendChild(card('當前弱點總數', fmt(st.newTotal), diff ? deltaSpan(st.newTotal - st.oldTotal) : null));
    grid.appendChild(card('受影響主機', fmt(st.newHosts), diff ? deltaSpan(st.newHosts - st.oldHosts) : null));
    if (diff) {
      grid.appendChild(card('🔴 本次新增', fmt(st.added), null));
      grid.appendChild(card('🟢 本次修復', fmt(st.removed), null));
    }
    grid.appendChild(card('Critical', fmt(st.newSev.Critical), diff ? deltaSpan(st.newSev.Critical - st.oldSev.Critical) : null));
    grid.appendChild(card('High', fmt(st.newSev.High), diff ? deltaSpan(st.newSev.High - st.oldSev.High) : null));
    if (diff) grid.appendChild(card('本次新增 CVE 數', fmt(st.newCVEs), null));
    const top = S.hostPriority[0];
    grid.appendChild(card('最高優先主機', top ? top.host : '—', (function () { const d = document.createElement('div'); d.className = 'd flat'; d.textContent = top ? ('優先分數 ' + top.score.toFixed(2)) : ''; return d; })()));
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
    const opt = {
      exec: $('#r-exec').checked, severity: $('#r-severity').checked, diffchart: $('#r-diffchart').checked,
      quadrant: $('#r-quadrant').checked, priority: $('#r-priority').checked, findings: $('#r-findings').checked,
      useFilter: $('#r-findings-filter').checked, highOnly: $('#r-findings-highonly').checked
    };
    const now = new Date().toLocaleString('zh-TW');

    let body = '';
    body += `<h1>${escapeXml(title)}</h1>`;
    body += `<p class="meta">${org ? '單位／專案：' + escapeXml(org) + ' · ' : ''}產生時間：${escapeXml(now)}`;
    body += ` · 基準：${escapeXml(S.old ? S.old.name : '（無）')} · 當前：${escapeXml(S.new ? S.new.name : '（無）')}</p>`;

    if (opt.exec) {
      body += `<h2>執行摘要</h2><div class="kpis">`;
      const kpi = (k, v) => `<div class="kpi"><div class="k">${escapeXml(k)}</div><div class="v">${escapeXml(v)}</div></div>`;
      body += kpi('當前弱點總數', fmt(st.newTotal));
      body += kpi('受影響主機', fmt(st.newHosts));
      if (st.mode === 'diff') { body += kpi('本次新增', fmt(st.added)); body += kpi('本次修復', fmt(st.removed)); }
      body += kpi('Critical', fmt(st.newSev.Critical));
      body += kpi('High', fmt(st.newSev.High));
      if (st.mode === 'diff') body += kpi('新增 CVE 數', fmt(st.newCVEs));
      const top = S.hostPriority[0];
      body += kpi('最高優先主機', top ? `${top.host}（${top.score.toFixed(2)}）` : '—');
      body += `</div>`;
      if (st.mode === 'diff') {
        body += `<p class="note">相較基準，弱點總數${st.newTotal - st.oldTotal >= 0 ? '增加' : '減少'} ${Math.abs(st.newTotal - st.oldTotal)} 筆；` +
          `新增 ${st.added} 筆、修復 ${st.removed} 筆、持續存在 ${st.persistent} 筆、屬性變更 ${st.changed} 筆。</p>`;
      }
    }
    if (opt.severity) body += `<h2>漏洞總數與各嚴重度比較（基準 vs 當前）</h2><div class="chart">${serialize(chartTotalsCompare(st))}</div><div class="chart">${serialize(chartSeverity(st.oldSev, st.newSev, st.mode))}</div>`;
    if (opt.diffchart && st.mode === 'diff') body += `<h2>差異總覽</h2><div class="chart">${serialize(chartDiff(st))}</div>`;
    if (opt.quadrant) {
      const xLabel = S.qx === 'vpr' ? 'VPR' : 'EPSS';
      body += `<h2>CVSS ×（${xLabel}）優先處理四象限</h2><p class="note">縱軸＝CVSS v2.0，橫軸＝${xLabel}；右上角（高嚴重度＋高${xLabel}）為最該優先處理者。</p><div class="chart">${serialize(chartQuadrant({ xKey: S.qx, mode: S.qmode }))}</div>`;
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
      body += findingsTableHTML(rows);
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
  function findingsTableHTML(rows) {
    const diff = S.stats.mode === 'diff';
    let h = `<table><thead><tr>${diff ? '<th>狀態</th>' : ''}<th>主機 / IP</th><th>Plugin</th><th>弱點名稱</th><th>嚴重度</th><th>Port</th><th class="num">VPR</th><th class="num">EPSS</th><th>CVE</th></tr></thead><tbody>`;
    for (const r of rows) {
      h += `<tr>${diff ? '<td class="s-' + r.status + '">' + escapeXml(STATUS_LABEL[r.status] || r.status) + '</td>' : ''}<td>${escapeXml(r.host)}</td><td>${escapeXml(r.pluginId)}</td><td>${escapeXml(r.name)}</td><td class="r-${r.risk}">${escapeXml(r.risk)}</td><td>${escapeXml(r.port)}</td><td class="num">${r.vpr == null ? '—' : r.vpr}</td><td class="num">${r.epss == null ? '—' : (r.epss * 100).toFixed(1) + '%'}</td><td>${escapeXml(r.cve)}</td></tr>`;
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
  function busy(on, text) { const b = $('#busy'); if (text) $('#busy-text').textContent = text; b.hidden = !on; }
  function toast(msg, kind) { const m = $('#import-msg'); m.className = 'import-msg' + (kind ? ' ' + kind : ''); m.textContent = msg; }

  function switchTab(name) {
    $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
    $$('.tabpane').forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
    if (name === 'charts') renderCharts();
    if (name === 'priority' && S.stats) applyHostFilter(); // 切到分頁時以正確視窗高度重繪
    if (name === 'log') Log.rerender();
  }

  let pendingSlot = null;
  function pickFile(slot) { pendingSlot = slot; $('#file-input').value = ''; $('#file-input').click(); }

  function handleFile(slot, file) {
    if (!file) return;
    if (!/\.csv$/i.test(file.name) && file.type && file.type.indexOf('csv') === -1) {
      toast('請選擇 .csv 檔案（Nessus 匯出）', 'error'); Log.warn('拒絕非 CSV 檔：' + file.name); return;
    }
    busy(true, '讀取檔案中…');
    Log.info(`開始匯入（${slot === 'old' ? '基準' : '當前'}）：${file.name}（${(file.size / 1024).toFixed(0)} KB）`);
    const reader = new FileReader();
    reader.onerror = () => { busy(false); Log.error('讀取檔案失敗：' + file.name); toast('讀取檔案失敗', 'error'); };
    reader.onload = () => {
      // 讓遮罩先繪出，再做較重的解析
      setTimeout(() => {
        try { processCSV(slot, file.name, reader.result); }
        catch (err) { Log.error('解析例外：' + err.message); toast('解析失敗：' + err.message, 'error'); }
        finally { busy(false); }
      }, 30);
    };
    reader.readAsText(file, 'UTF-8');
  }

  function processCSV(slot, fname, text) {
    const t0 = performance.now();
    const raw = parseCSV(text);
    if (!raw.length) { toast('CSV 沒有內容', 'error'); Log.warn('空 CSV：' + fname); return; }
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
    const { recs, skipped } = normalize(raw, map);
    // 記錄缺少的選用欄位
    const missingOpt = [];
    for (const k of ['name', 'risk', 'port', 'vpr', 'epss', 'cve']) if (map[k] < 0) missingOpt.push(k);
    const slotObj = { name: fname, recs, map, missingOpt };
    S[slot] = slotObj;

    const dt = (performance.now() - t0).toFixed(0);
    Log.info(`解析完成（${slot === 'old' ? '基準' : '當前'}）：${recs.length} 筆記錄、${new Set(recs.map(r => r.host)).size} 台主機、耗時 ${dt}ms`);
    if (skipped) Log.warn(`略過 ${skipped} 列（缺 Host 或 Plugin ID）`);
    if (missingOpt.length) Log.warn(`選用欄位缺少：${missingOpt.join(', ')}（相關圖表/欄位將降級顯示）`);

    // 更新拖放區顯示
    const dz = $(slot === 'old' ? '#dz-old' : '#dz-new');
    dz.classList.add('loaded');
    $('[data-role=filename]', dz).textContent = `✓ ${fname}（${recs.length} 筆）`;

    // 匯入訊息（含缺欄位提醒）
    let msg = `已載入 ${slot === 'old' ? '基準' : '當前'}掃描：${recs.length} 筆。`;
    if (missingOpt.includes('vpr') || missingOpt.includes('epss')) msg += ' 註：此份缺少 ' + (['vpr', 'epss'].filter(x => missingOpt.includes(x)).map(x => x.toUpperCase()).join('/')) + '，優先排序圖表會以現有資料降級。';
    toast(msg, missingOpt.length ? 'warn' : 'ok');

    $('#btn-clear').disabled = false;
    recompute();
  }

  function recompute() {
    const t0 = performance.now();
    const oldRecs = S.old ? S.old.recs : [];
    const newRecs = S.new ? S.new.recs : [];
    S.rows = NCore.computeRows(oldRecs, newRecs);
    S.stats = NCore.computeStats(oldRecs, newRecs, S.rows);
    S.hostPriority = NCore.computeHostPriority(oldRecs, newRecs, S.rows);
    S.subnets = NCore.computeSubnetAggregation(S.hostPriority);
    S.prioritySort = { key: 'score', dir: -1 };
    S.hostSort = { key: 'score', dir: -1 };
    S.selectedHost = null;

    // 大資料量優化：一次建好搜尋索引與主機→明細索引，避免每次篩選/展開重算
    S.rowsByHost = new Map();
    for (const r of S.rows) {
      r._hay = (r.host + ' ' + r.name + ' ' + r.cve + ' ' + r.pluginId).toLowerCase();
      let a = S.rowsByHost.get(r.host);
      if (!a) { a = []; S.rowsByHost.set(r.host, a); }
      a.push(r);
    }
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

    // 主機聚合分頁（準備資料 + 計數，實際 DOM 於切到該分頁時渲染）
    S.hview = 'host';
    buildHostHeader();
    applyHostFilter();

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
    // 依 IP 篩選即時計算本分頁圖表的資料集（未選任何主機 → 顯示提示，不畫）
    const sel = S.chartHosts;
    const allHosts = S.hostPriority.length;
    const useAll = sel.size === allHosts && allHosts > 0;
    const keep = r => useAll || sel.has(r.host);
    const oldRecs = (S.old ? S.old.recs : []).filter(keep);
    const newRecs = (S.new ? S.new.recs : []).filter(keep);
    const rows = useAll ? S.rows : S.rows.filter(keep);
    const stats = NCore.computeStats(oldRecs, newRecs, rows);
    const priority = NCore.computeHostPriority(oldRecs, newRecs, rows);
    const recs = newRecs.length ? newRecs : oldRecs;

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
    $('#chart-heatmap').replaceChildren(chartHeatmap(priority));
    $('#chart-severity2').replaceChildren(chartSeverity(stats.oldSev, stats.newSev, stats.mode));
    $('#chart-tophosts').replaceChildren(chartTopHosts(priority));
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

  function clearAll() {
    S.old = null; S.new = null; S.rows = []; S.filtered = []; S.stats = null; S.hostPriority = [];
    S.rowsByHost = new Map(); S.subnets = []; S.hostFiltered = []; S.selectedHost = null;
    S.chartHosts = new Set();
    $('#ip-ms-panel').hidden = true; $('#ip-ms-list').replaceChildren(); $('#ip-ms-btn').textContent = '全部主機 ▾';
    if ($('#ip-ms-search')) $('#ip-ms-search').value = '';
    ['#dz-old', '#dz-new'].forEach(sel => { const dz = $(sel); dz.classList.remove('loaded'); $('[data-role=filename]', dz).textContent = ''; });
    $('#overview-empty').hidden = false; $('#overview-body').hidden = true;
    $('#vrows').replaceChildren(); $('#vspacer').style.height = '0px'; $('#diff-count').textContent = '—';
    $('#diff-empty').hidden = false;
    $('#hrows').replaceChildren(); $('#hspacer').style.height = '0px'; $('#hthead').replaceChildren();
    $('#host-detail').hidden = true; $('#host-detail').replaceChildren(); $('#h-count').textContent = '—';
    ['#chart-quadrant', '#chart-totals', '#chart-heatmap', '#chart-severity2', '#chart-tophosts', '#subnet-mode', '#overview-priority', '#stat-grid'].forEach(s => { const el = $(s); if (el) el.replaceChildren(); });
    $('#btn-clear').disabled = true;
    toast('已清除所有資料，記憶體已釋放。', 'ok');
    Log.info('使用者清除所有資料（記憶體釋放）');
    if (window.gc) { try { window.gc(); } catch (e) { } }
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

    // 篩選
    $('#f-search').addEventListener('input', debounce(applyFilterSort, 180));
    ['#f-status', '#f-risk'].forEach(s => $(s).addEventListener('change', applyFilterSort));
    ['#f-vpr', '#f-epss'].forEach(s => $(s).addEventListener('input', debounce(applyFilterSort, 200)));
    ['#f-hideinfo', '#f-action'].forEach(s => $(s).addEventListener('change', applyFilterSort));
    $('#f-reset').addEventListener('click', () => {
      $('#f-search').value = ''; $('#f-status').value = ''; $('#f-risk').value = ''; $('#f-vpr').value = ''; $('#f-epss').value = '';
      $('#f-hideinfo').checked = true; $('#f-action').checked = false;
      applyFilterSort();
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

    // 優先主機分頁：檢視切換 / 搜尋 / 篩選
    $$('#tab-priority .viewtoggle .seg').forEach(b => b.addEventListener('click', () => switchHostView(b.dataset.hview)));
    $('#h-search').addEventListener('input', debounce(applyHostFilter, 180));
    $('#h-urgent-only').addEventListener('change', applyHostFilter);

    // 匯出
    $('#btn-export-csv').addEventListener('click', exportDiffCSV);
    $('#btn-sample').addEventListener('click', () => saveOutput('nessus-sample', 'csv', sampleCSV()));
    $('#btn-clear').addEventListener('click', clearAll);

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
