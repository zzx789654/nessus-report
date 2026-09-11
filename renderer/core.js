'use strict';
/*
 * Nessus Diff — 核心純邏輯（無 DOM 相依）
 * 解析、欄位對應、正規化、diff、統計、優先分數皆在此，
 * 供 renderer（瀏覽器）與 test（Node）共用同一份程式碼，確保測試涵蓋實際出貨邏輯。
 */
(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api; // Node
  else root.NCore = api;                                                     // 瀏覽器
})(typeof self !== 'undefined' ? self : this, function () {

  function escapeXml(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function num(v) {
    if (v == null || v === '') return null;
    let s = String(v).trim().replace('%', '');
    if (s === '' || s.toLowerCase() === 'n/a') return null;
    const f = parseFloat(s);
    return Number.isFinite(f) ? f : null;
  }

  // EPSS 三種格式：0.97（機率）、97（百分比）、97%（百分比）→ 一律轉 0~1。
  // 超出範圍或非數值 → 回報 issue、值為 null（不夾值，交由上層標記）。
  function parseEpssRaw(raw) {
    const s = String(raw == null ? '' : raw).trim();
    if (s === '' || /^n\/?a$/i.test(s)) return { value: null };
    const hadPct = /%\s*$/.test(s);
    const f = parseFloat(s.replace('%', ''));
    if (!Number.isFinite(f)) return { value: null, issue: 'EPSS 非數值' };
    let v = f;
    if (hadPct || v > 1) v = v / 100;   // 97 或 97% → 0.97；0.97 維持
    if (v < 0 || v > 1) return { value: null, issue: 'EPSS 超出範圍 0~1' };
    return { value: v };
  }
  // VPR / CVSS 分數：域 0~max；超界或非數值 → issue + null（不夾值）。
  function parseScoreRaw(raw, max, label) {
    const s = String(raw == null ? '' : raw).trim();
    if (s === '' || /^n\/?a$/i.test(s)) return { value: null };
    const f = parseFloat(s);
    if (!Number.isFinite(f)) return { value: null, issue: label + ' 非數值' };
    if (f < 0 || f > max) return { value: null, issue: label + ' 超出範圍 0~' + max };
    return { value: f };
  }

  // 可續傳的串流 CSV 解析器（RFC4180；支援跨 chunk 的引號跳脫與 CRLF）。
  // 供大檔分塊/串流解析：push(chunkText) 多次、最後 end()；每完成一列呼叫 onRow(cells)。
  function createStreamParser(onRow) {
    let field = '', row = [], inQ = false, pendingQuote = false, pendingCR = false, first = true;
    function emit() { row.push(field); field = ''; const rr = row; row = []; if (!(rr.length === 1 && rr[0] === '')) onRow(rr); }
    function push(text) {
      let i = 0; const n = text.length;
      if (first) { first = false; if (n && text.charCodeAt(0) === 0xFEFF) i = 1; }
      while (i < n) {
        const c = text[i];
        if (pendingCR) { pendingCR = false; if (c === '\n') { i++; continue; } }
        if (pendingQuote) { pendingQuote = false; if (c === '"') { field += '"'; i++; continue; } inQ = false; }
        if (inQ) {
          if (c === '"') {
            if (i + 1 < n) { if (text[i + 1] === '"') { field += '"'; i += 2; continue; } inQ = false; i++; continue; }
            pendingQuote = true; i++; continue;
          }
          field += c; i++; continue;
        }
        if (c === '"') { inQ = true; i++; continue; }
        if (c === ',') { row.push(field); field = ''; i++; continue; }
        if (c === '\n') { emit(); i++; continue; }
        if (c === '\r') { emit(); if (i + 1 < n) { i += (text[i + 1] === '\n') ? 2 : 1; } else { pendingCR = true; i++; } continue; }
        field += c; i++;
      }
    }
    function end() { if (pendingQuote) inQ = false; if (field.length > 0 || row.length > 0) emit(); }
    return { push, end };
  }

  // 一次性解析（沿用串流核心，確保與分塊路徑行為一致）
  function parseCSV(text) {
    const rows = [];
    const p = createStreamParser(r => rows.push(r));
    p.push(String(text == null ? '' : text));
    p.end();
    return rows;
  }

  const COLDEF = {
    host:     ['host', 'ip address', 'ip', 'asset ip', 'asset', 'dns name', 'fqdn'],
    pluginId: ['plugin id', 'pluginid', 'plugin'],
    name:     ['name', 'plugin name'],
    risk:     ['risk', 'severity', 'risk factor'],
    cve:      ['cve', 'cves'],
    port:     ['port'],
    protocol: ['protocol', 'proto'],
    cvss3:    ['cvss v3.0 base score', 'cvss v3.1 base score', 'cvss v3 base score', 'cvss3 base score'],
    cvss2:    ['cvss v2.0 base score', 'cvss base score', 'cvss'],
    vpr:      ['vpr score', 'vpr', 'vulnerability priority rating'],
    epss:     ['epss score', 'epss'],
    metasploit: ['metasploit', 'metasploit exploit', 'exploited by metasploit'],
    coreImpact: ['core impact', 'coreimpact', 'exploited by core impact'],
    canvas:     ['canvas', 'exploited by canvas'],
    synopsis: ['synopsis'],
    solution: ['solution', 'remediation', 'steps to remediate'],
    description: ['description'],
    pluginOutput: ['plugin output', 'plugin_output', 'output'],
    seeAlso: ['see also', 'see_also', 'xref', 'references'],
    dnsName: ['dns name', 'netbios name', 'fqdn'],
    os: ['operating system', 'os'],
    mac: ['mac address', 'mac'],
    disposition: ['處理狀態', 'remediation status', 'status', 'state', 'disposition'],
    exception: ['例外原因', 'exception reason', 'risk acceptance', 'justification'],
    owner: ['負責人', 'owner', 'assignee', 'assigned to'],
    note: ['備註', 'note', 'notes', 'comment', 'comments']
  };
  const REQUIRED = ['host', 'pluginId'];

  function mapColumns(headers) {
    const norm = headers.map(h => String(h || '').trim().toLowerCase());
    const map = {};
    for (const canon in COLDEF) {
      let idx = -1;
      for (const alias of COLDEF[canon]) { const j = norm.indexOf(alias); if (j !== -1) { idx = j; break; } }
      map[canon] = idx;
    }
    return map;
  }

  const RISK_LEVEL = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0, None: 0 };
  function normRisk(raw, cvss) {
    const s = String(raw || '').trim();
    const low = s.toLowerCase();
    if (low === 'critical') return 'Critical';
    if (low === 'high') return 'High';
    if (low === 'medium') return 'Medium';
    if (low === 'low') return 'Low';
    if (low === 'info' || low === 'informational' || low === 'none' || low === '') {
      if ((low === 'none' || low === '') && cvss != null) {
        if (cvss >= 9) return 'Critical';
        if (cvss >= 7) return 'High';
        if (cvss >= 4) return 'Medium';
        if (cvss > 0) return 'Low';
      }
      return 'Info';
    }
    const nlv = parseInt(low, 10);
    if (!Number.isNaN(nlv)) return ['Info', 'Low', 'Medium', 'High', 'Critical'][Math.max(0, Math.min(4, nlv))];
    return 'Info';
  }

  function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
  // 保留數字版工具（測試/相容）：非法值回 null（不夾值）。
  function normEpss(v) { if (v == null) return null; let x = v > 1 ? v / 100 : v; return (x < 0 || x > 1) ? null : x; }
  function normVpr(v) { if (v == null) return null; return (v < 0 || v > 10) ? null : v; }
  // Nessus 的 Metasploit / Core Impact / CANVAS 欄位以 TRUE/FALSE 標記該框架是否已有可利用模組。
  function parseBool(raw) { const s = String(raw == null ? '' : raw).trim().toLowerCase(); return s === 'true' || s === 't' || s === 'yes' || s === 'y' || s === '1'; }

  // 將 rawRows（含表頭）正規化為記錄陣列，並回報：略過列數、資料問題(issues)、重複列(dupes)。
  // 數值非法值一律標記為 issue 並存 null（不夾到最大值）。
  function normalize(rawRows, map) {
    const recs = [];
    let skipped = 0, issueCount = 0, dupes = 0;
    const issues = [], dupeSamples = [], ISSUE_CAP = 300;
    const seen = new Set();
    const get = (r, key) => (map[key] >= 0 ? (r[map[key]] || '') : '');
    const addIssue = (line, field, raw, reason) => { issueCount++; if (issues.length < ISSUE_CAP) issues.push({ line, field, raw: String(raw).slice(0, 60), reason }); };
    for (let k = 1; k < rawRows.length; k++) {
      const r = rawRows[k]; const line = k + 1;
      const host = String(get(r, 'host')).trim();
      const pid = String(get(r, 'pluginId')).trim();
      if (!host || !pid) { skipped++; continue; }
      const c2 = parseScoreRaw(get(r, 'cvss2'), 10, 'CVSS v2.0'); if (c2.issue) addIssue(line, 'CVSS v2.0', get(r, 'cvss2'), c2.issue);
      const c3 = parseScoreRaw(get(r, 'cvss3'), 10, 'CVSS v3.0'); if (c3.issue) addIssue(line, 'CVSS v3.0', get(r, 'cvss3'), c3.issue);
      const vp = parseScoreRaw(get(r, 'vpr'), 10, 'VPR'); if (vp.issue) addIssue(line, 'VPR', get(r, 'vpr'), vp.issue);
      const ep = parseEpssRaw(get(r, 'epss')); if (ep.issue) addIssue(line, 'EPSS', get(r, 'epss'), ep.issue);
      const cvss = (c3.value != null) ? c3.value : c2.value;
      const risk = normRisk(get(r, 'risk'), cvss);
      const msf = parseBool(get(r, 'metasploit')), coreImp = parseBool(get(r, 'coreImpact')), canv = parseBool(get(r, 'canvas'));
      const rec = {
        host, pluginId: pid,
        metasploit: msf, coreImpact: coreImp, canvas: canv,
        exploited: msf || coreImp || canv,   // 任一 exploit 框架具備可利用模組 → 視為「已武器化」
        name: String(get(r, 'name')).trim() || ('Plugin ' + pid),
        risk, riskLevel: RISK_LEVEL[risk] || 0,
        cve: String(get(r, 'cve')).trim(),
        port: String(get(r, 'port')).trim(),
        protocol: String(get(r, 'protocol')).trim().toLowerCase(),
        cvss, cvss2: c2.value, cvss3: c3.value, vpr: vp.value, epss: ep.value,
        synopsis: String(get(r, 'synopsis')).trim(),
        solution: String(get(r, 'solution')).trim(),
        description: String(get(r, 'description')).trim(),
        pluginOutput: String(get(r, 'pluginOutput')).trim(),
        seeAlso: String(get(r, 'seeAlso')).trim(),
        dnsName: String(get(r, 'dnsName')).trim(),
        os: String(get(r, 'os')).trim(),
        mac: String(get(r, 'mac')).trim(),
        disposition: String(get(r, 'disposition')).trim(),
        exception: String(get(r, 'exception')).trim(),
        owner: String(get(r, 'owner')).trim(),
        note: String(get(r, 'note')).trim()
      };
      const fk = host + '|' + findingKey(rec);
      if (seen.has(fk)) { dupes++; if (dupeSamples.length < 20) dupeSamples.push(fk); }
      else seen.add(fk);
      recs.push(rec);
    }
    return { recs, skipped, issues, issueCount, dupes, dupeSamples };
  }

  function findingKey(rec) { return rec.pluginId + '|' + rec.port + '|' + rec.protocol; }
  // 正規化 CVE 字串（排序去重）供內容比較
  function normCveStr(s) { return String(s || '').split(/[,;\s]+/).filter(x => /^CVE-/i.test(x)).map(x => x.toUpperCase()).sort().join(','); }

  // 掃描時間：由 Nessus「Scan Information」plugin(19506) 的 Plugin Output 盡力擷取
  function extractScanTime(recs) {
    for (const r of recs || []) {
      if (r.pluginId === '19506' && r.pluginOutput) {
        const m = /Scan\s+(?:Start|start)\s+Date\s*:\s*([^\r\n]+)/.exec(r.pluginOutput);
        if (m) return m[1].trim();
      }
    }
    return '';
  }

  // 由主機推導 /24 網段（非 IPv4 歸為「其他」），供 300+ IP 時的網段彙總收斂
  function subnetOf(host) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/.exec(String(host).trim());
    return m ? `${m[1]}.${m[2]}.${m[3]}.0/24` : '其他 / 非 IPv4';
  }

  // 網段彙總：把每台主機的指標依 /24 累加，讓大量 IP 先收斂到「哪個網段最糟」
  function computeSubnetAggregation(hostPriority) {
    const map = new Map();
    for (const h of hostPriority) {
      const key = subnetOf(h.host);
      let s = map.get(key);
      if (!s) { s = { subnet: key, score: 0, crit: 0, high: 0, urgent: 0, added: 0, hosts: 0, count: 0, maxVpr: 0, maxEpss: 0 }; map.set(key, s); }
      s.score += h.score; s.crit += h.crit; s.high += h.high; s.urgent += h.urgent;
      s.added += h.added; s.hosts++; s.count += h.count;
      s.maxVpr = Math.max(s.maxVpr, h.maxVpr); s.maxEpss = Math.max(s.maxEpss, h.maxEpss);
    }
    const arr = Array.from(map.values());
    arr.sort((a, b) => b.score - a.score);
    return arr;
  }

  // CSV 匯出：防公式注入（=,+,-,@,Tab,CR 開頭者前置單引號）＋ 正確跳脫
  function csvCell(v) {
    let s = (v == null) ? '' : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    if (/[",\n\r]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
    return s;
  }

  function buildIndex(recs) {
    const byHost = new Map();
    for (const rec of recs) {
      let m = byHost.get(rec.host);
      if (!m) { m = new Map(); byHost.set(rec.host, m); }
      m.set(findingKey(rec), rec);
    }
    return byHost;
  }

  function mkRow(rec, status, oldRec, changeTypes) {
    return {
      host: rec.host, pluginId: rec.pluginId, port: rec.port, protocol: rec.protocol,
      name: rec.name, risk: rec.risk, riskLevel: rec.riskLevel, cve: rec.cve,
      cvss: rec.cvss, vpr: rec.vpr, epss: rec.epss, status,
      metasploit: !!rec.metasploit, coreImpact: !!rec.coreImpact, canvas: !!rec.canvas, exploited: !!rec.exploited,
      oldRisk: oldRec ? oldRec.risk : null,
      disposition: rec.disposition || '', owner: rec.owner || '',
      changeTypes: changeTypes || [],
      priority: (rec.vpr != null && rec.epss != null) ? (rec.vpr / 10) * rec.epss : 0
    };
  }

  // 區分變更類型：風險(嚴重度) / 分數(VPR/EPSS/CVSS) / CVE / 名稱 / 修補方式
  function classifyChange(o, n) {
    const t = [];
    if (o.risk !== n.risk) t.push('風險');
    if (o.vpr !== n.vpr || o.epss !== n.epss || o.cvss !== n.cvss) t.push('分數');
    if (normCveStr(o.cve) !== normCveStr(n.cve)) t.push('CVE');
    if (o.name !== n.name) t.push('名稱');
    if ((o.solution || '') !== (n.solution || '')) t.push('修補');
    // 可利用性變化：任一 exploit 框架（Metasploit/Core Impact/CANVAS）有無改變
    const expSig = x => (x.metasploit ? 'M' : '') + (x.coreImpact ? 'C' : '') + (x.canvas ? 'V' : '');
    if (expSig(o) !== expSig(n)) t.push('可利用');
    return t;
  }

  // 以 host/IP 為主 Key 的差異計算
  function computeRows(oldRecs, newRecs) {
    const hasOld = oldRecs && oldRecs.length > 0;
    const hasNew = newRecs && newRecs.length > 0;
    const rows = [];
    if (hasOld && hasNew) {
      const oi = buildIndex(oldRecs), ni = buildIndex(newRecs);
      const hosts = new Set([...oi.keys(), ...ni.keys()]);
      for (const host of hosts) {
        const om = oi.get(host), nm = ni.get(host);
        if (om && nm) {
          const keys = new Set([...om.keys(), ...nm.keys()]);
          for (const key of keys) {
            const o = om.get(key), n = nm.get(key);
            if (o && n) {
              const ct = classifyChange(o, n);
              rows.push(mkRow(n, ct.length ? 'changed' : 'persistent', o, ct));
            } else if (n && !o) { rows.push(mkRow(n, 'added', null)); }
            else { rows.push(mkRow(o, 'removed', null)); }
          }
        } else if (nm && !om) { for (const n of nm.values()) rows.push(mkRow(n, 'added', null)); }
        else { for (const o of om.values()) rows.push(mkRow(o, 'removed', null)); }
      }
    } else if (hasNew || hasOld) {
      const one = hasNew ? newRecs : oldRecs;
      for (const rec of one) rows.push(mkRow(rec, 'single', null));
    }
    return rows;
  }

  function severityCounts(recs) {
    const c = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    if (recs) for (const r of recs) c[r.risk] = (c[r.risk] || 0) + 1;
    return c;
  }

  function computeStats(oldRecs, newRecs, rows) {
    oldRecs = oldRecs || []; newRecs = newRecs || [];
    const primary = newRecs.length ? newRecs : oldRecs;
    const st = {
      mode: (oldRecs.length && newRecs.length) ? 'diff' : 'single',
      oldTotal: oldRecs.length, newTotal: newRecs.length,
      oldHosts: new Set(oldRecs.map(r => r.host)).size,
      newHosts: new Set(primary.map(r => r.host)).size,
      oldSev: severityCounts(oldRecs), newSev: severityCounts(primary),
      added: 0, removed: 0, persistent: 0, changed: 0, newCVEs: 0
    };
    for (const row of rows) {
      if (row.status === 'added') st.added++;
      else if (row.status === 'removed') st.removed++;
      else if (row.status === 'persistent') st.persistent++;
      else if (row.status === 'changed') st.changed++;
    }
    // 新增 CVE：以「當前所有弱點的 CVE 集合」減去「基準的 CVE 集合」，
    // 因此涵蓋新增弱點、以及持續弱點內容變更後新出現的 CVE（修正舊版只算 added 的漏算）。
    const cveOf = (rs) => { const s = new Set(); for (const r of rs) if (r.cve) String(r.cve).split(/[,;\s]+/).forEach(c => { if (/^CVE-/i.test(c)) s.add(c.toUpperCase()); }); return s; };
    if (st.mode === 'diff') {
      const oldCve = cveOf(oldRecs), newCve = cveOf(primary);
      let nc = 0; for (const c of newCve) if (!oldCve.has(c)) nc++;
      st.newCVEs = nc;
    } else {
      st.newCVEs = cveOf(primary).size;
    }
    // 內容變更（僅內容、非風險/分數）計數，供報告說明
    st.contentChanged = rows.filter(r => r.status === 'changed' && r.changeTypes && !r.changeTypes.includes('風險') && !r.changeTypes.includes('分數')).length;
    // 可被利用漏洞數（已武器化：任一 exploit 框架具備模組）
    st.exploitable = primary.filter(r => r.exploited).length;
    st.oldExploitable = oldRecs.filter(r => r.exploited).length;
    return st;
  }

  // 主機優先分數：score = Σ (VPR/10 × EPSS)
  function computeHostPriority(oldRecs, newRecs, rows) {
    const recs = (newRecs && newRecs.length) ? newRecs : (oldRecs || []);
    const addedByHost = new Map();
    for (const row of rows) if (row.status === 'added') addedByHost.set(row.host, (addedByHost.get(row.host) || 0) + 1);
    const map = new Map();
    let anyEpss = false;
    for (const r of recs) {
      let h = map.get(r.host);
      if (!h) {
        h = { host: r.host, score: 0, maxVpr: 0, maxEpss: 0, sumVpr: 0, sumEpss: 0, urgent: 0, crit: 0, high: 0, count: 0, added: addedByHost.get(r.host) || 0, sev: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 } };
        map.set(r.host, h);
      }
      h.count++;
      if (r.vpr != null) { h.maxVpr = Math.max(h.maxVpr, r.vpr); h.sumVpr += r.vpr; }
      if (r.epss != null) { h.maxEpss = Math.max(h.maxEpss, r.epss); h.sumEpss += r.epss; anyEpss = true; }
      if (r.vpr != null && r.epss != null) { h.score += (r.vpr / 10) * r.epss; if (r.vpr >= 7 && r.epss >= 0.5) h.urgent++; }
      h.sev[r.risk] = (h.sev[r.risk] || 0) + 1;
      if (r.risk === 'Critical') h.crit++; else if (r.risk === 'High') h.high++;
    }
    const arr = Array.from(map.values());
    // 降級：整份無 EPSS 時，改以嚴重度 + VPR + 弱點量做排序分數（保證有弱點即 > 0）
    if (!anyEpss) for (const h of arr) h.score = h.crit * 3 + h.high * 2 + h.maxVpr / 10 + h.count * 0.05;
    arr.sort((a, b) => b.score - a.score);
    return arr;
  }

  return {
    escapeXml, num, parseCSV, createStreamParser, parseEpssRaw, parseScoreRaw,
    COLDEF, REQUIRED, mapColumns, RISK_LEVEL,
    normRisk, normEpss, normVpr, clamp, normalize, findingKey, normCveStr, extractScanTime,
    csvCell, buildIndex, mkRow, classifyChange,
    computeRows, severityCounts, computeStats, computeHostPriority,
    subnetOf, computeSubnetAggregation
  };
});
