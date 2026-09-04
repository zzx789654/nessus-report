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

  // CSV 解析（RFC4180：引號、"" 跳脫、內嵌逗號/換行、BOM、CRLF/LF）
  function parseCSV(text) {
    const rows = [];
    let row = [], field = '', inQ = false;
    let i = 0; const n = text.length;
    if (n && text.charCodeAt(0) === 0xFEFF) i = 1;
    while (i < n) {
      const c = text[i];
      if (inQ) {
        if (c === '"') {
          if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
          inQ = false; i++; continue;
        }
        field += c; i++; continue;
      }
      if (c === '"') { inQ = true; i++; continue; }
      if (c === ',') { row.push(field); field = ''; i++; continue; }
      if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; continue; }
      if (c === '\r') { row.push(field); rows.push(row); row = []; field = ''; i += (text[i + 1] === '\n') ? 2 : 1; continue; }
      field += c; i++;
    }
    if (field.length > 0 || row.length > 0) { row.push(field); rows.push(row); }
    return rows.filter(r => !(r.length === 1 && r[0] === ''));
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
    epss:     ['epss score', 'epss']
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

  function normalize(rawRows, map) {
    const recs = [];
    let skipped = 0;
    const get = (r, key) => (map[key] >= 0 ? (r[map[key]] || '') : '');
    for (let k = 1; k < rawRows.length; k++) {
      const r = rawRows[k];
      const host = String(get(r, 'host')).trim();
      const pid = String(get(r, 'pluginId')).trim();
      if (!host || !pid) { skipped++; continue; }
      const cvss = num(get(r, 'cvss3')) != null ? num(get(r, 'cvss3')) : num(get(r, 'cvss2'));
      const risk = normRisk(get(r, 'risk'), cvss);
      recs.push({
        host, pluginId: pid,
        name: String(get(r, 'name')).trim() || ('Plugin ' + pid),
        risk, riskLevel: RISK_LEVEL[risk] || 0,
        cve: String(get(r, 'cve')).trim(),
        port: String(get(r, 'port')).trim(),
        protocol: String(get(r, 'protocol')).trim().toLowerCase(),
        cvss, vpr: num(get(r, 'vpr')), epss: num(get(r, 'epss'))
      });
    }
    return { recs, skipped };
  }

  function findingKey(rec) { return rec.pluginId + '|' + rec.port + '|' + rec.protocol; }

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

  function mkRow(rec, status, oldRec) {
    return {
      host: rec.host, pluginId: rec.pluginId, port: rec.port, protocol: rec.protocol,
      name: rec.name, risk: rec.risk, riskLevel: rec.riskLevel, cve: rec.cve,
      cvss: rec.cvss, vpr: rec.vpr, epss: rec.epss, status,
      oldRisk: oldRec ? oldRec.risk : null,
      priority: (rec.vpr != null && rec.epss != null) ? (rec.vpr / 10) * rec.epss : 0
    };
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
              const changed = (o.risk !== n.risk) || (o.vpr !== n.vpr) || (o.epss !== n.epss);
              rows.push(mkRow(n, changed ? 'changed' : 'persistent', o));
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
    const cveSet = new Set();
    for (const row of rows) {
      if (row.status === 'added' && row.cve) {
        String(row.cve).split(/[,;\s]+/).forEach(c => { if (/^CVE-/i.test(c)) cveSet.add(c.toUpperCase()); });
      }
    }
    st.newCVEs = cveSet.size;
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
      if (!h) { h = { host: r.host, score: 0, maxVpr: 0, maxEpss: 0, urgent: 0, crit: 0, high: 0, count: 0, added: addedByHost.get(r.host) || 0 }; map.set(r.host, h); }
      h.count++;
      if (r.vpr != null) h.maxVpr = Math.max(h.maxVpr, r.vpr);
      if (r.epss != null) { h.maxEpss = Math.max(h.maxEpss, r.epss); anyEpss = true; }
      if (r.vpr != null && r.epss != null) { h.score += (r.vpr / 10) * r.epss; if (r.vpr >= 7 && r.epss >= 0.5) h.urgent++; }
      if (r.risk === 'Critical') h.crit++; else if (r.risk === 'High') h.high++;
    }
    const arr = Array.from(map.values());
    // 降級：整份無 EPSS 時，改以嚴重度 + VPR + 弱點量做排序分數（保證有弱點即 > 0）
    if (!anyEpss) for (const h of arr) h.score = h.crit * 3 + h.high * 2 + h.maxVpr / 10 + h.count * 0.05;
    arr.sort((a, b) => b.score - a.score);
    return arr;
  }

  return {
    escapeXml, num, parseCSV, COLDEF, REQUIRED, mapColumns, RISK_LEVEL,
    normRisk, normalize, findingKey, csvCell, buildIndex, mkRow,
    computeRows, severityCounts, computeStats, computeHostPriority,
    subnetOf, computeSubnetAggregation
  };
});
