'use strict';
/*
 * Nessus Diff — 核心邏輯測試（Node，零相依）
 * 測試對象即出貨用的 renderer/core.js（同一份程式碼），涵蓋正常/邊界/異常路徑。
 * 執行：npm test  或  node test/run-tests.js
 */
const fs = require('fs');
const path = require('path');
const C = require('../renderer/core.js');

let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name + (extra ? '  → ' + extra : '')); }
}
function eq(name, got, want) { ok(name, got === want, `got=${JSON.stringify(got)} want=${JSON.stringify(want)}`); }

function loadCsv(f) { return fs.readFileSync(path.join(__dirname, '..', 'samples', f), 'utf8'); }
function toRecs(csv) {
  const raw = C.parseCSV(csv);
  const map = C.mapColumns(raw[0]);
  return C.normalize(raw, map);
}

console.log('\n[1] CSV 解析（RFC4180）');
(function () {
  const rows = C.parseCSV('a,b,c\r\n1,"x,y","line1\nline2"\r\n2,"quote""inside",z\n');
  eq('列數', rows.length, 3);
  eq('引號內逗號', rows[1][1], 'x,y');
  eq('引號內換行', rows[1][2], 'line1\nline2');
  eq('雙引號跳脫', rows[2][1], 'quote"inside');
  const bom = C.parseCSV('﻿Host,Plugin ID\n1.1.1.1,100\n');
  eq('去除 BOM', bom[0][0], 'Host');
  const trailing = C.parseCSV('a,b\n1,2\n\n');
  eq('略過整列空白尾列', trailing.length, 2);
})();

console.log('\n[2] 欄位對應與必要欄位');
(function () {
  const m = C.mapColumns(['Plugin ID', 'CVE', 'Risk', 'Host', 'Port', 'VPR Score', 'EPSS Score']);
  ok('對應 host', m.host === 3);
  ok('對應 pluginId', m.pluginId === 0);
  ok('對應 vpr', m.vpr === 5);
  ok('對應 epss', m.epss === 6);
  const alias = C.mapColumns(['IP Address', 'PluginID']);
  ok('別名 IP Address→host', alias.host === 0);
  ok('別名 PluginID→pluginId', alias.pluginId === 1);
  const miss = C.mapColumns(['Foo', 'Bar']);
  const missingReq = C.REQUIRED.filter(k => miss[k] < 0);
  eq('偵測缺必要欄位', missingReq.length, 2);
})();

console.log('\n[3] 正規化 / 風險判定');
(function () {
  const raw = C.parseCSV('Host,Plugin ID,Risk,CVSS v3.0 Base Score,VPR Score,EPSS Score\n' +
    '1.1.1.1,10,Critical,9.8,9.5,0.9\n' +
    '1.1.1.1,11,None,8.5,,\n' +          // 無 Risk → 由 CVSS 推 High
    '1.1.1.1,12,,3.0,,\n' +             // 空 Risk + CVSS3.0 → Low
    ',13,High,,,\n' +                    // 缺 Host → 略過
    '1.1.1.1,,High,,,\n');              // 缺 PluginID → 略過
  const map = C.mapColumns(raw[0]);
  const { recs, skipped } = C.normalize(raw, map);
  eq('有效記錄數', recs.length, 3);
  eq('略過列數', skipped, 2);
  eq('Critical 保留', recs[0].risk, 'Critical');
  eq('None+CVSS9→High? (8.5→High)', recs[1].risk, 'High');
  eq('空Risk+CVSS3→Low', recs[2].risk, 'Low');
  eq('EPSS 解析', recs[0].epss, 0.9);
  eq('百分比 EPSS', C.num('97%'), 97);
  eq('n/a→null', C.num('n/a'), null);
})();

console.log('\n[4] Diff 引擎（固定測試資料）');
// 內建固定 fixture，不依賴 samples/（範例資料可能調整）
const H = 'Plugin ID,CVE,CVSS v2.0 Base Score,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,VPR Score,EPSS Score';
const OLD_CSV = [H,
  '19506,,,,None,192.168.1.10,tcp,0,Scan Info,,',
  '153953,CVE-2021-44228,9.3,10.0,Critical,192.168.1.10,tcp,8080,Log4Shell,9.8,0.975',
  '42873,CVE-2013-2566,4.3,,Medium,192.168.1.10,tcp,443,RC4,4.4,0.012',
  '104743,CVE-2017-0144,9.3,8.1,Critical,192.168.1.20,tcp,445,EternalBlue,9.6,0.94',
  '51192,,,,Medium,192.168.1.20,tcp,3389,SSL Cert,5.9,0.31'
].join('\n');
const NEW_CSV = [H,
  '19506,,,,None,192.168.1.10,tcp,0,Scan Info,,',
  '153953,CVE-2021-44228,9.3,10.0,Critical,192.168.1.10,tcp,8080,Log4Shell,9.8,0.975',
  '156032,CVE-2022-22965,,9.8,Critical,192.168.1.10,tcp,8080,Spring4Shell,9.1,0.90',
  '104743,CVE-2017-0144,9.3,8.1,Critical,192.168.1.20,tcp,445,EternalBlue,9.6,0.94',
  '51192,,,7.5,High,192.168.1.20,tcp,3389,SSL Cert,7.4,0.31'
].join('\n');
function recsOf(csv) { const raw = C.parseCSV(csv); return C.normalize(raw, C.mapColumns(raw[0])).recs; }
let stats, priority;
(function () {
  const oldR = recsOf(OLD_CSV), newR = recsOf(NEW_CSV);
  eq('基準記錄數', oldR.length, 5);
  eq('當前記錄數', newR.length, 5);
  const rows = C.computeRows(oldR, newR);
  const by = s => rows.filter(r => r.status === s).length;
  eq('新增數 (Spring4Shell)', by('added'), 1);
  eq('已修復數 (RC4)', by('removed'), 1);
  eq('持續數', by('persistent'), 3);
  eq('變更數 (SSL Cert Medium→High)', by('changed'), 1);
  const changed = rows.find(r => r.status === 'changed');
  ok('變更列 51192 Medium→High', changed && changed.pluginId === '51192' && changed.risk === 'High' && changed.oldRisk === 'Medium');

  stats = C.computeStats(oldR, newR, rows);
  eq('模式=diff', stats.mode, 'diff');
  eq('當前 Critical', stats.newSev.Critical, 3);
  eq('新增 CVE 數', stats.newCVEs, 1);
  eq('主機數', stats.newHosts, 2);

  priority = C.computeHostPriority(oldR, newR, rows);
  eq('最高優先主機', priority[0].host, '192.168.1.10');
  const h10 = priority.find(h => h.host === '192.168.1.10');
  eq('.10 緊急數(VPR≥7&EPSS≥.5)', h10.urgent, 2);
  ok('.10 sumVpr ≈ 18.9', Math.abs(h10.sumVpr - 18.9) < 0.01, 'sumVpr=' + h10.sumVpr);
  ok('.10 sumEpss ≈ 1.875', Math.abs(h10.sumEpss - 1.875) < 0.001, 'sumEpss=' + h10.sumEpss);
  eq('.10 Critical 數', h10.sev.Critical, 2);
  eq('.10 Info 數', h10.sev.Info, 1);
  eq('.10 弱點總數 = 各嚴重度加總', h10.count, h10.sev.Critical + h10.sev.High + h10.sev.Medium + h10.sev.Low + h10.sev.Info);
})();

console.log('\n[5] 單份模式（只匯入一份）');
(function () {
  const newR = recsOf(NEW_CSV);
  const rows = C.computeRows([], newR);
  ok('全部為 single 狀態', rows.every(r => r.status === 'single'));
  const st = C.computeStats([], newR, rows);
  eq('單份模式', st.mode, 'single');
})();

console.log('\n[5b] 範例檔可解析且約 300 筆');
(function () {
  const oldR = toRecs(loadCsv('scan_baseline.csv')).recs;
  const newR = toRecs(loadCsv('scan_current.csv')).recs;
  ok('基準 ≥ 250 筆', oldR.length >= 250, 'len=' + oldR.length);
  ok('當前 ≥ 250 筆', newR.length >= 250, 'len=' + newR.length);
  ok('多台主機(≥ 20)', new Set(newR.map(r => r.host)).size >= 20);
  ok('含 Solution 欄位', newR.some(r => r.solution && r.solution.length > 0));
})();

console.log('\n[6] CSV 匯出防公式注入');
(function () {
  eq('= 開頭前置引號', C.csvCell('=1+1'), "'=1+1");
  eq('+ 開頭', C.csvCell('+cmd'), "'+cmd");
  eq('@ 開頭', C.csvCell('@SUM'), "'@SUM");
  eq('- 開頭', C.csvCell('-2'), "'-2");
  eq('含逗號用引號包住', C.csvCell('a,b'), '"a,b"');
  eq('含雙引號跳脫', C.csvCell('a"b'), '"a""b"');
  eq('一般值不變', C.csvCell('192.168.1.1'), '192.168.1.1');
})();

console.log('\n[7] 缺 VPR/EPSS 降級（優先分數不為全 0）');
(function () {
  const raw = C.parseCSV('Host,Plugin ID,Risk\n1.1.1.1,10,Critical\n1.1.1.1,11,High\n2.2.2.2,12,Low\n');
  const { recs } = C.normalize(raw, C.mapColumns(raw[0]));
  const rows = C.computeRows([], recs);
  const pr = C.computeHostPriority([], recs, rows);
  ok('無 EPSS 時仍能排序（分數>0）', pr[0].score > 0);
  eq('高風險主機優先', pr[0].host, '1.1.1.1');
})();

console.log('\n[3b] CVSS v2.0 / v3.0 分開保留（四象限 Y 軸用）');
(function () {
  const raw = C.parseCSV('Host,Plugin ID,Risk,CVSS v2.0 Base Score,CVSS v3.0 Base Score\n1.1.1.1,10,High,7.5,9.8\n1.1.1.1,11,Medium,,6.4\n1.1.1.1,12,Critical,15,\n');
  const { recs, issueCount } = C.normalize(raw, C.mapColumns(raw[0]));
  eq('cvss2 保留', recs[0].cvss2, 7.5);
  eq('cvss3 保留', recs[0].cvss3, 9.8);
  eq('缺 v2.0 → null', recs[1].cvss2, null);
  eq('cvss2 超界(15)→null（不夾值）', recs[2].cvss2, null);
  ok('超界值列為 issue', issueCount >= 1, 'issueCount=' + issueCount);
  eq('合併值 v3 優先', recs[0].cvss, 9.8);
})();

console.log('\n[9] EPSS/VPR 正規化：非法值→null（不夾值，交由上層標記）');
(function () {
  // 數字版工具（相容）：域內原值、域外→null
  eq('EPSS 0.97 不變', C.normEpss(0.97), 0.97);
  eq('EPSS 97(%)→0.97', C.normEpss(97), 0.97);
  eq('EPSS 5 → 0.05', C.normEpss(5), 0.05);
  eq('EPSS >100 → null（不夾值）', C.normEpss(250), null);
  eq('EPSS 負值 → null（不夾值）', C.normEpss(-3), null);
  eq('EPSS null 維持', C.normEpss(null), null);
  eq('VPR 8.5 不變', C.normVpr(8.5), 8.5);
  eq('VPR 99 → null（不夾值）', C.normVpr(99), null);
  eq('VPR 負值 → null（不夾值）', C.normVpr(-1), null);
  // 端對端：髒 CSV（VPR 超界、EPSS >1）→ 非法者為 null 並登記 issue，不夾到最大值
  const raw = C.parseCSV('Host,Plugin ID,Risk,VPR Score,EPSS Score\n1.1.1.1,10,Critical,99,97%\n1.1.1.1,11,High,-2,250\n');
  const { recs, issues, issueCount } = C.normalize(raw, C.mapColumns(raw[0]));
  eq('VPR 99(超界)→null', recs[0].vpr, null);
  eq('VPR -2(超界)→null', recs[1].vpr, null);
  eq('EPSS 97%→0.97（合法百分比）', recs[0].epss, 0.97);
  eq('EPSS 250(→2.5 仍超界)→null', recs[1].epss, null);
  ok('登記 3 處非法值 issue', issueCount === 3, 'issueCount=' + issueCount);
  ok('issue 內含欄位與原值', issues.some(i => i.field === 'VPR' && i.raw === '99'), JSON.stringify(issues));
})();

console.log('\n[9b] parseEpssRaw / parseScoreRaw（三格式 + 合法/非法分流）');
(function () {
  eq('EPSS 0.97（機率）', C.parseEpssRaw('0.97').value, 0.97);
  eq('EPSS 97（百分比整數）', C.parseEpssRaw('97').value, 0.97);
  eq('EPSS 97%（百分比帶符號）', C.parseEpssRaw('97%').value, 0.97);
  eq('EPSS 0.5%（小百分比）', C.parseEpssRaw('0.5%').value, 0.005);
  eq('EPSS 空 → null 無 issue', C.parseEpssRaw('').value, null);
  ok('EPSS 空 → 無 issue', !C.parseEpssRaw('').issue);
  ok('EPSS 150 → 超界 issue', !!C.parseEpssRaw('150').issue, JSON.stringify(C.parseEpssRaw('150')));
  ok('EPSS abc → 非數值 issue', !!C.parseEpssRaw('abc').issue);
  eq('VPR 7.5（合法）', C.parseScoreRaw('7.5', 10, 'VPR').value, 7.5);
  ok('VPR 11 → 超界 issue', !!C.parseScoreRaw('11', 10, 'VPR').issue);
  ok('CVSS x → 非數值 issue', !!C.parseScoreRaw('x', 10, 'CVSS').issue);
  eq('n/a → null 無 issue', C.parseScoreRaw('n/a', 10, 'VPR').value, null);
})();

console.log('\n[9c] 重複列偵測（相同 Host/Plugin/Port/Protocol）');
(function () {
  const raw = C.parseCSV('Host,Plugin ID,Risk,Port,Protocol\n' +
    '1.1.1.1,10,High,443,tcp\n' +
    '1.1.1.1,10,High,443,tcp\n' +     // 完全重複
    '1.1.1.1,10,High,80,tcp\n' +      // 不同 Port → 不算重複
    '2.2.2.2,10,High,443,tcp\n');     // 不同 Host → 不算重複
  const { recs, dupes, dupeSamples } = C.normalize(raw, C.mapColumns(raw[0]));
  eq('全部保留（重複不丟棄，僅標記）', recs.length, 4);
  eq('重複數 = 1', dupes, 1);
  ok('重複樣本含 host+key', dupeSamples.length === 1 && dupeSamples[0].indexOf('1.1.1.1') === 0, JSON.stringify(dupeSamples));
})();

console.log('\n[9d] 變更分類（風險 / 分數 / CVE / 名稱 / 修補）');
(function () {
  const base = { risk: 'High', vpr: 7, epss: 0.3, cvss: 7.5, cve: 'CVE-2020-1', name: 'A', solution: 'patch' };
  const mk = ov => Object.assign({}, base, ov);
  eq('風險變更', C.classifyChange(base, mk({ risk: 'Critical' })).join(','), '風險');
  eq('分數變更(VPR)', C.classifyChange(base, mk({ vpr: 9 })).join(','), '分數');
  eq('CVE 變更(新增)', C.classifyChange(base, mk({ cve: 'CVE-2020-1,CVE-2021-2' })).join(','), 'CVE');
  eq('CVE 順序不同不算變更', C.classifyChange(mk({ cve: 'CVE-2020-1,CVE-2021-2' }), mk({ cve: 'CVE-2021-2,CVE-2020-1' })).length, 0);
  eq('名稱變更', C.classifyChange(base, mk({ name: 'B' })).join(','), '名稱');
  eq('修補方式變更', C.classifyChange(base, mk({ solution: 'upgrade' })).join(','), '修補');
  eq('無變更 → 空', C.classifyChange(base, mk({})).length, 0);
  const multi = C.classifyChange(base, mk({ risk: 'Critical', name: 'B' }));
  ok('可同時多種變更', multi.includes('風險') && multi.includes('名稱'), multi.join(','));
})();

console.log('\n[9e] 新增 CVE 統計：涵蓋持續弱點內容變更後新出現的 CVE');
(function () {
  // 同一 finding（plugin 500/tcp/443）持續存在，但 CVE 從 1 個變 2 個 → 新增的 CVE 應計入
  const HH = 'Plugin ID,CVE,Risk,Host,Protocol,Port,Name';
  const oldC = [HH, '500,CVE-2020-1,High,9.9.9.9,tcp,443,X'].join('\n');
  const newC = [HH, '500,"CVE-2020-1,CVE-2021-9",High,9.9.9.9,tcp,443,X'].join('\n');
  const oldR = recsOf(oldC), newR = recsOf(newC);
  const rows = C.computeRows(oldR, newR);
  const st = C.computeStats(oldR, newR, rows);
  eq('持續弱點（非新增列）', rows.filter(r => r.status === 'persistent' || r.status === 'changed').length, 1);
  eq('新增 CVE 計入內容變更', st.newCVEs, 1); // CVE-2021-9 為新出現
  const changed = rows.find(r => r.status === 'changed');
  ok('該列被歸類為 changed(CVE)', changed && changed.changeTypes.includes('CVE'), JSON.stringify(changed && changed.changeTypes));
})();

console.log('\n[9f] 正式報告欄位正規化（Description / Plugin Output / See Also / 資產 / 追蹤）');
(function () {
  const HH = 'Host,Plugin ID,Description,Plugin Output,See Also,Operating System,DNS Name,處理狀態,負責人,備註';
  const raw = C.parseCSV(HH + '\n1.1.1.1,10,"說明內容","輸出內容","https://ref","Linux","host.local","處理中","Alice","待複測"');
  const { recs } = C.normalize(raw, C.mapColumns(raw[0]));
  const r = recs[0];
  eq('description', r.description, '說明內容');
  eq('pluginOutput', r.pluginOutput, '輸出內容');
  eq('seeAlso', r.seeAlso, 'https://ref');
  eq('os', r.os, 'Linux');
  eq('dnsName', r.dnsName, 'host.local');
  eq('disposition(處理狀態)', r.disposition, '處理中');
  eq('owner(負責人)', r.owner, 'Alice');
  eq('note(備註)', r.note, '待複測');
})();

console.log('\n[9g] extractScanTime（由 Scan Information plugin 19506 擷取）');
(function () {
  const HH = 'Host,Plugin ID,Name,Plugin Output';
  const raw = C.parseCSV(HH + '\n1.1.1.1,19506,Scan Info,"Scan Start Date : 2024/01/15 10:30 CST\nOther : x"');
  const { recs } = C.normalize(raw, C.mapColumns(raw[0]));
  eq('擷取掃描起始時間', C.extractScanTime(recs), '2024/01/15 10:30 CST');
  eq('無 19506 → 空字串', C.extractScanTime([{ pluginId: '10', pluginOutput: '' }]), '');
})();

console.log('\n[9h] 串流解析與一次性解析結果一致（跨 chunk 引號/CRLF）');
(function () {
  const text = 'a,b,c\r\n1,"x,y","li""ne\nbreak"\r\n2,z,w\n';
  const oneShot = C.parseCSV(text);
  // 逐字元 push，逼出所有 pending 邊界
  const collected = [];
  const p = C.createStreamParser(r => collected.push(r));
  for (const ch of text) p.push(ch);
  p.end();
  eq('串流與一次性列數一致', collected.length, oneShot.length);
  eq('跨 chunk 引號逗號一致', collected[1][1], 'x,y');
  eq('跨 chunk 引號跳脫+換行一致', collected[1][2], 'li"ne\nbreak');
})();

console.log('\n[8] 網段彙總（300+ IP 收斂）');
(function () {
  eq('IPv4 /24', C.subnetOf('10.0.5.23'), '10.0.5.0/24');
  eq('非 IPv4 歸類', C.subnetOf('web-server.local'), '其他 / 非 IPv4');
  // 造 3 個網段、每段多台主機
  let csv = 'Host,Plugin ID,Risk,VPR Score,EPSS Score\n';
  for (let s = 1; s <= 3; s++) for (let h = 1; h <= 5; h++)
    csv += `10.0.${s}.${h},${1000 + s * 10 + h},${s === 1 ? 'Critical' : 'Medium'},${s === 1 ? 9.5 : 4},${s === 1 ? 0.9 : 0.05}\n`;
  const { recs } = C.normalize(C.parseCSV(csv), C.mapColumns(C.parseCSV(csv)[0]));
  const rows = C.computeRows([], recs);
  const pr = C.computeHostPriority([], recs, rows);
  const subs = C.computeSubnetAggregation(pr);
  eq('網段數', subs.length, 3);
  eq('最糟網段', subs[0].subnet, '10.0.1.0/24');
  eq('最糟網段主機數', subs[0].hosts, 5);
  eq('最糟網段 Critical 數', subs[0].crit, 5);
  ok('網段分數遞減', subs[0].score >= subs[1].score);
})();

console.log('\n[10] 邊界：空檔 / 只有表頭 / 缺欄位 / 主機格式');
(function () {
  // 空字串
  eq('空字串 → 0 列', C.parseCSV('').length, 0);
  // 只有表頭（無資料列）
  const onlyHead = C.parseCSV('Host,Plugin ID\n');
  const oh = C.normalize(onlyHead, C.mapColumns(onlyHead[0]));
  eq('只有表頭 → 0 筆記錄', oh.recs.length, 0);
  // 缺必要欄位
  const noReq = C.mapColumns(['Foo', 'Bar', 'Baz']);
  eq('缺 host+pluginId', C.REQUIRED.filter(k => noReq[k] < 0).length, 2);
  // 缺 Host 或 Plugin ID 的資料列被略過並計數
  const partial = C.parseCSV('Host,Plugin ID,Risk\n,10,High\n1.1.1.1,,High\n1.1.1.1,10,High\n');
  const pr2 = C.normalize(partial, C.mapColumns(partial[0]));
  eq('略過缺鍵列', pr2.skipped, 2);
  eq('保留有效列', pr2.recs.length, 1);
  // 主機格式：IPv4 / 主機名 / FQDN 皆可作為 key
  const hosts = C.parseCSV('Host,Plugin ID,Risk\n10.0.0.1,10,High\nweb01,11,High\napp.example.com,12,High\n');
  const hr = C.normalize(hosts, C.mapColumns(hosts[0]));
  eq('三種主機格式皆保留', new Set(hr.recs.map(r => r.host)).size, 3);
  eq('IPv4 → /24 網段', C.subnetOf('10.0.0.1'), '10.0.0.0/24');
  eq('主機名 → 非 IPv4 類', C.subnetOf('web01'), '其他 / 非 IPv4');
})();

console.log('\n[11] 報告統計 = 畫面資料（同一 computeStats/rows 來源，數字一致）');
(function () {
  const oldR = recsOf(OLD_CSV), newR = recsOf(NEW_CSV);
  const rows = C.computeRows(oldR, newR);
  const st = C.computeStats(oldR, newR, rows);
  // 報告「執行摘要」的數字全部由同一組 rows/stats 推導，逐項核對
  eq('新增 = rows 中 added', st.added, rows.filter(r => r.status === 'added').length);
  eq('修復 = rows 中 removed', st.removed, rows.filter(r => r.status === 'removed').length);
  eq('持續 = rows 中 persistent', st.persistent, rows.filter(r => r.status === 'persistent').length);
  eq('變更 = rows 中 changed', st.changed, rows.filter(r => r.status === 'changed').length);
  eq('當前總數 = 記錄數', st.newTotal, newR.length);
  eq('當前主機數 = 去重主機', st.newHosts, new Set(newR.map(r => r.host)).size);
  // 嚴重度分佈加總 = 總筆數
  const sevSum = Object.values(st.newSev).reduce((a, b) => a + b, 0);
  eq('嚴重度分佈加總 = 當前總數', sevSum, st.newTotal);
  // 內容變更計數：changed 且不含風險/分數
  eq('內容變更計數存在', typeof st.contentChanged, 'number');
})();

console.log('\n[12] XSS / 注入 防護（escapeXml + csvCell）');
(function () {
  eq('escape <script>', C.escapeXml('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;/script&gt;');
  eq('escape 引號', C.escapeXml('a"b\'c'), 'a&quot;b&#39;c');
  eq('escape &', C.escapeXml('a&b'), 'a&amp;b');
  // CSV 公式注入：=HYPERLINK(...) 這類危險公式應被前置單引號，且含引號者正確跳脫
  eq('=HYPERLINK 前置引號並跳脫', C.csvCell('=HYPERLINK("http://x")'), '"\'=HYPERLINK(""http://x"")"');
  ok('=開頭被前置單引號', C.csvCell('=1').charAt(0) === "'");
  ok('含逗號被引號包住', /^".*"$/.test(C.csvCell('a,b')));
})();

console.log('\n[13] 大量資料：串流解析 + 正規化 + 比對（≥ 50,000 列）');
(function () {
  const N = 60000;               // > 50,000，涵蓋大型企業掃描
  const HH = 'Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,VPR Score,EPSS Score';
  // 以串流解析器逐塊 push，模擬檔案分塊，不一次組整份字串（省記憶體）
  const t0 = Date.now();
  const rawRows = [];
  const parser = C.createStreamParser(r => rawRows.push(r));
  parser.push(HH + '\n');
  let buf = '';
  const UNIQ = 40000;            // 前 40,000 列 key 唯一；其後 20,000 列刻意重複，驗證大規模重複偵測
  for (let i = 0; i < N; i++) {
    const j = i < UNIQ ? i : (i - UNIQ);
    const host = `10.${(j >> 8) & 255}.${j & 255}.${(j % 254) + 1}`;
    const risk = ['Critical', 'High', 'Medium', 'Low'][i % 4];
    buf += `${1000 + (j % 500)},CVE-2021-${1000 + (i % 3000)},${(i % 100) / 10},${risk},${host},tcp,${80 + (j % 50)},"Vuln, ${i}",${(i % 100) / 10},${(i % 100) / 100}\n`;
    if (i % 1000 === 0) { parser.push(buf); buf = ''; }   // 分塊
  }
  parser.push(buf); parser.end();
  const parseMs = Date.now() - t0;
  eq('串流解析列數（含表頭）', rawRows.length, N + 1);

  const t1 = Date.now();
  const { recs, dupes } = C.normalize(rawRows, C.mapColumns(rawRows[0]));
  const normMs = Date.now() - t1;
  eq('正規化記錄數', recs.length, N);
  ok('偵測到重複（key 空間 < N，必有重複）', dupes > 0, 'dupes=' + dupes);
  ok('所有 EPSS 在 [0,1]', recs.every(r => r.epss == null || (r.epss >= 0 && r.epss <= 1)));

  const t2 = Date.now();
  const half = recs.slice(0, N / 2), rows = C.computeRows(half, recs);
  const stats = C.computeStats(half, recs, rows);
  const diffMs = Date.now() - t2;
  ok('比對產生列數 > 0', rows.length > 0, 'rows=' + rows.length);
  ok('統計 mode=diff', stats.mode === 'diff');
  console.log(`    ⏱ 解析 ${parseMs}ms · 正規化 ${normMs}ms · 比對 ${diffMs}ms（${N} 列）`);
  ok('整體效能在合理範圍（< 15s）', (parseMs + normMs + diffMs) < 15000, `${parseMs + normMs + diffMs}ms`);
})();

console.log('\n[14] 離線安全邊界（main.js 靜態不變式，防退化）');
(function () {
  const src = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
  ok('未使用 shell.openExternal（不對外開連結）', !/shell\.openExternal/.test(src) && !/require\(['"]electron['"]\)[^\n]*shell/.test(src.split('\n').find(l => /shell/.test(l)) || ''));
  ok('未 import electron 的 shell 模組', !/[{,]\s*shell\s*[,}]/.test(src));
  ok('攔截所有請求 onBeforeRequest', /webRequest\.onBeforeRequest/.test(src));
  ok('非本機請求一律 cancel', /cancel:\s*!isLocal/.test(src));
  ok('拒絕權限請求 setPermissionRequestHandler', /setPermissionRequestHandler\([^)]*cb\(false\)/.test(src) || /setPermissionRequestHandler\(\(_wc, _perm, cb\) => cb\(false\)\)/.test(src));
  ok('封鎖對外導覽 will-navigate', /will-navigate/.test(src));
  ok('封鎖重新導向 will-redirect', /will-redirect/.test(src));
  ok('contextIsolation 開啟', /contextIsolation:\s*true/.test(src));
  ok('nodeIntegration 關閉', /nodeIntegration:\s*false/.test(src));
  ok('sandbox 開啟', /sandbox:\s*true/.test(src));
  // isLocal 判定邏輯（複製自 main.js，避免載入 electron）
  const isLocal = (url) => typeof url === 'string' && (/^file:/i.test(url) || url === 'about:blank' || url === '' || /^devtools:/i.test(url));
  ok('file: 視為本機', isLocal('file:///a/b.html'));
  ok('about:blank 視為本機', isLocal('about:blank'));
  ok('http 外連視為非本機（會被封鎖）', !isLocal('http://evil.example/x'));
  ok('https 外連視為非本機（會被封鎖）', !isLocal('https://evil.example/x'));
  ok('ftp 外連視為非本機（會被封鎖）', !isLocal('ftp://x/y'));
})();

console.log('\n[15] CSP 靜態不變式（index.html 完全離線）');
(function () {
  const html = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'index.html'), 'utf8');
  const m = /Content-Security-Policy[^>]*content="([^"]+)"/i.exec(html);
  ok('存在 CSP meta', !!m, 'no CSP');
  if (m) {
    const csp = m[1];
    ok('default-src none', /default-src\s+'none'/.test(csp), csp);
    ok('不允許外連 connect-src（無 http/https）', !/connect-src[^;]*https?:/.test(csp), csp);
    ok('script 僅本機（無遠端來源）', !/script-src[^;]*https?:/.test(csp), csp);
  }
})();

console.log('\n──────────────────────────────');
console.log(`結果：${pass} 通過 / ${fail} 失敗`);
process.exit(fail ? 1 : 0);
