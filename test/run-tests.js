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
  const { recs } = C.normalize(raw, C.mapColumns(raw[0]));
  eq('cvss2 保留', recs[0].cvss2, 7.5);
  eq('cvss3 保留', recs[0].cvss3, 9.8);
  eq('缺 v2.0 → null', recs[1].cvss2, null);
  eq('cvss2 超界夾到 10', recs[2].cvss2, 10);
  eq('合併值 v3 優先', recs[0].cvss, 9.8);
})();

console.log('\n[9] EPSS/VPR 正規化與夾範圍（防圖表座標溢出）');
(function () {
  eq('EPSS 0.97 不變', C.normEpss(0.97), 0.97);
  eq('EPSS 97(%)→0.97', C.normEpss(97), 0.97);
  eq('EPSS 5 → 0.05', C.normEpss(5), 0.05);
  eq('EPSS >100 夾到 1', C.normEpss(250), 1);
  eq('EPSS 負值夾到 0', C.normEpss(-3), 0);
  eq('EPSS null 維持', C.normEpss(null), null);
  eq('VPR 8.5 不變', C.normVpr(8.5), 8.5);
  eq('VPR 99 夾到 10', C.normVpr(99), 10);
  eq('VPR 負值夾到 0', C.normVpr(-1), 0);
  // 端對端：髒 CSV（EPSS 百分比、VPR 超界）→ 正規化後在域內
  const raw = C.parseCSV('Host,Plugin ID,Risk,VPR Score,EPSS Score\n1.1.1.1,10,Critical,99,97%\n1.1.1.1,11,High,-2,1.5\n');
  const { recs } = C.normalize(raw, C.mapColumns(raw[0]));
  ok('EPSS 全在 [0,1]', recs.every(r => r.epss >= 0 && r.epss <= 1), JSON.stringify(recs.map(r => r.epss)));
  ok('VPR 全在 [0,10]', recs.every(r => r.vpr >= 0 && r.vpr <= 10), JSON.stringify(recs.map(r => r.vpr)));
  eq('百分比 EPSS 換算正確', recs[0].epss, 0.97);
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

console.log('\n──────────────────────────────');
console.log(`結果：${pass} 通過 / ${fail} 失敗`);
process.exit(fail ? 1 : 0);
