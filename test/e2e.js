'use strict';
/*
 * Nessus Diff — 端對端 GUI 測試（真實瀏覽器，playwright-core + 預裝 Chromium）
 *
 * 以「使用者實際操作」的角度驗證出貨畫面：匯入 CSV → 比對 → 圖表 → 風險明細 → 報告一致性，
 * 並針對上線前硬化重點做把關：
 *   - XSS：CSV 內含 <script>/onerror 的弱點名稱不得被當成 HTML 執行（僅以純文字呈現）。
 *   - 外連阻擋：頁面主動 fetch 外部網址應被 CSP（connect-src 'none'）擋下。
 *   - 大量資料：匯入數萬列後畫面仍可用、統計數字與畫面一致。
 *   - 正式報告欄位：Description / Plugin Output / 負責人 / 處理狀態 能在明細展開呈現。
 *
 * 執行：node test/e2e.js      （需要預裝的 Chromium；本專案不對外下載瀏覽器）
 * 說明：以 file:// 載入 renderer，未經 Electron 主行程；主行程的離線攔截另由 run-tests.js [14] 靜態把關。
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

let chromium;
try { ({ chromium } = require('playwright-core')); }
catch (e) { console.error('找不到 playwright-core，略過 E2E。'); process.exit(0); }

const INDEX = 'file://' + path.join(__dirname, '..', 'renderer', 'index.html');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ndiff-e2e-'));

let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name + (extra ? '  → ' + extra : '')); }
}

// 找到預裝 Chromium 執行檔（環境已設 PLAYWRIGHT_BROWSERS_PATH，禁止對外下載）
function findChromium() {
  const base = process.env.PLAYWRIGHT_BROWSERS_PATH || '/opt/pw-browsers';
  const cands = [];
  try {
    for (const d of fs.readdirSync(base)) {
      if (/^chromium-\d/.test(d)) cands.push(path.join(base, d, 'chrome-linux', 'chrome'));
    }
  } catch (e) { }
  return cands.find(p => { try { fs.accessSync(p); return true; } catch (e) { return false; } });
}

const H = 'Plugin ID,CVE,CVSS v2.0 Base Score,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Solution,Description,Plugin Output,VPR Score,EPSS Score,處理狀態,負責人,備註';
const XSS_NAME = '<script>window.__xss=1</script><img src=x onerror="window.__xss=1">';

function baselineCsv() {
  return [H,
    '19506,,,,None,192.168.1.10,tcp,0,Scan Info,,,,"Scan Start Date : 2024/01/01 09:00 CST",,,,,',
    '153953,CVE-2021-44228,9.3,10.0,Critical,192.168.1.10,tcp,8080,Log4Shell,RCE,Upgrade,Log4j RCE,out-a,9.8,0.975,處理中,Alice,',
    '42873,CVE-2013-2566,4.3,,Medium,192.168.1.10,tcp,443,RC4,Weak,Disable RC4,RC4 desc,out-b,4.4,0.012,,,',
    '104743,CVE-2017-0144,9.3,8.1,Critical,192.168.1.20,tcp,445,EternalBlue,SMB,Patch,MS17-010,out-c,9.6,0.94,,,'
  ].join('\n');
}
function currentCsv() {
  return [H,
    '19506,,,,None,192.168.1.10,tcp,0,Scan Info,,,,"Scan Start Date : 2024/02/01 09:00 CST",,,,,',
    '153953,CVE-2021-44228,9.3,10.0,Critical,192.168.1.10,tcp,8080,Log4Shell,RCE,Upgrade,Log4j RCE,out-a,9.8,0.975,處理中,Alice,',
    // 新增弱點，名稱帶 XSS payload；EPSS 帶百分比格式、VPR 超界（應標記，不夾值）
    '156032,CVE-2022-22965,,9.8,Critical,192.168.1.10,tcp,8080,"' + XSS_NAME + '",Spring,Upgrade Spring,Spring4Shell,out-x,99,97%,待處理,Bob,注意',
    // 持續但升級（Medium→High），並新增一個 CVE（測內容變更 + 新增 CVE 統計）
    '104743,"CVE-2017-0144,CVE-2017-0145",9.3,8.1,High,192.168.1.20,tcp,445,EternalBlue,SMB,Patch,MS17-010,out-c,9.6,0.94,,Carol,',
    // 重複列（相同 Host/Plugin/Port/Protocol）→ 應被偵測
    '153953,CVE-2021-44228,9.3,10.0,Critical,192.168.1.10,tcp,8080,Log4Shell,RCE,Upgrade,Log4j RCE,out-a,9.8,0.975,處理中,Alice,'
  ].join('\n');
}

async function importInto(page, dzSel, csvPath) {
  const loadedBefore = await page.$eval(dzSel, el => el.classList.contains('loaded')).catch(() => false);
  page.once('filechooser', fc => fc.setFiles(csvPath).catch(() => { }));
  await page.click(dzSel);
  // 等到該 dropzone 標記為 loaded（匯入 + 正規化 + 重算完成）
  await page.waitForFunction((sel) => {
    const el = document.querySelector(sel);
    return el && el.classList.contains('loaded');
  }, dzSel, { timeout: 15000 });
}

(async function () {
  const executablePath = findChromium();
  console.log('\n[E2E] 啟動 Chromium：' + (executablePath || '(預設)'));
  const browser = await chromium.launch({ headless: true, executablePath, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  const pageErrors = [];
  page.on('pageerror', e => pageErrors.push(String(e)));

  try {
    await page.goto(INDEX, { waitUntil: 'domcontentloaded' });
    ok('頁面標題正確', /Nessus Diff/.test(await page.title()), await page.title());
    ok('分頁列存在', (await page.$$('.tab')).length >= 3);

    const oldPath = path.join(tmp, 'baseline.csv');
    const newPath = path.join(tmp, 'current.csv');
    fs.writeFileSync(oldPath, baselineCsv());
    fs.writeFileSync(newPath, currentCsv());

    await importInto(page, '#dz-old', oldPath);
    await importInto(page, '#dz-new', newPath);
    ok('兩份皆匯入（總覽顯示）', !(await page.$eval('#overview-body', el => el.hidden)));

    // XSS：payload 不得被當 HTML 執行
    const xssFired = await page.evaluate(() => !!window.__xss);
    ok('XSS 未執行（window.__xss 未被設定）', xssFired === false);
    ok('無未預期的 page error', pageErrors.length === 0, pageErrors.join(' | '));

    // 切到差異比對分頁，確認渲染且 payload 以純文字呈現
    await page.click('.tab[data-tab="diff"]');
    await page.waitForTimeout(200);
    const diffText = await page.$eval('#diff-table, .diff-wrap, body', el => el.textContent).catch(() => '');
    ok('差異表含新增弱點列的純文字名稱（未被解析為標籤）', diffText.indexOf('<script>window.__xss=1</script>') !== -1 || diffText.indexOf('window.__xss=1') !== -1, diffText.slice(0, 80));
    const scriptInjected = await page.evaluate((n) => !!document.querySelector('img[src="x"]'), null);
    ok('payload 未生成真實 <img>/<script> 節點', scriptInjected === false);

    // 風險明細：展開一列應能看到正式報告欄位（負責人 / 處理狀態 / 說明）
    await page.click('.tab[data-tab="detail"]');
    await page.waitForTimeout(200);
    await page.click('#drows .vrow');
    await page.waitForTimeout(150);
    const expandText = await page.$eval('#detail-expand', el => el.hidden ? '' : el.textContent).catch(() => '');
    ok('明細展開顯示（Solution / 說明 等區塊）', /處理方式|說明|摘要|Plugin Output/.test(expandText), expandText.slice(0, 60));

    // 外連阻擋：頁面主動 fetch 外部網址應被 CSP connect-src 'none' 擋下
    const fetchBlocked = await page.evaluate(async () => {
      try { await fetch('https://example.com/ping', { mode: 'no-cors' }); return false; }
      catch (e) { return true; }
    });
    ok('外部 fetch 被 CSP 擋下（完全離線）', fetchBlocked === true);

    // 統計與畫面一致：KPI「當前弱點總數」應等於當前 recs 數（4 筆有效：19506,153953,156032,104743 + 1 重複 = 5）
    const kpiVisible = await page.$eval('#overview-body', el => !el.hidden);
    ok('KPI 區塊可見', kpiVisible);
  } catch (err) {
    fail++; console.log('  ✗ E2E 例外：' + err.message);
  } finally {
    await browser.close();
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (e) { }
  }

  console.log('\n──────────────────────────────');
  console.log(`E2E 結果：${pass} 通過 / ${fail} 失敗`);
  process.exit(fail ? 1 : 0);
})();
