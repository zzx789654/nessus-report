'use strict';

/*
 * Nessus Diff — Electron 主行程（安全離線外殼）
 *
 * 資安基線（資安分析師把關）：
 *  - contextIsolation:true / nodeIntegration:false / sandbox:true → renderer 無法直接碰 Node/OS。
 *  - webSecurity:true、嚴格 CSP（於 index.html meta）→ 純本機、無外連。
 *  - 封鎖對外導覽與開新視窗 → 離線工具不應被導去任何網址。
 *  - preload 僅透過 contextBridge 暴露「儲存檔案」單一功能，且在主行程二次驗證輸入。
 *  - 不使用任何持久化（無 session partition 落地、無快取寫入需求）；關窗即結束。
 */

const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const fs = require('fs');
const path = require('path');

let mainWindow = null;

// 關閉硬體加速可再降低記憶體/相容性風險（離線資料工具不需要 GPU）。
app.disableHardwareAcceleration();

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 960,
    minHeight: 640,
    backgroundColor: '#0f1420',
    title: 'Nessus Diff — 弱點掃描比對工具',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      sandbox: true,
      webSecurity: true,
      spellcheck: false,
      // 明確關閉可被濫用的功能
      allowRunningInsecureContent: false
    }
  });

  // 移除選單列（減少誤觸，桌面工具聚焦單一視窗）
  mainWindow.removeMenu();

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  // 封鎖任何對外導覽（離線工具只允許載入本機檔案）
  mainWindow.webContents.on('will-navigate', (event) => {
    event.preventDefault();
  });

  // 視窗開啟策略：
  //  - about:blank（報表「預覽」用，內容為本 app 產生且已 escape 的安全 HTML）→ 放行，
  //    但以無 Node 整合、無外部導覽的方式開啟，維持沙箱。
  //  - http(s) 外連 → 交給系統瀏覽器，app 內拒絕。
  //  - 其餘一律拒絕。
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url === 'about:blank' || url === '') {
      return {
        action: 'allow',
        overrideBrowserWindowOptions: {
          webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true }
        }
      };
    }
    if (/^https?:\/\//i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });

  // 預覽子視窗本身也不得對外導覽
  mainWindow.webContents.on('did-create-window', (child) => {
    child.webContents.on('will-navigate', (e) => e.preventDefault());
    child.removeMenu();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  // 關閉即完全結束行程 → 作業系統回收所有記憶體（符合「不記憶、關閉釋放」）
  app.quit();
});

/*
 * IPC：儲存檔案（報表 / Log / 範例 CSV 匯出）
 * 由 renderer 產生內容字串，主行程負責顯示原生「另存新檔」對話框並寫檔。
 * 安全處理：
 *  - 只接受字串內容與白名單過的副檔名。
 *  - 路徑完全由使用者透過原生對話框選擇，renderer 無法指定任意路徑（防路徑穿越）。
 */
const ALLOWED_EXT = new Set(['html', 'csv', 'log', 'txt', 'json']);

ipcMain.handle('save-file', async (_event, payload) => {
  try {
    if (!payload || typeof payload !== 'object') {
      return { ok: false, error: 'invalid payload' };
    }
    const content = typeof payload.content === 'string' ? payload.content : '';
    let ext = String(payload.ext || 'txt').toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!ALLOWED_EXT.has(ext)) ext = 'txt';

    // 清理預設檔名，去除路徑分隔與危險字元
    let defaultName = String(payload.defaultName || 'export');
    defaultName = defaultName.replace(/[\\/:*?"<>|]+/g, '_').slice(0, 120);
    if (!defaultName) defaultName = 'export';

    const result = await dialog.showSaveDialog(mainWindow, {
      title: '另存新檔',
      defaultPath: `${defaultName}.${ext}`,
      filters: [
        { name: ext.toUpperCase(), extensions: [ext] },
        { name: 'All Files', extensions: ['*'] }
      ]
    });

    if (result.canceled || !result.filePath) {
      return { ok: false, canceled: true };
    }

    // 加 UTF-8 BOM 讓 Excel 正確辨識中文（僅對文字型輸出）
    const needBom = ext === 'csv' || ext === 'txt' || ext === 'log';
    const data = needBom ? '﻿' + content : content;
    fs.writeFileSync(result.filePath, data, { encoding: 'utf8' });
    return { ok: true, path: result.filePath };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
});
