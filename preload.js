'use strict';

/*
 * preload — 唯一連接 renderer 與 Node 的橋樑。
 * 透過 contextBridge 只暴露「儲存檔案」一個經最小化的 API；
 * renderer 拿不到 require / fs / ipcRenderer 全域，攻擊面極小。
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('desktop', {
  // 由 renderer 產生內容字串，主行程負責原生另存對話框與寫檔
  saveFile: (defaultName, ext, content) =>
    ipcRenderer.invoke('save-file', {
      defaultName: String(defaultName || 'export'),
      ext: String(ext || 'txt'),
      content: String(content == null ? '' : content)
    }),
  // 讓 renderer 判斷是否在 Electron 桌面環境（瀏覽器直開時為 false）
  isDesktop: true
});
