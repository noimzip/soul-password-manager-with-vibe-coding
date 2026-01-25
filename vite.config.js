import { dirname, resolve } from 'path'
import { defineConfig } from 'vite'
const root = resolve(__dirname, './');
const outDir = resolve(__dirname, 'dist');

export default defineConfig({
  // ビルド時の出力先設定など
publicDir: 'public',
  root,
  build: {
    outDir,
    rollupOptions: {
      input: {
        main: resolve(root, './', './index.html'),
        web: resolve(root, './web', './index.html')
      },
    },
  },
  base: "./",
  // ローカルサーバーの設定
  server: {
    open: true, // 起動時にブラウザを開く
  }
});

