import { defineConfig } from 'vite';

export default defineConfig({
  // ビルド時の出力先設定など
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  base: "./",
  // ローカルサーバーの設定
  server: {
    open: true, // 起動時にブラウザを開く
  }
});

