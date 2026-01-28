import { resolve } from 'path'
import { defineConfig } from 'vite'
import { VitePWA } from 'vite-plugin-pwa'

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
        web: resolve(root, './web', './index.html'),
        web_en: resolve(root, './web', './index_ja.html'),
        "pwa-512x512": resolve('./icons', './', 'pwa-512x512.png'),
        "pwa-192x192": resolve('./icons', './', 'pwa-192x192.png')
        
      },
      output: {
        assetFileNames: "[name].[ext]",
        chunkFileNames: "[name].[ext]",
        entryFileNames: "[name].js"
      },
    },
  },
  base: "./",
  // ローカルサーバーの設定
  server: {
    open: true, // 起動時にブラウザを開く
  },
  plugins: [
    VitePWA({
      workbox: {
        globPatterns: ['**/*.{js,css,html,ico,png,svg}'],
        maximumFileSizeToCacheInBytes: 3000000
      },
      registerType: 'autoUpdate',
      devOptions: {
        enabled: true
      },
      includeAssets: ['./icons/pwa-192x192.png', './icons/pwa-512x512.png', './icons/favicon.ico', './icons/apple-touch-icon.png'],
      manifest: {
        name: 'Soul Password Manager',
        short_name: 'Soul Pass',
        description: 'Next-generation password manager',
        theme_color: '#6750a4',
        icons: [
          {
            src: 'pwa-192x192.png',
            sizes: '192x192',
            type: 'image/png'
          },
          {
            src: 'pwa-512x512.png',
            sizes: '512x512',
            type: 'image/png'
          }
        ]
      }
    })
  ]
});
