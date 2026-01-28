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
    emptyOutDir: true,
    reportCompressedSize: true,
    chunkSizeWarningLimit: 1000,
    // esbuildによる最適化（console.log削除など）
    esbuild: {
      drop: ['console', 'debugger'],
    },
    rollupOptions: {
      input: {
        main: resolve(root, './', './index.html'),
        web: resolve(root, './web', './index.html'),
        web_en: resolve(root, './web', './index_ja.html'),
      },
      output: {
        // キャッシュ管理のためにハッシュを付与
        entryFileNames: "assets/[name]-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash].[ext]",
        // ベンダーコードの分割
        manualChunks(id) {
            if (id.includes('node_modules')) {
                if (id.includes('firebase')) {
                    return 'vendor-firebase';
                }
                if (id.includes('zxcvbn')) {
                    return 'vendor-zxcvbn';
                }
                if (id.includes('@m3e')) {
                    return 'vendor-ui';
                }
                return 'vendor';
            }
        }
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
        maximumFileSizeToCacheInBytes: 4000000
      },
      registerType: 'autoUpdate',
      devOptions: {
        enabled: true
      },
      // public/iconsに移動したためパスを更新
      includeAssets: ['icons/pwa-192x192.png', 'icons/pwa-512x512.png', 'icons/favicon.ico', 'icons/apple-touch-icon.png'],
      manifest: {
        name: 'Soul Password Manager',
        short_name: 'Soul Pass',
        description: 'Next-generation password manager',
        theme_color: '#6750a4',
        icons: [
          {
            src: 'icons/pwa-192x192.png',
            sizes: '192x192',
            type: 'image/png'
          },
          {
            src: 'icons/pwa-512x512.png',
            sizes: '512x512',
            type: 'image/png'
          }
        ]
      }
    })
  ]
});
