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
    chunkSizeWarningLimit: 500,
    // ターゲットを最新のブラウザに設定（より小さなバンドルサイズ）
    target: 'esnext',
    // CSS コード分割を有効化
    cssCodeSplit: true,
    // ソースマップは本番では無効化
    sourcemap: false,
    // minify設定
    minify: true,
    rollupOptions: {
      input: {
        main: resolve(root, './', './index.html'),
        web: resolve(root, './web', './index.html'),
        web_ja: resolve(root, './web', './index_ja.html'),
      },
      output: {
        // キャッシュ管理のためにハッシュを付与
        entryFileNames: "assets/[name]-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash].[ext]",
        // ベンダーコードの細分化された分割
        manualChunks(id) {
            if (id.includes('node_modules')) {
                // Firebase関連を細分化
                if (id.includes('firebase/auth')) {
                    return 'vendor-firebase-auth';
                }
                if (id.includes('firebase/firestore')) {
                    return 'vendor-firebase-firestore';
                }
                if (id.includes('firebase/app')) {
                    return 'vendor-firebase-core';
                }
                if (id.includes('firebase')) {
                    return 'vendor-firebase-other';
                }
                // パスワード強度チェッカー（大きなライブラリなので別チャンク）
                if (id.includes('zxcvbn')) {
                    return 'vendor-zxcvbn';
                }
                // UIコンポーネント
                if (id.includes('@m3e')) {
                    return 'vendor-ui';
                }
                // Lit関連
                if (id.includes('lit')) {
                    return 'vendor-lit';
                }
                // OTPライブラリ
                if (id.includes('otpauth')) {
                    return 'vendor-otp';
                }
                // QRコード関連
                if (id.includes('jsqr')) {
                    return 'vendor-qr';
                }
                // DOMPurify
                if (id.includes('dompurify')) {
                    return 'vendor-security';
                }
                // その他のベンダー
                return 'vendor';
            }
        }
      },
      // ツリーシェイキングの最適化
      treeshake: {
        moduleSideEffects: 'no-external',
        propertyReadSideEffects: false,
        tryCatchDeoptimization: false
      }
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
        ],
        display: "standalone",
        permissions: ["camera"]
      }
    })
  ]
});
