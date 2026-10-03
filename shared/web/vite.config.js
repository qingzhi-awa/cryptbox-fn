import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  base: './',
  // 构建时注入前端版本号（打包脚本通过 APP_VERSION 环境变量传入，与 manifest 一致）。
  // 用于运行时与服务端 /api/status 的版本比对：不一致则自动刷新页面（消除旧缓存页面）。
  define: {
    __APP_VERSION__: JSON.stringify(process.env.APP_VERSION || 'dev')
  },
  plugins: [vue()]
})
