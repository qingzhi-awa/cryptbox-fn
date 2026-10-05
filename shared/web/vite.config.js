import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  base: './',
  // 构建时注入前端版本号（打包脚本通过 APP_VERSION 环境变量传入，与 manifest 一致）。
  // 用于运行时与服务端 /api/status 的版本比对：不一致则自动刷新页面（消除旧缓存页面）。
  //
  // __INTLIFY_JIT_COMPILATION__ = true（R9-06）：vue-i18n 默认走"生成函数源码再
  // new Function 求值"的编译路径，这要求 CSP 放行 'unsafe-eval'。开启 JIT 编译后，
  // vue-i18n 改用内置 AST 解释器（不需要 eval）；且该开关在构建期被字面量替换，
  // 使另一分支（compileToFunction）成为死代码被 tree-shake，产物中不再含 new Function。
  define: {
    __APP_VERSION__: JSON.stringify(process.env.APP_VERSION || 'dev'),
    __INTLIFY_JIT_COMPILATION__: true
  },
  plugins: [vue()]
})
