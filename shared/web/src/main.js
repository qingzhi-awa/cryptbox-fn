import { createApp } from 'vue'
import App from './App.vue'
import i18n from './i18n'
import './style.css'

// ===== 主题（auto=跟随系统 / light / dark）=====
// 启动时立即应用，避免闪白；auto 模式监听系统深浅色变化实时切换。
export function resolveTheme(mode) {
  if (mode !== 'light' && mode !== 'dark') {
    try {
      return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
    } catch (e) {
      return 'light'
    }
  }
  return mode
}
export function applyTheme() {
  let mode = 'auto'
  try {
    mode = localStorage.getItem('theme') || 'auto'
  } catch (e) {
    /* ignore */
  }
  document.documentElement.setAttribute('data-theme', resolveTheme(mode))
}
applyTheme()
try {
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    let mode = 'auto'
    try {
      mode = localStorage.getItem('theme') || 'auto'
    } catch (e) {
      /* ignore */
    }
    if (mode === 'auto') applyTheme()
  })
} catch (e) {
  /* 旧浏览器无此 API，忽略 */
}

// 兜底错误展示：任何未捕获异常都在页面上可见。
// 起因：内嵌/网关环境下曾出现「整页空白」且无从排查，此处把异常直接渲染出来。
function showFatal(msg) {
  try {
    let box = document.getElementById('cryptbox-fatal')
    if (!box) {
      box = document.createElement('div')
      box.id = 'cryptbox-fatal'
      box.style.cssText =
        'position:fixed;left:0;right:0;bottom:0;z-index:99999;max-height:45vh;overflow:auto;' +
        'background:#fff3cd;color:#4a3200;border-top:1px solid #e0c36b;' +
        'font:12px/1.55 ui-monospace,Consolas,monospace;padding:8px 12px;white-space:pre-wrap'
      document.body.appendChild(box)
    }
    box.textContent = '页面出现异常（应用可能未完全加载，请把下方信息反馈给管理员）：\n' + msg
  } catch (e) {
    /* 极端情况下忽略 */
  }
}

window.addEventListener(
  'error',
  (e) => {
    const t = e.target
    if (t && (t.src || t.href)) {
      showFatal('资源加载失败: ' + (t.src || t.href))
      return
    }
    showFatal(e.message || String(e))
  },
  true
)
window.addEventListener('unhandledrejection', (e) => {
  const r = e.reason
  showFatal(String((r && (r.stack || r.message)) || r))
})

const app = createApp(App)
app.use(i18n)
app.config.errorHandler = (err, _inst, info) => {
  const msg = (err && (err.stack || err.message)) || String(err)
  console.error('[cryptbox] 未捕获异常:', msg, info)
  showFatal(msg + '\n(位置: ' + info + ')')
}
app.mount('#app')

// 版本自检：前端构建版本（__APP_VERSION__）与服务端版本不一致时，
// 说明浏览器在跑旧缓存页面（升级后常见）—— 自动刷新一次以加载新前端。
// 服务端对未认证请求只返回版本摘要（build），因此这里比较摘要而非精确版本号；
// 摘要算法须与 Go 侧 version.BuildTagOf 保持一致（FNV-1a 32 位）。
function buildTagOf(v) {
  let h = 2166136261
  for (let i = 0; i < v.length; i++) {
    h ^= v.charCodeAt(i)
    h = Math.imul(h, 16777619) >>> 0
  }
  return h.toString(16).padStart(8, '0')
}
;(async () => {
  try {
    if (__APP_VERSION__ === 'dev') return
    const res = await fetch('api/status', { cache: 'no-store' })
    if (!res.ok) return
    const st = await res.json()
    const mine = buildTagOf(String(__APP_VERSION__))
    if (!st.build || st.build === mine) return
    const key = 'cryptbox_reload_for_' + st.build
    if (sessionStorage.getItem(key)) return
    sessionStorage.setItem(key, '1')
    console.info('[cryptbox] 服务端版本与页面版本不一致，自动刷新')
    location.reload()
  } catch (e) {
    /* 版本自检失败不影响使用 */
  }
})()
