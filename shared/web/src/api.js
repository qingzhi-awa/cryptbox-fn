// 写操作的「POST 入口 ↔ 原方法」双向映射：
// 飞牛统一网关只转发 GET/POST，PUT/DELETE 会被网关自身接管并返回其首页（HTTP 200 非 JSON）。
// 这里默认走 POST 入口；万一某个环境反而只放行原方法，也能自动回退重试一次。
const METHOD_ALTERNATES = {
  'POST /api/vault': 'PUT /api/vault',
  'POST /api/vault/delete': 'DELETE /api/vault',
  'POST /api/vault-key': 'PUT /api/vault-key',
  'POST /api/me/update': 'PUT /api/me',
  'POST /api/settings/update': 'PUT /api/settings',
}
const USERS_ALTERNATES = {
  '/api/users/update': 'PUT',
  '/api/users/delete': 'DELETE',
  '/api/users/status': 'PUT',
}

function alternateFor(method, path) {
  const key = method + ' ' + path.split('?')[0]
  if (METHOD_ALTERNATES[key]) {
    return METHOD_ALTERNATES[key].split(' ')[0] + '|' + METHOD_ALTERNATES[key].split(' ')[1]
  }
  const base = path.split('?')[0]
  if (USERS_ALTERNATES[base]) {
    // POST /api/users/update?id=7 -> PUT /api/users/7
    const id = new URLSearchParams(path.split('?')[1] || '').get('id')
    if (!id) return null
    const suffix = base.endsWith('/status') ? '/status' : ''
    return USERS_ALTERNATES[base] + '|/api/users/' + id + suffix
  }
  return null
}

async function send(method, path, body, token) {
  const headers = { 'Content-Type': 'application/json' }
  // 同时携带两种凭据通道：直连端口时 Authorization 生效；
  // 经飞牛统一网关内嵌打开时该头会被网关剥离，此时由 X-Auth-Token 或同源 Cookie 兜底。
  if (token) {
    headers['Authorization'] = 'Bearer ' + token
    headers['X-Auth-Token'] = token
  }
  // 相对路径请求：兼容 fnOS 统一网关（反向代理可能带应用路径前缀）
  const rel = path.replace(/^\//, '')
  const res = await fetch(rel, {
    method,
    headers,
    credentials: 'same-origin',
    body: body !== undefined ? JSON.stringify(body) : undefined
  })
  const text = await res.text()
  let data = {}
  if (text.trim() !== '') {
    try {
      data = JSON.parse(text)
    } catch (e) {
      // 非空且非 JSON：通常是网关把请求拦截后返回了自己的页面。
      // 把响应开头原文附在错误里，用户直接粘贴即可定位网关返回了什么。
      const snippet = text.replace(/\s+/g, ' ').trim().slice(0, 160)
      const err = new Error(
        '接口返回了非预期内容（HTTP ' +
          res.status +
          '，' +
          method +
          ' ' +
          rel +
          '）。响应开头: «' +
          snippet +
          '» —— 请把本条完整信息反馈给开发者'
      )
      err.code = 'BAD_RESPONSE'
      err.status = res.status
      throw err
    }
  }
  if (!res.ok) {
    const err = new Error(data.error || '请求失败: ' + res.status)
    err.status = res.status
    throw err
  }
  return data
}

async function request(method, path, body, token) {
  try {
    return await send(method, path, body, token)
  } catch (e) {
    // 方法不被转发时，自动改用等效方法重试一次（覆盖两种网关策略）。
    const alt = alternateFor(method, path)
    if (alt && (e.code === 'BAD_RESPONSE' || e.status === 404 || e.status === 405)) {
      const [m, p] = alt.split('|')
      try {
        return await send(m, p, body, token)
      } catch (e2) {
        if (e2.code === 'BAD_RESPONSE') {
          // 两种方式都被网关拦截：合并两次的完整诊断信息，一次反馈即可定位。
          const err = new Error(
            '请求被网关拦截（两种方式均失败）。\n' +
              '第一次 ' +
              method +
              ' ' +
              path +
              ' -> ' +
              e.message +
              '\n第二次 ' +
              m +
              ' ' +
              p +
              ' -> ' +
              e2.message
          )
          err.code = 'BAD_RESPONSE'
          throw err
        }
        throw e2
      }
    }
    throw e
  }
}

export default {
  status: () => request('GET', '/api/status'),
  logout: (t) => request('POST', '/api/logout', {}, t),
  setup: (u, p, vaultKeyEnc, kdfSalt) => request('POST', '/api/setup', { username: u, password: p, vault_key_enc: vaultKeyEnc, kdf_salt: kdfSalt }),
  login: (u, p) => request('POST', '/api/login', { username: u, password: p }),
  register: (data) => request('POST', '/api/register', data),
  publicSettings: () => request('GET', '/api/settings/public'),
  me: (t) => request('GET', '/api/me', undefined, t),
  updateMe: (data, t) => request('POST', '/api/me/update', data, t),
  // 自助改绑邮箱：向新邮箱发送所有权验证码（R7-01）。管理员改他人邮箱不需要验证码。
  sendMyEmailCode: (data, t) => request('POST', '/api/me/email-code', data, t),
  uploadAvatar: (data, t) => request('POST', '/api/me/avatar', data, t),
  // 密码条目：端到端加密，统一走 Vault 协议（整库上传/下载），服务端不透明存储。
  // 写操作一律使用 POST 入口：飞牛统一网关只转发 GET/POST，PUT/DELETE 会被网关自身
  // 接管并返回其首页（HTTP 200 非 JSON）。服务端同时保留了 PUT/DELETE 供直连使用。
  getVault: (t) => request('GET', '/api/vault', undefined, t),
  putVault: (entries, t) => request('POST', '/api/vault', { entries }, t),
  putVaultKey: (vaultKeyEnc, t) => request('POST', '/api/vault-key', { vault_key_enc: vaultKeyEnc }, t),
  // 密码重置后放弃旧密码库：清空本账号条目密文并重置 vault key（不可恢复）。
  deleteVault: (t) => request('POST', '/api/vault/delete', undefined, t),
  // 旧数据迁移：取回服务端静态密钥加密条目的明文，供浏览器用 vault key 重新加密。
  getLegacy: (t) => request('GET', '/api/vault/legacy', undefined, t),
  // 迁移完成上报：服务端落标记后永久关闭 legacy 明文接口（此后返回 410）。
  markLegacyDone: (t) => request('POST', '/api/vault/legacy/done', undefined, t),
  listUsers: (t) => request('GET', '/api/users', undefined, t),
  // 过渡期提示：仍存在服务端可解密旧数据（未迁移）的账号清单。
  legacyPending: (t) => request('GET', '/api/legacy-pending', undefined, t),
  createUser: (u, t) => request('POST', '/api/users', u, t),
  importUsers: (csv, t) => request('POST', '/api/users/import', { csv }, t),
  deleteUser: (id, t) => request('POST', '/api/users/delete?id=' + id, undefined, t),
  updateUserStatus: (id, status, t) => request('POST', '/api/users/status?id=' + id, { status }, t),
  updateUser: (id, data, t) => request('POST', '/api/users/update?id=' + id, data, t),
  listLogs: (t) => request('GET', '/api/logs', undefined, t),
  getSettings: (t) => request('GET', '/api/settings', undefined, t),
  updateSettings: (data, t) => request('POST', '/api/settings/update', data, t),
  testEmail: (email, t) => request('POST', '/api/settings/test-email', { email }, t),
  exportSettings: (t) => request('GET', '/api/settings/export', undefined, t),
  importSettings: (data, t) => request('POST', '/api/settings/import', data, t),
  sendRegisterCode: (email) => request('POST', '/api/register/send-code', { email }),
  sendResetCode: (email) => request('POST', '/api/reset/send-code', { email }),
  resetPassword: (data) => request('POST', '/api/reset', data)
}
