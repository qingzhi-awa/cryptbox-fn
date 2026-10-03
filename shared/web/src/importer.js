// CSV / TXT 导入解析（浏览器端）。
//
// 与 Go 端 shared/csv 保持一致：兼容中英文列名、GBK 编码、以及本应用导出的「字段名: 值」TXT 格式。
// 解析在浏览器本地完成，明文不经过服务端。
import { newEntryUUID } from './vault.js'

// 处理编码：UTF-8 直接使用，否则按 GBK（中文 Excel 常见）解码。
function decodeText(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch (e) {
    return new TextDecoder('gbk').decode(bytes)
  }
}

// 规范化表头用于模糊匹配。
function normalizeHeader(s) {
  return String(s)
    .replace(/^\ufeff/, '')
    .toLowerCase()
    .trim()
    .replace(/[\s_\-()/\\.,:：]/g, '')
}

const FIELD_ALIASES = [
  ['password', ['password', 'pass', 'pwd', '密码', '口令', '密碼', 'パスワード', '비밀번호', 'contraseña', 'senha', 'пароль']],
  ['username', ['username', 'user', 'login', 'account', '用户名', '账号', '账户', '登录', '使用者名稱', 'ユーザー名', '사용자명', 'utilisateur', 'benutzername', 'usuario', 'логин']],
  ['url', ['url', 'uri', 'website', '网址', '網址', '链接', '地址']],
  ['notes', ['note', 'remark', '备注', '说明', '注释', '備註', 'メモ', '메모', 'notizen', 'notas', 'заметки']],
  ['category', ['category', 'group', 'folder', '分类', '分组', '目录', '分類', '분류', 'catégorie', 'kategorie', 'categoría', 'категория', 'categoria']],
  ['title', ['title', 'name', '名称', '标题', '网站', '站点', '应用', '服务', '標題', 'タイトル', '제목', 'titre', 'titel', 'título', 'название']]
]

function matchField(h) {
  const n = normalizeHeader(h)
  for (const [field, aliases] of FIELD_ALIASES) {
    for (const alias of aliases) {
      if (n.includes(normalizeHeader(alias))) return field
    }
  }
  return ''
}

// RFC4180 风格 CSV 解析，等价于 Go encoding/csv（跳过空行、支持双引号转义）。
function parseCsvRows(text) {
  const rows = []
  let row = []
  let field = ''
  let inQuotes = false
  let i = 0
  const endField = () => {
    row.push(field)
    field = ''
  }
  const endRow = () => {
    endField()
    if (!(row.length === 1 && row[0] === '')) rows.push(row)
    row = []
  }
  while (i < text.length) {
    const c = text[i]
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"'
          i += 2
          continue
        }
        inQuotes = false
        i++
        continue
      }
      field += c
      i++
      continue
    }
    if (c === '"') {
      inQuotes = true
      i++
      continue
    }
    if (c === ',') {
      endField()
      i++
      continue
    }
    if (c === '\r') {
      if (text[i + 1] === '\n') i++
      endRow()
      i++
      continue
    }
    if (c === '\n') {
      endRow()
      i++
      continue
    }
    field += c
    i++
  }
  if (field !== '' || row.length > 0) endRow()
  return rows
}

// 解析 CSV 内容为密码条目。首行为表头，自动识别常见中英文列名。
export function parseCsvEntries(input) {
  const records = parseCsvRows(decodeText(input))
  if (records.length === 0) throw new Error('文件为空')

  const m = {}
  records[0].forEach((h, i) => {
    const f = matchField(h)
    if (f && m[f] === undefined) m[f] = i
  })
  // 表头无法识别时，按常见顺序兜底：标题、用户名、密码、网址、备注、分类
  if (m.title === undefined && m.password === undefined) {
    m.title = 0
    m.username = 1
    m.password = 2
    m.url = 3
    m.notes = 4
    m.category = 5
  }

  const get = (row, key) => {
    const i = m[key]
    if (i !== undefined && i < row.length) return String(row[i]).trim()
    return ''
  }

  const entries = []
  for (const row of records.slice(1)) {
    const e = {
      title: get(row, 'title'),
      username: get(row, 'username'),
      password: get(row, 'password'),
      url: get(row, 'url'),
      category: get(row, 'category'),
      notes: get(row, 'notes')
    }
    if (e.title === '' && e.username === '' && e.password === '') continue
    entries.push(e)
  }
  return entries
}

// 判断是否为 TXT 导出中的分隔线（全由 - 或 = 组成）。
function isSepLine(s) {
  const t = s.trim()
  if (t === '') return false
  return t.replace(/-/g, '') === '' || t.replace(/=/g, '') === ''
}

// 解析 TXT 内容为密码条目，兼容本应用导出的「字段名: 值」格式。
export function parseTxtEntries(input) {
  const text = decodeText(input).replace(/\r\n/g, '\n').replace(/\r/g, '\n')
  const entries = []
  let cur = {}
  let hasCur = false

  const flush = () => {
    if (hasCur && (cur.title || cur.username || cur.password)) entries.push(cur)
    cur = {}
    hasCur = false
  }

  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim()
    if (line === '') continue
    if (isSepLine(line)) {
      if (line.includes('-')) flush()
      continue
    }
    const idx = line.search(/[:：]/)
    if (idx < 0) continue
    const key = line.slice(0, idx).trim()
    const val = line.slice(idx + 1).trim()
    switch (matchField(key)) {
      case 'title':
        flush()
        cur.title = val
        hasCur = true
        break
      case 'username':
        cur.username = val
        hasCur = true
        break
      case 'password':
        cur.password = val
        hasCur = true
        break
      case 'url':
        cur.url = val
        hasCur = true
        break
      case 'category':
        cur.category = val
        hasCur = true
        break
      case 'notes':
        cur.notes = val
        hasCur = true
        break
      default:
        break
    }
  }
  flush()
  return entries
}

// 补齐条目缺省字段。uuid 为新条目一次性生成的全局唯一同步标识（PT-04）；
// 已有 uuid 的条目原样保留，避免改写既有身份。
export function normalizeEntry(e) {
  return {
    id: 0,
    uuid: e.uuid || newEntryUUID(),
    sort_order: 0,
    title: e.title || '',
    username: e.username || '',
    password: e.password || '',
    url: e.url || '',
    category: e.category || '',
    notes: e.notes || '',
    created_at: '',
    updated_at: '',
    deleted: false
  }
}
