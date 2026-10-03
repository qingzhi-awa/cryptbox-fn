// 端到端加密（E2EE）前端模块。
//
// 密钥模型（与桌面客户端一致）：
//   账号密码 --scrypt(salt=用户名)--> master key（仅存在于浏览器内存）
//   master key --AES-256-GCM 解密--> vault key（随机 32 字节，随账号在服务端同步）
//   vault key --AES-256-GCM--> 条目密文（password / notes）
//
// 服务端只保存 vault_key_enc 与条目密文，永远不持有可解密的密钥。
//
// 加密实现有两条路径：
//   1. WebCrypto（默认）：仅在安全上下文（HTTPS / localhost）可用；
//   2. 纯 JS GCM（@noble/ciphers，降级路径）：仅在用户于引导页显式确认
//      「了解风险后在可信内网继续使用」后启用（allow_insecure_crypto）。
//      两者密文格式完全互通（标准 AES-256-GCM，12 字节 nonce 前置）。
import { scryptAsync } from '@noble/hashes/scrypt'
import { gcm } from '@noble/ciphers/aes.js'

// 与 Go / Rust 端保持一致：N=2^15, r=8, p=1, dkLen=32。
const SCRYPT_PARAMS = { N: 32768, r: 8, p: 1, dkLen: 32 }

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

// vault key 仅保存在内存中，刷新页面即失效（需重新输入账号密码解锁）。
let vaultKey = null

// 降级模式开关：用户在引导页显式确认后，持久化到 localStorage。
// 仅影响当前浏览器，可随时在引导页之外手动清除（清除 localStorage）。
const INSECURE_KEY = 'allow_insecure_crypto'

export function insecureFallbackEnabled() {
  try {
    return typeof localStorage !== 'undefined' && localStorage.getItem(INSECURE_KEY) === 'true'
  } catch (e) {
    return false
  }
}

export function enableInsecureFallback() {
  try {
    localStorage.setItem(INSECURE_KEY, 'true')
  } catch (e) {
    /* ignore */
  }
}

export function disableInsecureFallback() {
  try {
    localStorage.removeItem(INSECURE_KEY)
  } catch (e) {
    /* ignore */
  }
}

// webCryptoAvailable：WebCrypto 是否真实可用（与用户确认状态无关）。
export function webCryptoAvailable() {
  return typeof crypto !== 'undefined' && !!crypto.subtle && typeof crypto.getRandomValues === 'function'
}

// hasCrypto：加密能力是否就绪。纯 JS 实现（@noble/ciphers）已随应用打包，
// 在非安全上下文（HTTP）下自动降级使用，因此始终返回 true。
// 注意：降级意味着登录密码在网络上明文传输，仅建议在可信内网使用。
export function hasCrypto() {
  return true
}

export function isUnlocked() {
  return vaultKey !== null
}

export function setVaultKey(bytes) {
  vaultKey = bytes
}

export function getVaultKey() {
  return vaultKey
}

export function clearVaultKey() {
  if (vaultKey) vaultKey.fill(0)
  vaultKey = null
}

export function randomBytes(n) {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return b
}

// 生成条目的全局唯一同步标识（UUID v4，PT-04）。
// 使用 crypto.getRandomValues（非安全上下文同样可用），不依赖仅在安全上下文
// 可用的 crypto.randomUUID。新建条目即分配，避免同一账号多端按本地自增 id
// 互相覆盖导致静默丢数据。
export function newEntryUUID() {
  const b = randomBytes(16)
  b[6] = (b[6] & 0x0f) | 0x40 // version 4
  b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
  let hex = ''
  for (let i = 0; i < 16; i++) hex += b[i].toString(16).padStart(2, '0')
  return (
    hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) +
    '-' + hex.slice(16, 20) + '-' + hex.slice(20)
  )
}

export function toBase64(bytes) {
  let bin = ''
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000))
  }
  return btoa(bin)
}

export function fromBase64(str) {
  const bin = atob(str)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// 生成 16 字节随机盐并以 base64 返回，作为主密钥派生盐（kdf_salt）上传服务端。
// 相比以用户名作盐，随机盐不随用户名变化，用户改名后既有数据仍可解密。
export function newSalt() {
  return toBase64(randomBytes(16))
}

// 派生 master key：scrypt(密码, salt)。salt 优先取服务端下发的随机盐 kdf_salt；
// 历史账号无盐时由调用方回退传用户名，保证同一账号在任何设备派生出相同密钥。
export function deriveMasterKey(password, salt) {
  return scryptAsync(textEncoder.encode(password), textEncoder.encode(salt), SCRYPT_PARAMS)
}

async function importAesKey(keyBytes) {
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

// 纯 JS GCM 降级实现（@noble/ciphers）：仅在用户于引导页显式确认
// 「了解风险后在可信内网继续使用」后才会走到这里。
// 密文格式与 WebCrypto 完全一致（标准 AES-256-GCM，12 字节 nonce 前置）。
function nobleEncrypt(keyBytes, plainBytes) {
  const iv = randomBytes(12)
  const ct = gcm(keyBytes, iv).encrypt(plainBytes)
  const out = new Uint8Array(iv.length + ct.length)
  out.set(iv, 0)
  out.set(ct, iv.length)
  return toBase64(out)
}

function nobleDecrypt(keyBytes, encoded) {
  const raw = fromBase64(encoded)
  if (raw.length < 13) throw new Error('密文长度不足')
  const pt = gcm(keyBytes, raw.subarray(0, 12)).decrypt(raw.subarray(12))
  return new Uint8Array(pt)
}

// AES-256-GCM 加密原始字节，返回 base64(nonce(12) + ciphertext + tag)。
async function encryptRaw(keyBytes, plainBytes) {
  if (webCryptoAvailable()) {
    const iv = randomBytes(12)
    const key = await importAesKey(keyBytes)
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plainBytes))
    const out = new Uint8Array(iv.length + ct.length)
    out.set(iv, 0)
    out.set(ct, iv.length)
    return toBase64(out)
  }
  return nobleEncrypt(keyBytes, plainBytes)
}

async function decryptRaw(keyBytes, encoded) {
  const raw = fromBase64(encoded)
  if (raw.length < 13) throw new Error('密文长度不足')
  if (webCryptoAvailable()) {
    const key = await importAesKey(keyBytes)
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: raw.subarray(0, 12) },
      key,
      raw.subarray(12)
    )
    return new Uint8Array(pt)
  }
  return nobleDecrypt(keyBytes, encoded)
}

export function encryptString(keyBytes, plaintext) {
  return encryptRaw(keyBytes, textEncoder.encode(plaintext))
}

export async function decryptString(keyBytes, encoded) {
  return textDecoder.decode(await decryptRaw(keyBytes, encoded))
}

// 用 master key 加密/解密 vault key（32 字节原始密钥）。
export function encryptVaultKey(masterKey, vk) {
  return encryptRaw(masterKey, vk)
}

export async function decryptVaultKey(masterKey, encoded) {
  const bytes = await decryptRaw(masterKey, encoded)
  if (bytes.length !== 32) throw new Error('vault key 长度错误')
  return bytes
}

// 条目加解密：仅 password / notes 为密文，其余字段（标题/用户名/网址/分类）为索引元数据，保持明文。
export async function encryptEntries(list) {
  const out = []
  for (const e of list) {
    out.push({
      ...e,
      password: await encryptString(vaultKey, e.password || ''),
      notes: await encryptString(vaultKey, e.notes || '')
    })
  }
  return out
}

export async function decryptEntries(list) {
  const out = []
  for (const e of list) {
    const copy = { ...e }
    try {
      copy.password = await decryptString(vaultKey, e.password || '')
    } catch (err) {
      copy.password = ''
      copy.decryptFailed = true
    }
    try {
      copy.notes = await decryptString(vaultKey, e.notes || '')
    } catch (err) {
      copy.notes = ''
      copy.decryptFailed = true
    }
    out.push(copy)
  }
  return out
}

export async function encryptOne(entry) {
  const [r] = await encryptEntries([entry])
  return r
}

// 单条解密失败（例如旧数据仍由服务端静态密钥加密）时标记，便于提示用户。
export const DECRYPT_FAILED_FLAG = 'decryptFailed'
