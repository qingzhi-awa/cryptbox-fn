<div align="center">

<!-- 📸 宣传图占位（后续添加宣传图用）：
     1. 把图片放进 docs/ 目录，例如 docs/banner.png
     2. 删除下面两行注释符，即可在页面顶部显示
![CryPtBox 飞牛端宣传图](docs/banner.png)
-->

# 密匣 CryPtBox · 飞牛端

**本地优先密码管理器的飞牛 fnOS 服务端 —— Web 管理后台 + 多端同步 API**

`飞牛 fnOS` `Go` `Gin` `Vue 3` `SQLite` `AES-256-GCM` `JWT` `FN Connect`

> 本仓库为**飞牛端服务端**（部署于飞牛 fnOS，提供 Web 管理后台与多端同步 API）。客户端（Windows / macOS / Linux 桌面应用）见 [密匣主仓库](https://github.com/qingzhi-awa/cryptbox)。
>
> 当前版本：**0.2.36**

</div>

---

## 特性

### Web 管理后台

- **内嵌单页应用**：Vue 3 + vue-i18n 编译进 Go 二进制（`go:embed`），浏览器即可管理密码库、用户与系统设置
- **密码库管理**：条目增删改查、分类、回收站（恢复 / 彻底删除 / 清空）、置顶与拖拽排序
- **用户管理**：添加 / 导入 / 删除 / 更新用户，设置角色与启用状态
- **操作日志**：记录登录、增删改、配置变更等关键操作，便于审计追溯
- **配置导入导出**：系统设置（含 SMTP）一键导出 / 导入 JSON，敏感字段自动掩码
- **多语言**：中文简体 / 繁体、英、日、韩、德、西、法、葡、俄 10 种语言

### 多端同步 API

- **RESTful 接口 + JWT 认证**：客户端登录后可一键上传 / 下载 / 合并密码库
- **端到端加密**：口令与备注在客户端即加密为密文，服务端**无法解密**（vault key 由客户端主密钥保护）
- **条目按 UUID 归并**：多设备互不覆盖，避免并发同步丢数据
- **证书指纹接口**：`GET /api/fingerprint` 供客户端做首次信任与变更校验

### 账号与权限

- **三级角色**：超级管理员 / 管理员 / 普通用户
- **权限分级**：管理员只能管理普通用户，**仅超级管理员**可创建管理员或授予管理员角色
- **邮箱唯一化**：注册、建号、导入、改绑均校验邮箱占用；登录（用户名优先、邮箱兜底）与找回密码不再受同邮箱多账号干扰
- **邮箱验证码**：注册、找回密码、自助改绑邮箱各走独立用途的验证码
- **登录保护**：失败锁定（含来源维度）+ 全局限流，避免账号被恶意锁定
- **令牌版本**：改密 / 重置口令后此前签发的令牌立即失效（登出不会踢掉其他设备）

### 部署与运维

- **安装向导**：首次安装引导配置超级管理员账号与 SMTP 邮件，须同意条款且测试邮件通过后才可完成安装
- **邮件服务**：SMTP 内置 QQ / 126 / 163 / Gmail / Outlook 常见服务商，报文符合 RFC 2047（中文主题正确编码）
- **访问方式**：TCP `5201` 与飞牛统一网关 Unix Socket 并存，支持局域网 / FN Connect / DDNS
- **安全存储**：加密密钥与 JWT 密钥落在数据目录下 `0600` 独立文件（不再存数据库）；SMTP 口令加密落库

## 安装

1. 在飞牛 fnOS 应用中心安装 `fnos-cryptbox-x86-0.2.36.fpk`（见 [Releases](../../releases) 或本地构建产物）
2. 安装向导中设置超级管理员账号（用户名 / 密码 / 邮箱）
3. 按需配置 SMTP 邮件（用于注册与找回密码），测试通过后完成安装
4. 完成后可从飞牛桌面打开，或浏览器直连 `http://<NAS IP>:5201`

> 英文版使用 `fygo-cryptbox-*.fpk`。

## 远程访问

| 方式 | 说明 |
|------|------|
| 局域网 | 浏览器直连 `http://<NAS IP>:5201`，或客户端局域网自动扫描 |
| FN Connect | 飞牛账号远程访问，`https://fnos.net/<FN ID>/app/cryptbox/` |
| DDNS / 公网 | 自定义域名 + HTTPS 反向代理到 `5201` 端口 |

> 服务端同时监听 TCP `5201` 端口与飞牛统一网关 Unix Socket，三种访问方式可并存。

### ⚠️ 网关 / 反向代理部署必读

- 经飞牛统一网关或反向代理访问时，**必须设置 `TRUST_PROXY=true`**，否则来源 IP 会退化为代理地址，导致「登录失败锁定」「接口限流」的来源维度失效。
- 网关只转发 `GET` / `POST` 且会剥离 `Authorization` 头，因此写操作保留了 POST 等价入口，鉴权支持三通道：`Authorization`、`X-Auth-Token`、会话 Cookie（`HttpOnly`，`Secure` 按反代后的真实协议判定）。

## 安全设计

- **加密参数三端一致**：scrypt（N=2¹⁵, r=8, p=1, len=32）+ AES-256-GCM，密文格式 `base64(nonce12 ‖ ciphertext)`，与桌面端 Rust 实现、网页端 JS 实现保持完全一致
- **内容安全策略**：后台页面 CSP 为 `script-src 'self'`（不使用 `unsafe-eval`），`style-src` 保留 `'unsafe-inline'` 以适配 Vue 运行时样式注入
- **会话管理**：令牌只存内存 + 服务端 `HttpOnly` Cookie，不落前端存储
- **限流与锁定**：登录 / 注册 / 发送验证码 / 初始化接口均按来源 IP 与账号双维度计数，计数表周期性清理
- **口令哈希**：bcrypt（cost = 12）
- **迁移守卫**：初始化超管的一次性迁移带版本标记，仅在库中无超级管理员时执行，杜绝重启提权

## 已知取舍

- **反向代理部署必须设 `TRUST_PROXY=true`**：否则来源 IP 退化为代理地址，「登录失败锁定」「接口限流」的来源维度失效（见上节）。
- **邮箱唯一化**：同一邮箱同时只能绑定一个账号（改绑需通过新邮箱验证码）。升级前若存量库已有重复邮箱，部分唯一索引会告警跳过、不阻塞启动，需管理员先归并重复邮箱再重启。
- **明文迁移接口** `GET /api/vault/legacy` 为历史遗留，计划在 0.3.0 移除。
- **CSP 保留 `style-src 'unsafe-inline'`**：Vue 运行时会注入内联样式，属既有取舍（`script-src` 已收敛为 `'self'`，不含 `unsafe-eval`）。
- **解锁材料改写需二次验证口令（R13-02 起）**：账号**已有** `vault_key_enc` 时，改写 `kdf_salt` / `vault_key_enc`（`PUT|POST /api/me`、`PUT|POST /api/vault-key`）必须在请求体中带 `current_password`，否则返回 400——避免持有泄露令牌者仅凭令牌不可逆地破坏本地解锁材料。首次启用端到端加密（服务端 `vault_key_enc` 为空）不受影响。**升级提示**：旧版桌面客户端在「旧密码恢复」路径未携带该字段，会被新服务端拒绝，需同步升级客户端。

## 从源码构建

```powershell
# 进入 fnos-server 目录
cd fnos-server

# 一键构建：前端构建 + 交叉编译（amd64 / arm64）+ 打包 fpk
.\build.ps1
```

构建产物：

- `fnos-server/fnos-cryptbox-x86-0.2.36.fpk`（x86_64，中文）
- `fnos-server/fnos-cryptbox-arm-0.2.36.fpk`（arm64，中文）
- `fnos-server/fygo-cryptbox-x86-0.2.36.fpk`（x86_64，英文）
- `fnos-server/fygo-cryptbox-arm-0.2.36.fpk`（arm64，英文）

> 英文版位于 `fnos-server/cryptbox-en/`：复制 `cryptbox` 目录、替换英文资源与编译产物后，用 `fnpack build -d cryptbox-en` 打包。
>
> 打包需 `fnpack` 位于 `PATH`；前端产物通过 `go:embed` 编入 Go 二进制，fpk 内的 `app/www/` 为空属正常现象。

## API 概览

| 分类 | 端点 |
|------|------|
| 状态与指纹 | `GET /api/status`、`GET /api/fingerprint` |
| 认证 | `POST /api/setup`、`/api/login`、`/api/register`、`/api/me/password`、`/api/me/email-code` |
| 密码库同步 | `/api/vault/push`、`/api/vault/pull`、`/api/vault/merge` |
| 用户管理 | `/api/users`（增删改查）、`/api/users/import` |
| 设置与日志 | `/api/settings`、`/api/logs` |
| 回收站 | `/api/trash`（列表 / 恢复 / 彻底删除 / 清空） |

> 写操作同时提供 POST 入口以兼容飞牛网关；鉴权支持 `Authorization`、`X-Auth-Token` 与 Cookie 三通道。

## 目录结构

```
.
├── fnos-server/              # 飞牛端入口与打包
│   ├── main.go               # 服务入口（TCP 5201 + 网关 Unix Socket）
│   ├── build.ps1             # 一键构建脚本
│   ├── cryptbox/             # fnOS 应用打包配置（中文）
│   │   ├── manifest          # 应用清单（appname / version / 端口等）
│   │   ├── wizard/           # 安装 / 卸载向导（静态表单 JSON）
│   │   ├── cmd/              # 生命周期脚本（install / config / upgrade / uninstall）
│   │   ├── app/ui/           # 飞牛桌面入口（图标 + 打开方式 config）
│   │   └── config/           # 权限 / 资源声明
│   └── cryptbox-en/          # 英文版打包配置
└── shared/                   # 核心共享源码
    ├── auth/                 # 口令哈希、JWT、SMTP 邮件
    ├── config/               # 运行时配置（端口 / 数据库 / Socket）
    ├── crypto/               # AES-256-GCM 加解密
    ├── csv/                  # CSV 解析
    ├── db/                   # SQLite 连接、迁移、元数据
    ├── handlers/             # Gin 路由与全部 HTTP 处理器
    ├── log/                  # 操作日志
    ├── ratelimit/            # 内存限流与定期清理
    ├── tlsutil/              # 自签证书生成 / 加载
    ├── uuid/                 # UUIDv5 命名空间（条目同步标识）
    ├── version/              # 版本信息
    └── web/                  # 内嵌 Web 管理后台（Vue 3，go:embed）
```

## 技术栈

Go 1.26 · Gin · Vue 3 · vue-i18n · SQLite（modernc 纯 Go 驱动，无 CGO）· JWT · bcrypt · AES-256-GCM

## 更新日志

各版本发布说明见 [Releases](../../releases)。

<!-- 📸 更多截图占位（后续添加）：
| Web 管理后台 | 系统设置 |
|--------|----------|
| ![Web 管理后台](docs/screenshot-web.png) | ![系统设置](docs/screenshot-settings.png) |
-->
