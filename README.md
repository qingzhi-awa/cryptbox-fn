<div align="center">

<!-- 📸 宣传图占位（后续添加宣传图用）：
     1. 把图片放进 docs/ 目录，例如 docs/banner.png
     2. 删除下面两行注释符，即可在页面顶部显示
![CryPtBox 飞牛端宣传图](docs/banner.png)
-->

# 密匣 CryPtBox · 飞牛端

**本地加密密码管理器的飞牛 fnOS 服务端 —— Web 管理后台 + 多端同步 API**

`飞牛 fnOS` `Go` `Gin` `Vue 3` `SQLite` `AES-256-GCM` `JWT` `FN Connect`

> 本仓库为**飞牛端服务端**（部署于飞牛 fnOS，提供 Web 管理后台与多端同步 API）。客户端（Windows / macOS / Linux 桌面应用）见 [密匣主仓库](https://github.com/qingzhi-awa/cryptbox)。

</div>

---

## 特性

- **Web 管理后台**：内嵌 Vue 3 单页应用，浏览器即可管理密码库、用户与系统设置
- **多端同步 API**：RESTful 接口 + JWT 认证，客户端登录后可一键上传 / 下载 / 合并密码库
- **本地加密存储**：密码条目使用 AES-256-GCM 加密落盘，加密密钥由服务端生成并持久化，绝不外泄
- **回收站**：删除数据软删除，支持单条恢复、彻底删除、一键清空，按保留天数自动清理过期数据
- **用户管理**：管理员可添加 / 导入 / 删除 / 更新用户，设置角色（管理员 / 普通用户）与启用状态
- **邮件服务**：SMTP 内置 QQ / 126 / 163 / Gmail / Outlook 常见服务商，支持注册、找回密码的邮箱验证码与测试邮件
- **操作日志**：记录登录、增删改、配置变更等关键操作，便于审计追溯
- **配置导入导出**：系统设置（含 SMTP 等）支持一键导出 / 导入 JSON，便于备份迁移
- **多语言**：中文简体 / 繁体、英、日、韩、德、西、法、葡、俄 10 种语言
- **安装向导**：首次安装引导配置超级管理员账号与 SMTP 邮件，须同意条款且测试邮件通过后才可完成安装

## 安装

1. 在飞牛 fnOS 应用中心安装 `cryptbox.fpk`（见 [Releases](../../releases) 或本地构建产物）
2. 安装向导中设置超级管理员账号（用户名 / 密码 / 邮箱）
3. 按需配置 SMTP 邮件（用于注册与找回密码），测试通过后完成安装
4. 完成后可从飞牛桌面打开，或浏览器直连 `http://<NAS IP>:5201`

## 远程访问

| 方式 | 说明 |
|------|------|
| 局域网 | 浏览器直连 `http://<NAS IP>:5201`，或客户端局域网自动扫描 |
| FN Connect | 飞牛账号远程访问，`https://fnos.net/<FN ID>/app/cryptbox/` |
| DDNS / 公网 | 自定义域名 + HTTPS 反向代理到 `5201` 端口 |

> 服务端同时监听 TCP `5201` 端口与飞牛统一网关 Unix Socket，三种访问方式可并存。

## 从源码构建

```powershell
# 进入 fnos-server 目录
cd fnos-server

# 一键构建：前端构建 + 交叉编译（amd64/arm64）+ 打包 fpk
.\build.ps1
```

构建产物：

- `fnos-server/cryptbox-x86-0.2.3.fpk`（x86 架构）
- `fnos-server/cryptbox-arm-0.2.3.fpk`（arm 架构）

> 英文版位于 `fnos-server/cryptbox-en/`：复制 `cryptbox` 目录、替换英文资源与编译产物后，用 `fnpack build -d cryptbox-en` 打包。

## 目录结构

```
.
├── fnos-server/              # 飞牛端入口与打包
│   ├── main.go               # 服务入口（TCP 5201 + 网关 Unix Socket）
│   ├── build.ps1             # 一键构建脚本
│   └── cryptbox/             # fnOS 应用打包配置
│       ├── manifest          # 应用清单（appname / version / 端口等）
│       ├── wizard/           # 安装 / 卸载向导（静态表单 JSON）
│       ├── cmd/              # 生命周期脚本（install / config / upgrade / uninstall）
│       ├── app/ui/           # 飞牛桌面入口（图标 + 打开方式 config）
│       └── config/           # 权限 / 资源声明
└── shared/                   # 核心共享源码
    ├── auth/                 # 密码哈希、JWT、SMTP 邮件
    ├── config/               # 运行时配置（端口 / 数据库 / Socket）
    ├── crypto/               # AES-256-GCM 加解密
    ├── csv/                  # CSV 解析
    ├── db/                   # SQLite 连接、迁移、元数据
    ├── handlers/             # Gin 路由与全部 HTTP 处理器
    ├── log/                  # 操作日志
    └── web/                  # 内嵌 Web 管理后台（Vue 3，go:embed）
```

## 技术栈

Go 1.26 · Gin · Vue 3 · vue-i18n · SQLite（modernc 纯 Go 驱动，无 CGO）· JWT

## 更新日志

各版本发布说明见 [Releases](../../releases)。

<!-- 📸 更多截图占位（后续添加）：
| Web 管理后台 | 系统设置 |
|--------|----------|
| ![Web 管理后台](docs/screenshot-web.png) | ![系统设置](docs/screenshot-settings.png) |
-->
