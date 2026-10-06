<template>
  <select v-model="lang" class="lang-select lang-fixed" @change="changeLang">
    <option value="zh-CN">简体中文</option>
    <option value="zh-TW">繁體中文</option>
    <option value="en">English</option>
    <option value="ja">日本語</option>
    <option value="ko">한국어</option>
    <option value="fr">Français</option>
    <option value="de">Deutsch</option>
    <option value="es">Español</option>
    <option value="ru">Русский</option>
    <option value="pt">Português</option>
  </select>
  <!-- 登录 / 注册 / 找回密码（非加密环境下自动使用纯 JS 降级加密，不再阻断） -->
  <div v-if="!token && !sessionAuth" class="gate">
    <div class="gate-card">
      <h1>{{ gateTitle }}</h1>

      <template v-if="gateMode === 'setup'">
        <p class="sub">{{ $t('login.setupHint') }}</p>
        <input v-model="setupForm.username" :placeholder="$t('login.username')" />
        <input v-model="setupForm.password" type="password" :placeholder="$t('login.password')" @keyup.enter="doSetup" />
        <button class="btn-primary" @click="doSetup">{{ $t('login.setupSubmit') }}</button>
      </template>

      <template v-else-if="gateMode === 'login'">
        <input v-model="loginForm.username" :placeholder="$t('login.usernameOrEmail')" @keyup.enter="login" />
        <input v-model="loginForm.password" type="password" :placeholder="$t('login.password')" @keyup.enter="login" />
        <button class="btn-primary" @click="login">{{ $t('login.submit') }}</button>
        <div v-if="!isAdminLogin" class="gate-links">
          <button v-if="allowReg" class="link" @click="switchGate('register')">{{ $t('login.toRegister') }}</button>
          <button class="link" @click="switchGate('forgot')">{{ $t('login.forgot') }}</button>
        </div>
      </template>

      <template v-else-if="gateMode === 'register'">
        <p v-if="!allowReg" class="sub">{{ $t('login.registerClosed') }}</p>
        <template v-else>
          <input v-model="regForm.username" :placeholder="$t('login.username')" />
          <input v-model="regForm.email" :placeholder="$t('users.email')" />
          <input v-model="regForm.password" type="password" :placeholder="$t('login.password')" />
          <div class="code-row">
            <input v-model="regForm.code" :placeholder="$t('login.code')" />
            <button class="btn-ghost" @click="sendRegCode">{{ $t('login.sendCode') }}</button>
          </div>
          <button class="btn-primary" @click="register">{{ $t('login.register') }}</button>
        </template>
        <div class="gate-links">
          <button class="link" @click="switchGate('login')">{{ $t('login.back') }}</button>
        </div>
      </template>

      <template v-else>
        <input v-model="resetForm.email" :placeholder="$t('users.email')" />
        <div class="code-row">
          <input v-model="resetForm.code" :placeholder="$t('login.code')" />
          <button class="btn-ghost" @click="sendResetCode">{{ $t('login.sendCode') }}</button>
        </div>
        <input v-model="resetForm.password" type="password" :placeholder="$t('login.newPassword')" />
        <button class="btn-primary" @click="resetPassword">{{ $t('login.resetSubmit') }}</button>
        <div class="gate-links">
          <button class="link" @click="switchGate('login')">{{ $t('login.back') }}</button>
        </div>
      </template>

      <p v-if="error" class="error">{{ error }}</p>
      <p v-else-if="msg" class="msg">{{ msg }}</p>
    </div>
  </div>

  <!-- 解锁密码库（端到端加密：需在本地用账号密码派生密钥，服务端不参与） -->
  <div v-else-if="!vaultUnlocked" class="gate">
    <div class="gate-card">
      <h1>{{ $t('login.unlockTitle') }}</h1>
      <p class="sub">{{ $t('login.unlockHint') }}</p>
      <input v-model="unlockForm.password" type="password" :placeholder="$t('login.password')" @keyup.enter="unlockVault" />
      <button class="btn-primary" @click="unlockVault">{{ $t('login.unlockSubmit') }}</button>
      <div class="gate-links">
        <button class="link" @click="logout">{{ $t('header.logout') }}</button>
        <button class="link" @click="vaultRecovery = !vaultRecovery">{{ $t('login.recoverTitle') }}</button>
      </div>
      <!-- 密码曾被重置时的恢复路径：旧密码恢复（数据无损）或清空重建 -->
      <div v-if="vaultRecovery" class="recovery">
        <p class="sub">{{ $t('login.recoverHint') }}</p>
        <input v-model="recoverForm.oldPassword" type="password" :placeholder="$t('login.recoverOldPassword')" />
        <button class="btn-primary" @click="recoverVault">{{ $t('login.recoverSubmit') }}</button>
        <button class="link" @click="resetVaultData">{{ $t('login.resetVault') }}</button>
      </div>
      <p v-if="unlockError" class="error">{{ unlockError }}</p>
    </div>
  </div>

  <!-- 主界面 -->
  <div v-else class="app">
    <header class="topbar">
      <h1>{{ $t('app.title') }}</h1>
      <div class="user-info">
        <div class="user-menu" @click="menuOpen = !menuOpen">
          <img v-if="myAvatar" :src="avatarUrl(myId)" class="avatar" alt="" />
          <span v-else class="avatar avatar-fallback">{{ (username || '?').charAt(0).toUpperCase() }}</span>
          <span class="user-name">{{ username }}</span>
          <span class="caret">▾</span>
          <div v-if="menuOpen" class="user-dropdown" @click.stop>
            <button class="dropdown-item" @click="openMe(); menuOpen = false">{{ $t('me.edit') }}</button>
            <button class="dropdown-item" @click="lock">{{ $t('header.lock') }}</button>
            <button class="dropdown-item" @click="logout">{{ $t('header.logout') }}</button>
          </div>
        </div>
      </div>
    </header>
    <div v-if="menuOpen" class="menu-backdrop" @click="menuOpen = false"></div>

    <div class="layout">
      <nav class="sidebar">
        <button :class="{ active: tab === 'passwords' }" @click="switchTab('passwords')">{{ $t('tabs.passwords') }}</button>
        <button :class="{ active: tab === 'trash' }" @click="switchTab('trash')">{{ $t('tabs.trash') }}</button>
        <button v-if="isAdmin" :class="{ active: tab === 'users' }" @click="switchTab('users')">
          {{ $t('tabs.users') }}
        </button>
        <button v-if="isAdmin" :class="{ active: tab === 'logs' }" @click="switchTab('logs')">{{ $t('tabs.logs') }}</button>
        <button v-if="isAdmin" :class="{ active: tab === 'settings' }" @click="switchTab('settings')">{{ $t('tabs.settings') }}</button>
        <button v-if="isAdmin" :class="{ active: tab === 'about' }" @click="switchTab('about')">{{ $t('tabs.about') }}</button>
        <div class="sidebar-footer">
          <button class="theme-toggle" @click="cycleTheme" :title="themeLabel">
            <span class="theme-icon">{{ themeIcon }}</span>
          </button>
          <a
            class="gh-link"
            href="https://github.com/qingzhi-awa/cryptbox-fn"
            target="_blank"
            rel="noopener"
            :title="$t('about.github')"
          >
            <svg viewBox="0 0 16 16" width="18" height="18" fill="currentColor" aria-hidden="true">
              <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
            </svg>
          </a>
        </div>
      </nav>

      <div class="content">

    <!-- 密码管理 -->
    <div v-if="tab === 'passwords'" class="panel">
      <div class="toolbar">
        <div class="toolbar-main">
          <input v-model="search" :placeholder="$t('toolbar.search')" />
          <button class="btn-primary" @click="startAdd">{{ $t('toolbar.add') }}</button>
        </div>
        <div class="toolbar-sub hide-mobile">
          <select v-model="ioFormat" class="btn-ghost menu-select" @change="onIO">
            <option value="" selected>{{ $t('toolbar.io') }}</option>
            <option value="import-csv">{{ $t('toolbar.import') }} CSV</option>
            <option value="import-txt">{{ $t('toolbar.import') }} TXT</option>
            <option value="export-csv">{{ $t('toolbar.export') }} CSV</option>
            <option value="export-txt">{{ $t('toolbar.export') }} TXT</option>
          </select>
          <button class="btn-ghost" @click="downloadTemplate">{{ $t('toolbar.template') }}</button>
        </div>
        <input ref="fileInput" type="file" accept=".csv,.txt,text/csv,text/plain" style="display:none" @change="importFile" />
      </div>

      <div class="list grid-list">
        <div
          v-for="e in filtered"
          :key="e.id"
          class="entry"
          :class="{ 'entry-pinned': e.pinned, 'entry-dragging': dragId === e.id, 'entry-drop-target': dragOverId === e.id && dragId !== e.id }"
          :draggable="canDrag"
          :title="canDrag ? $t('list.dragHint') : ''"
          @dragstart="onDragStart(e)"
          @dragover.prevent="onDragOver(e)"
          @dragleave="onDragLeave(e)"
          @drop.prevent="onDrop(e)"
          @dragend="onDragEnd"
        >
          <div class="entry-head">
            <div class="title">
              <span v-if="e.pinned" class="pin-mark" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="12" height="12">
                  <path d="M12 2l2.4 6.2 6.6.5-5 4.3 1.5 6.4L12 16l-5.5 3.4 1.5-6.4-5-4.3 6.6-.5z" fill="currentColor"></path>
                </svg>
              </span>
              <span>{{ e.title }}</span>
            </div>
            <div class="ops">
              <button class="btn-ghost pin-btn" :class="{ 'pin-on': e.pinned }" @click="togglePin(e)">
                {{ e.pinned ? $t('list.unpin') : $t('list.pin') }}
              </button>
              <button class="btn-ghost" @click="startEdit(e)">{{ $t('list.edit') }}</button>
              <button class="btn-danger" @click="remove(e)">{{ $t('list.delete') }}</button>
            </div>
          </div>
          <div class="entry-meta">
            <div class="meta-line">
              <span class="label">{{ $t('modal.url') }}:</span>
              <span class="field" @click="copyText(e.url)">{{ e.url || $t('list.none') }}</span>
              <button v-if="e.url" class="copy-btn" @click="copyText(e.url)">{{ $t('list.copy') }}</button>
            </div>
            <div class="meta-line">
              <span class="label">{{ $t('modal.username') }}:</span>
              <span class="field" @click="copyText(e.username)">{{ e.username || $t('list.none') }}</span>
              <button v-if="e.username" class="copy-btn" @click="copyText(e.username)">{{ $t('list.copy') }}</button>
            </div>
            <div class="meta-line">
              <span class="label">{{ $t('modal.password') }}:</span>
              <span class="mono field" @click="copyText(e.password)">{{ revealed.has(e.id) ? e.password : '••••••••' }}</span>
              <button class="mini" @click="toggleReveal(e.id)">
                {{ revealed.has(e.id) ? $t('list.hide') : $t('list.show') }}
              </button>
              <button class="copy-btn" @click="copyText(e.password)">{{ $t('list.copy') }}</button>
            </div>
            <div class="meta-line">
              <span class="label">{{ $t('modal.category') }}:</span>
              <span class="field" @click="copyText(e.category)">{{ e.category || $t('list.none') }}</span>
            </div>
            <div class="meta-line">
              <span class="label">{{ $t('modal.notes') }}:</span>
              <span class="field" @click="copyText(e.notes)">{{ e.notes || $t('list.none') }}</span>
            </div>
          </div>
        </div>
        <div v-if="filtered.length === 0" class="empty">{{ $t('list.empty') }}</div>
      </div>
    </div>

    <!-- 回收站 -->
    <div v-if="tab === 'trash'" class="panel">
      <div class="toolbar">
        <div class="toolbar-main">
          <button class="btn-danger" :disabled="trash.length === 0" @click="emptyTrash">{{ $t('trash.emptyTrash') }}</button>
        </div>
      </div>
      <div class="list grid-list">
        <div v-for="e in trash" :key="e.id" class="entry">
          <div class="entry-head">
            <div class="title">{{ e.title }}</div>
            <div class="ops">
              <button class="btn-ghost" @click="restoreEntry(e.id)">{{ $t('trash.restore') }}</button>
              <button class="btn-danger" @click="purgeEntry(e.id)">{{ $t('trash.purge') }}</button>
            </div>
          </div>
          <div class="entry-meta">
            <div class="meta-line">
              <span class="label">{{ $t('modal.username') }}:</span>
              <span class="field">{{ e.username || '—' }}</span>
            </div>
            <div class="meta-line">
              <span class="label">{{ $t('modal.url') }}:</span>
              <span class="field">{{ e.url || $t('list.none') }}</span>
            </div>
          </div>
        </div>
        <div v-if="trash.length === 0" class="empty">{{ $t('trash.empty') }}</div>
      </div>
    </div>

    <!-- 用户管理 -->
    <div v-if="tab === 'users'" class="panel">
      <div class="toolbar">
        <button class="btn-primary" @click="openAddUser">{{ $t('users.add') }}</button>
        <div class="toolbar-sub">
          <button class="btn-ghost hide-mobile" @click="exportUsers">{{ $t('users.export') }}</button>
          <button class="btn-ghost hide-mobile" @click="$refs.userFileInput.click()">{{ $t('users.import') }}</button>
          <button class="btn-ghost hide-mobile" @click="downloadUserTemplate">{{ $t('users.templateBtn') }}</button>
          <input ref="userFileInput" type="file" accept=".csv,text/csv" style="display:none" @change="importUsersFile" />
        </div>
      </div>
      <!-- 过渡期提示：仍有账号存在服务端可解密旧数据（未完成端到端迁移） -->
      <div v-if="legacyPending.length" class="notice-warn">
        {{ $t('users.legacyPending', { n: legacyPending.length, v: legacyRemoveVersion }) }}
      </div>
      <div class="list">
        <div v-for="u in users" :key="u.id" class="row">
          <img v-if="u.avatar" :src="avatarUrl(u.id)" class="avatar" alt="" />
          <span v-else class="avatar avatar-fallback">{{ (u.username || '?').charAt(0).toUpperCase() }}</span>
          <div class="main">
            <div class="title">#{{ u.id }} {{ u.username }}</div>
            <div class="meta">
              <span class="tag">{{ roleLabel(u.role) }}</span>
              <span :class="u.status === 'active' ? 'ok' : 'off'">
                {{ u.status === 'active' ? $t('users.active') : $t('users.disabled') }}
              </span>
              <span v-if="u.email">{{ u.email }}</span>
            </div>
          </div>
          <div class="ops" v-if="canManageUser(u)">
            <button class="btn-ghost" @click="startEditUser(u)">{{ $t('users.edit') }}</button>
            <button class="btn-ghost" @click="toggleStatus(u)">
              {{ u.status === 'active' ? $t('users.disable') : $t('users.enable') }}
            </button>
            <button class="btn-danger" @click="removeUser(u)">{{ $t('list.delete') }}</button>
          </div>
        </div>
        <div v-if="users.length === 0" class="empty">{{ $t('users.empty') }}</div>
      </div>
    </div>

    <!-- 日志 -->
    <div v-if="tab === 'logs'" class="panel">
      <div class="list">
        <div v-for="l in logs" :key="l.id" class="row">
          <div class="main">
            <div class="title"><span class="tag">{{ l.username || '—' }}</span> {{ l.action }}</div>
            <div class="meta">
              <span>{{ l.detail }}</span>
              <span>{{ l.ip }}</span>
              <span>{{ formatLogTime(l.created_at) }}</span>
            </div>
          </div>
        </div>
        <div v-if="logs.length === 0" class="empty">{{ $t('logs.empty') }}</div>
      </div>
    </div>

    <!-- 系统设置 -->
    <div v-if="tab === 'settings'" class="panel">
      <div class="settings-card">
        <div class="card-header card-header-row">
          <h3>{{ $t('settings.smtp') }}</h3>
          <select v-model="settings.smtp_enabled" class="select-block select-inline">
            <option :value="true">{{ $t('settings.on') }}</option>
            <option :value="false">{{ $t('settings.off') }}</option>
          </select>
        </div>
        <div class="card-body" v-if="settings.smtp_enabled">
          <label class="form-label">{{ $t('settings.vendor') }}</label>
          <select v-model="settings.smtp.vendor" class="select-block" @change="onVendorChange">
            <option v-for="v in smtpVendors" :key="v.value" :value="v.value">{{ v.label }}</option>
          </select>

          <template v-if="settings.smtp.vendor !== 'custom'">
            <label class="form-label">{{ $t('settings.email') }}</label>
            <input v-model="settings.smtp.from" :placeholder="$t('settings.emailPlaceholder')" />
            <label class="form-label">
              {{ $t('settings.authCode') }}
              <a class="link-inline" href="#" @click.prevent="showVendorAuthHelp">{{ $t('settings.howToAuthCode') }}</a>
            </label>
            <input v-model="settings.smtp.password" type="password" :placeholder="$t('settings.authCodePlaceholder')" />
            <div v-if="vendorTip" class="tip">{{ vendorTip }}</div>
          </template>

          <template v-else>
            <label class="form-label">{{ $t('settings.host') }}</label>
            <input v-model="settings.smtp.host" :placeholder="$t('settings.hostPlaceholder')" />

            <div class="form-grid">
              <div class="form-col">
                <label class="form-label">{{ $t('settings.secureMode') }}</label>
                <select v-model="settingsSecureMode" class="select-block" @change="onSecureChange">
                  <option value="ssl">{{ $t('settings.sslSecure') }}</option>
                  <option value="tls">{{ $t('settings.tlsSecure') }}</option>
                  <option value="none">{{ $t('settings.noSecure') }}</option>
                </select>
              </div>
              <div class="form-col">
                <label class="form-label">{{ $t('settings.port') }}</label>
                <input v-model.number="settings.smtp.port" type="number" @input="onPortEdit" />
              </div>
            </div>

            <div class="form-grid">
              <div class="form-col">
                <label class="form-label">{{ $t('settings.username') }}</label>
                <input v-model="settings.smtp.username" :placeholder="$t('settings.usernamePlaceholder')" />
              </div>
              <div class="form-col">
                <label class="form-label">{{ $t('settings.password') }}</label>
                <input v-model="settings.smtp.password" type="password" :placeholder="$t('settings.passwordHint')" />
              </div>
            </div>

            <label class="form-label">{{ $t('settings.from') }}</label>
            <input v-model="settings.smtp.from" :placeholder="$t('settings.fromPlaceholder')" />
          </template>
          <div class="test-email-row">
            <input v-model="testEmail" :placeholder="$t('settings.testEmailPlaceholder')" />
            <button class="btn-ghost" @click="sendTestEmail">{{ $t('settings.sendTest') }}</button>
          </div>
        </div>

        <template v-if="settings.allow_registration">
        <div class="card-divider" />

        <div class="card-header">
          <h3>{{ $t('settings.verifyMode') }}</h3>
        </div>
        <div class="card-body">
          <select v-model="settings.email_verify_mode" class="select-block">
            <option value="code">{{ $t('settings.modeCode') }}</option>
            <option value="none">{{ $t('settings.modeNone') }}</option>
          </select>
        </div>
        </template>

        <template v-if="settings.smtp_enabled">
        <div class="card-divider" />

        <div class="card-header">
          <h3>{{ $t('settings.registerTitle') }}</h3>
        </div>
        <div class="card-body">
          <div class="form-grid">
            <div class="form-col">
              <label class="form-label">{{ $t('settings.allowRegistration') }}</label>
              <select v-model="settings.allow_registration" class="select-block">
                <option :value="false">{{ $t('settings.off') }}</option>
                <option :value="true">{{ $t('settings.on') }}</option>
              </select>
            </div>
            <div class="form-col">
              <label class="form-label">{{ $t('settings.passwordMinLength') }}</label>
              <input v-model.number="settings.password_min_length" type="number" min="4" max="64" />
            </div>
          </div>
          <div class="form-grid">
            <div class="form-col">
              <label class="form-label">{{ $t('settings.requireComplex') }}</label>
              <select v-model="settings.password_require_complex" class="select-block">
                <option :value="false">{{ $t('settings.off') }}</option>
                <option :value="true">{{ $t('settings.on') }}</option>
              </select>
            </div>
          </div>
        </div>
        </template>

        <div class="card-divider" />

        <div class="card-header">
          <h3>{{ $t('settings.recycleTitle') }}</h3>
        </div>
        <div class="card-body">
          <div class="form-grid">
            <div class="form-col">
              <label class="form-label">{{ $t('settings.recycle') }}</label>
              <select v-model="settings.recycle" class="select-block">
                <option :value="true">{{ $t('settings.on') }}</option>
                <option :value="false">{{ $t('settings.off') }}</option>
              </select>
            </div>
            <div class="form-col">
              <label class="form-label">{{ $t('settings.recycleDays') }}</label>
              <input v-model.number="settings.recycle_days" type="number" min="1" max="3650" />
            </div>
          </div>
        </div>

        <div class="card-footer">
          <button class="btn-ghost" @click="exportSettings">{{ $t('settings.exportConfig') }}</button>
          <button class="btn-ghost" @click="$refs.configInput.click()">{{ $t('settings.importConfig') }}</button>
          <input ref="configInput" type="file" accept=".json,application/json" style="display:none" @change="importSettingsFile" />
          <button class="btn-primary" @click="saveSettings">{{ $t('modal.save') }}</button>
        </div>
      </div>
    </div>

    <!-- 关于 -->
    <div v-if="tab === 'about'" class="panel">
      <div class="about-card">
        <div class="about-head">
          <img :src="logoUrl" class="about-logo" alt="CryPtBox" />
          <div class="about-info">
            <p class="about-title">CryPtBox 密匣 - 飞牛OS第三方密码管理器</p>
            <p class="about-line">作者：CryPtBox</p>
            <p class="about-line">发布者：青芷</p>
            <p class="about-line">当前版本：v{{ serverVersion || 'dev' }}</p>
            <p class="about-line">官网链接：<a class="about-link" href="https://cryptbox.fnosp.com" target="_blank" rel="noopener">cryptbox.fnosp.com</a></p>
            <p class="about-line">{{ $t('about.github') }}：<a class="about-link" href="https://github.com/qingzhi-awa/cryptbox-fn" target="_blank" rel="noopener">github.com/qingzhi-awa/cryptbox-fn</a></p>
          </div>
        </div>
        <div class="about-divider" />
        <p class="about-subtitle">{{ $t('about.changelog') }}</p>
        <div class="about-changelog">
          <div class="cl-item current">
            <div class="cl-ver">v{{ changelog[0].v }}<span class="cl-tag">{{ $t('about.current') }}</span></div>
            <ul class="cl-items">
              <li v-for="(it, i) in changelog[0].items" :key="i">{{ it }}</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
      </div>
    </div>

    <!-- 站点页脚 -->
    <footer class="site-footer">
      <p v-if="site.footer_text" class="footer-line">{{ site.footer_text }}</p>
      <p v-if="serverVersion" class="footer-line footer-version">CryPtBox v{{ serverVersion }}</p>
    </footer>

    <!-- 全局提示 toast -->
    <div v-if="error || msg" class="toast" :class="error ? 'toast-error' : 'toast-msg'">
      {{ error || msg }}
    </div>

    <!-- 新增/编辑密码弹窗 -->
    <div v-if="editing !== null" class="mask" @click.self="editing = null">
      <div class="modal">
        <h2>{{ form.id ? $t('modal.editTitle') : $t('modal.addTitle') }}</h2>
        <label>{{ $t('modal.title') }}</label>
        <input v-model="form.title" />
        <label>{{ $t('modal.username') }} *</label>
        <input v-model="form.username" />
        <label>{{ $t('modal.password') }} *</label>
        <div class="pw-row">
          <input v-model="form.password" :type="formShow ? 'text' : 'password'" />
          <button class="mini" @click="formShow = !formShow">{{ formShow ? $t('list.hide') : $t('list.show') }}</button>
        </div>
        <label>{{ $t('modal.url') }} *</label>
        <input v-model="form.url" />
        <label>{{ $t('modal.category') }}</label>
        <input v-model="form.category" />
        <label>{{ $t('modal.notes') }}</label>
        <textarea v-model="form.notes" rows="3"></textarea>
        <div class="modal-actions">
          <button class="btn-ghost" @click="editing = null">{{ $t('modal.cancel') }}</button>
          <button class="btn-primary" @click="save">{{ $t('modal.save') }}</button>
        </div>
      </div>
    </div>

    <!-- 编辑用户弹窗 -->
    <div v-if="editingUser !== null" class="mask" @click.self="editingUser = null">
      <div class="modal">
        <h2>{{ $t('users.editTitle') }} #{{ editingUser.id }}</h2>
        <label>{{ $t('users.username') }}</label>
        <input v-model="userForm.username" />
        <label>{{ $t('users.email') }}</label>
        <input v-model="userForm.email" />
        <label>{{ $t('users.password') }}</label>
        <input v-model="userForm.password" type="password" :placeholder="$t('users.passwordHint')" />
        <label>{{ $t('users.role') }}</label>
        <select v-model="userForm.role">
          <option value="user">{{ $t('users.roleUser') }}</option>
          <option v-if="role === 'superadmin'" value="admin">{{ $t('users.roleAdmin') }}</option>
        </select>
        <label>{{ $t('users.active') }}</label>
        <select v-model="userForm.status">
          <option value="active">{{ $t('users.active') }}</option>
          <option value="disabled">{{ $t('users.disabled') }}</option>
        </select>
        <div class="modal-actions">
          <button class="btn-ghost" @click="editingUser = null">{{ $t('modal.cancel') }}</button>
          <button class="btn-primary" @click="saveUser">{{ $t('modal.save') }}</button>
        </div>
      </div>
    </div>

    <!-- 新增用户弹窗 -->
    <div v-if="showAddUser" class="mask" @click.self="showAddUser = false">
      <div class="modal">
        <h2>{{ $t('users.add') }}</h2>
        <label>{{ $t('users.username') }} *</label>
        <input v-model="newUser.username" />
        <label>{{ $t('users.email') }} *</label>
        <input v-model="newUser.email" />
        <label>{{ $t('users.password') }} *</label>
        <input v-model="newUser.password" type="password" />
        <label>{{ $t('users.role') }}</label>
        <select v-model="newUser.role">
          <option value="user">{{ $t('users.roleUser') }}</option>
          <option v-if="role === 'superadmin'" value="admin">{{ $t('users.roleAdmin') }}</option>
        </select>
        <p v-if="userError" class="error">{{ userError }}</p>
        <div class="modal-actions">
          <button class="btn-ghost" @click="showAddUser = false">{{ $t('modal.cancel') }}</button>
          <button class="btn-primary" @click="createUser">{{ $t('modal.save') }}</button>
        </div>
      </div>
    </div>

    <!-- 我的账号弹窗 -->
    <div v-if="showMe" class="mask" @click.self="showMe = false">
      <div class="modal">
        <h2>{{ $t('me.title') }}</h2>
        <div class="avatar-row">
          <img v-if="myAvatar" :src="avatarUrl(myId)" class="avatar avatar-lg" alt="" />
          <span v-else class="avatar avatar-lg avatar-fallback">{{ (username || '?').charAt(0).toUpperCase() }}</span>
          <button class="btn-ghost" @click="triggerAvatar">{{ $t('me.changeAvatar') }}</button>
          <input ref="avatarInput" type="file" accept="image/*" style="display:none" @change="uploadAvatar" />
        </div>
        <label>{{ $t('me.username') }}</label>
        <input v-model="meForm.username" />
        <label>{{ $t('me.email') }}</label>
        <input v-model="meForm.email" />
        <!-- 改邮箱需邮箱所有权验证码：仅在邮箱实际变更时出现（R7-01） -->
        <template v-if="meEmailChanged">
          <label>{{ $t('me.emailCode') }}</label>
          <div class="code-row">
            <input v-model="meForm.email_code" :placeholder="$t('me.emailCode')" />
            <button class="btn-ghost" :disabled="emailCodeSending" @click="sendMyEmailCode">
              {{ emailCodeSending ? $t('me.sending') : $t('me.sendCode') }}
            </button>
          </div>
        </template>
        <label>{{ $t('me.currentPassword') }}</label>
        <input v-model="meForm.current_password" type="password" />
        <label>{{ $t('me.newPassword') }}</label>
        <input v-model="meForm.new_password" type="password" :placeholder="$t('users.passwordHint')" />
        <div class="modal-actions">
          <button class="btn-ghost" @click="showMe = false">{{ $t('modal.cancel') }}</button>
          <button class="btn-primary" @click="saveMe">{{ $t('modal.save') }}</button>
        </div>
      </div>
    </div>

    <!-- 删除确认弹窗 -->
    <div v-if="confirmBox" class="mask" @click.self="confirmBox = null">
      <div class="modal modal-confirm">
        <h2>{{ $t('modal.confirmTitle') }}</h2>
        <p class="confirm-text">{{ confirmBox.text }}</p>
        <div class="modal-actions">
          <button class="btn-ghost" @click="confirmBox = null">{{ $t('modal.cancel') }}</button>
          <button class="btn-danger" @click="confirmBox.onOk(); confirmBox = null">{{ $t('modal.ok') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import api from './api'
import * as vault from './vault'
import { parseCsvEntries, parseTxtEntries, normalizeEntry } from './importer'
import logoUrl from './assets/logo.png'

// 生成与 Go 端 time.RFC3339 一致的时间戳（秒级、UTC，无毫秒）。
function nowRfc3339() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
}

function csvEscape(v) {
  v = String(v == null ? '' : v)
  // 公式注入防护：以 = + - @ 开头的字段会被 Excel/WPS 当作公式执行，前置单引号强制按文本处理。
  // R11-10：Excel/WPS 会忽略单元格里的**前导空白**，因此 " =1+1" 这类同样危险，
  // 判定必须纵向拉开到第一个非空白字符（原正则只检查首字符，可被前导空格绕过）。
  if (/^[\s]*[=+\-@\t\r]/.test(v)) v = "'" + v
  if (/[",\n\r]/.test(v)) v = '"' + v.replace(/"/g, '""') + '"'
  return v
}

export default {
  data() {
    return {
      logoUrl,
      // R8-07：JWT 仅存内存，不落 sessionStorage（否则削弱服务端 HttpOnly Cookie 的
      // XSS 缓解）。刷新后由服务端下发的 HttpOnly 会话 Cookie 续期（见 trySession）。
      token: '',
      sessionAuth: false,
      username: sessionStorage.getItem('username') || '',
      role: sessionStorage.getItem('role') || '',
      // 端到端加密：vault key 仅存内存，刷新后需重新输入密码解锁。
      vaultUnlocked: false,
      // 主密钥派生盐：优先使用服务端下发的随机盐 kdf_salt；
      // 历史账号该值为空，此时回退用用户名作盐（兼容既有数据）。
      kdfSalt: '',
      // 密码重置后的恢复模式：用旧密码恢复原密码库，或清空后重新开始。
      vaultRecovery: false,
      recoverForm: { oldPassword: '' },
      // 更新日志（关于页展示；与当前版本相同的条目会高亮）。
      changelog: [
        { v: '0.2.3', items: ['优化登录体验；修复密码错误提示异常，使提示更精准', '修复登录后用户信息加载失败', '修复部分情况下同步按钮失效问题，优化同步逻辑', '新增多重安全机制，收紧文件权限，加强敏感字段脱敏', '内嵌入口接入统一网关，提升访问稳定性', '新增 API 访问日志，便于排查', '修复部分场景下的页面异常', '优化模板内容与名称的显示', '修复部分情况下的语言显示问题', '优化删除逻辑，新增软删除，支持误删恢复', '优化用户偏好设置'] },
        { v: '0.2.36', items: ['收紧管理员权限：仅超级管理员可创建管理员或授予管理员角色，封堵「造号提权」旁路', '会话 Cookie 的 Secure 按反代/网关后的真实协议判定，直连 TLS 与受信代理均正确', '新增管理接口列出仍存在服务端可解密历史条目的账号，明文迁移接口计划 0.3.0 移除', '网页后台内容安全策略移除 unsafe-eval，消除脚本注入时的代码执行面', '修复初始化接口限流计数器未纳入定期清理导致的键表增长'] },
        { v: '0.2.35', items: ['修复验证码与重置邮件发送失败（主题编码/补齐邮件头/正文编码/连接超时）', '邮箱唯一化：注册、建号、导入与改绑均校验占用，登录与重置不再受同邮箱多账号干扰', '用户自助改绑邮箱需通过新邮箱验证码，管理员后台调整无需验证码', '收紧管理员权限：仅能管理普通用户，不能再操作同级管理员', '登录失败锁定加入来源维度，避免被恶意锁定他人账号', '网页端登录令牌仅存内存，刷新免登录依赖服务端安全 Cookie'] },
        { v: '0.2.34', items: ['新增账号级「置顶参与同步」开关，桌面端与网页端均可修改', '开启后置顶状态随密码库同步到所有设备；关闭时各端独立保存'] },
        { v: '0.2.33', items: ['网页端条目支持置顶与拖拽排序', '置顶偏好按账号保存在服务端，与桌面端按设备置顶互不影响', '排序调整会随同步传播到桌面端'] },
        { v: '0.2.32', items: ['桌面端条目支持置顶与拖拽排序', '网址与用户名栏改为掩码显示，与密码一致', '移除桌面端渲染层多余的对话框权限'] },
        { v: '0.2.31', items: ['条目改用全局唯一标识归并，多设备同步不再互相覆盖丢数据', '改密码后此前签发的登录令牌立即失效', '加密密钥与 JWT 密钥移出数据库，改为数据目录下 0600 独立文件', 'SMTP 口令加密存储，配置导出对敏感字段掩码', '数据库文件权限自动收紧为 0600'] },
        { v: '0.2.30', items: ['客户端同步默认改用 HTTPS，并新增服务器证书指纹校验（防中间人）', '同步密钥改由系统凭据库保管，不再明文落库', '新增 GET /api/fingerprint 证书指纹接口'] },
        { v: '0.2.29', items: ['修复多账号同步相互冲突的问题', '升级前自动备份数据库', '超级管理员口令要求更严（≥10 位且含字母数字）', '未登录请求不再返回精确版本号'] },
        { v: '0.2.28', items: ['修复主题按钮宽度被侧栏样式覆盖的问题'] },
        { v: '0.2.27', items: ['侧栏底部按钮收紧至图标宽度'] },
        { v: '0.2.26', items: ['侧栏底部按钮布局微调'] },
        { v: '0.2.25', items: ['主题切换按钮精简为图标，新增 GitHub 入口', '关于页新增官网与开源地址链接'] },
        { v: '0.2.24', items: ['新增颜色模式切换（自动 / 浅色 / 深色）', '回收站条目显示网址', '导入模板示例内容跟随语言', '关于页布局优化，更新日志仅显示最新版本'] },
        { v: '0.2.23', items: ['导入模板区分密码/用户并附带示例内容'] },
        { v: '0.2.22', items: ['新增「导出用户」（CSV，不含密码）', '新增「关于」页'] },
        { v: '0.2.21', items: ['回收站为空时「清空回收站」置灰', '操作日志时间显示为本地时区'] },
        { v: '0.2.20', items: ['HTTP 访问直接可用（移除加密引导页）'] },
        { v: '0.2.19', items: ['移除降级模式常驻提示条'] },
        { v: '0.2.18', items: ['修复非加密模式下的页面异常'] },
        { v: '0.2.17', items: ['内嵌入口优化'] },
        { v: '0.2.16', items: ['支持证书下载导入'] },
        { v: '0.2.15', items: ['内嵌入口改为直连访问'] },
        { v: '0.2.14', items: ['入口带版本参数防缓存', '新增 API 访问日志（info.log）'] },
        { v: '0.2.13', items: ['页面禁缓存策略', '界面底部显示版本号'] },
        { v: '0.2.12', items: ['写操作兼容飞牛网关（POST 入口）'] },
        { v: '0.2.11', items: ['修复修改密码后密码库无法解锁', '增强旧密码恢复'] },
        { v: '0.2.10', items: ['兼容飞牛统一网关登录（双通道鉴权）'] },
        { v: '0.2.9', items: ['内嵌入口接入统一网关'] },
        { v: '0.2.7', items: ['内嵌入口支持 HTTPS'] },
        { v: '0.2.6', items: ['同一端口同时兼容 HTTP 与 HTTPS'] },
        { v: '0.2.5', items: ['默认启用 HTTPS（首次启动自动生成证书）'] },
        { v: '0.2.4', items: ['安全加固：验证码防穷举、登录锁定、全局限流', '令牌有效期收敛至 24 小时', '新增密码库恢复（旧密码恢复 / 清空重建）'] }
      ],
      unlockForm: { password: '' },
      unlockError: '',
      allEntries: [],
      myId: 0,
      meEmail: '',
      myAvatar: '',
      avatarVersion: 0,
      userError: '',
      loginForm: { username: '', password: '' },
      setupForm: { username: '', password: '' },
      isAdminLogin: location.pathname.startsWith('/admin-login'),
      gateMode: 'login',
      initialized: true,
      // 服务端版本号（/api/status 下发），显示在页脚用于确认版本与前端刷新状态。
      serverVersion: '',
      verifyMode: 'none',
      regForm: { username: '', email: '', password: '', code: '' },
      resetForm: { email: '', code: '', password: '' },
      error: '',
      msg: '',
      tab: 'passwords',
      logs: [],
      settings: { smtp: { host: '', port: 465, username: '', password: '', from: '', ssl: false, vendor: 'qq' }, smtp_enabled: false, email_verify_mode: 'none', allow_registration: false, password_min_length: 6, password_require_complex: false, recycle: true, recycle_days: 30 },
      testEmail: '',
      site: { footer_text: '' },
      allowReg: false,
      recycleEnabled: true,
      portAuto: true,
      settingsSecureMode: 'ssl',
      // 自助改绑邮箱：验证码发送中状态（按钮防重复点击）。
      emailCodeSending: false,
      entries: [],
      trash: [],
      search: '',
      revealed: new Set(),
      // 拖拽排序状态：dragId 为被拖动条目，dragOverId 为当前悬停目标。
      dragId: null,
      dragOverId: null,
      editing: null,
      form: this.emptyForm(),
      formShow: false,
      users: [],
      // 仍存在服务端可解密旧数据（未迁移）的账号清单，及其计划移除版本。
      legacyPending: [],
      legacyRemoveVersion: '',
      newUser: { username: '', email: '', password: '', role: 'user' },
      showAddUser: false,
      editingUser: null,
      userForm: { username: '', email: '', password: '', role: 'user', status: 'active' },
      showMe: false,
      confirmBox: null,
      menuOpen: false,
      meForm: { username: '', email: '', email_code: '', current_password: '', new_password: '' },
      importFormat: '',
      ioFormat: '',
      lang: localStorage.getItem('locale') || 'zh-CN',
      // 颜色模式：auto（跟随系统）/ light / dark，循环切换。
      themeMode: localStorage.getItem('theme') || 'auto'
    }
  },
  computed: {
    themeIcon() {
      return this.themeMode === 'light' ? '☀️' : this.themeMode === 'dark' ? '🌙' : '🌗'
    },
    themeLabel() {
      const key = this.themeMode === 'light' ? 'theme.light' : this.themeMode === 'dark' ? 'theme.dark' : 'theme.auto'
      return this.$t(key)
    },
    filtered() {
      const q = this.search.trim().toLowerCase()
      if (!q) return this.entries
      return this.entries.filter((e) =>
        [e.title, e.username, e.url, e.category].some((s) => (s || '').toLowerCase().includes(q))
      )
    },
    // 拖拽排序：仅在未搜索（列表即完整顺序）且条目多于一条时启用，
    // 否则拖动的只是筛选结果，落库顺序会与所见不符。
    canDrag() {
      return !this.search.trim() && this.entries.length > 1
    },
    isAdmin() {
      return this.role === 'admin' || this.role === 'superadmin'
    },
    // 「我的账号」中邮箱是否被改动：决定是否展示验证码输入与发送按钮。
    meEmailChanged() {
      return (this.meForm.email || '').trim() !== (this.meEmail || '').trim()
    },
    gateTitle() {
      if (this.gateMode === 'setup') return this.$t('login.setupTitle')
      if (this.gateMode === 'register') return this.$t('login.register')
      if (this.gateMode === 'forgot') return this.$t('login.forgot')
      return this.isAdminLogin ? this.$t('login.adminTitle') : this.$t('app.title')
    },
    smtpVendors() {
      const t = this.$t
      return [
        { value: 'qq', label: 'QQ邮箱' },
        { value: '126', label: '126邮箱' },
        { value: '163', label: '163邮箱' },
        { value: 'gmail', label: 'Gmail' },
        { value: 'outlook', label: 'Outlook' },
        { value: 'custom', label: t('settings.vendorCustom') }
      ]
    },
    vendorTip() {
      const map = {
        qq: this.$t('settings.qqTip'),
        '126': this.$t('settings.126Tip'),
        '163': this.$t('settings.163Tip'),
        gmail: this.$t('settings.gmailTip'),
        outlook: this.$t('settings.outlookTip')
      }
      return map[this.settings.smtp.vendor] || ''
    }
  },
  watch: {
    msg(val) {
      if (val) this._flash('msg')
    },
    error(val) {
      if (val) this._flash('error')
    }
  },
  async mounted() {
    // R8-07：清理历史版本可能残留在 sessionStorage 的令牌副本。
    try {
      sessionStorage.removeItem('token')
    } catch (e) {
      /* ignore */
    }
    this.loadPublicSettings()
    try {
      const st = await api.status()
      this.initialized = st.initialized
      // 版本号在认证后由 /api/me 下发并显示在页脚（此处仅取初始化状态：
      // 未认证请求不暴露精确版本号，只返回用于前端自检的 build 摘要）。
      if (!st.initialized) this.gateMode = 'setup'
    } catch (e) {
      /* ignore */
    }
    // 优先尝试已有会话（HttpOnly Cookie，登录后由服务端下发；直接端口访问则靠本地 token）
    await this.trySession()
    if (this.sessionAuth) return
    if (this.token) await this.init()
  },
  methods: {
    _flash(key) {
      clearTimeout(this._flashTimer)
      this._flashTimer = setTimeout(() => {
        this[key] = ''
      }, 3000)
    },
    emptyForm() {
      return { id: 0, title: '', username: '', password: '', url: '', category: '', notes: '' }
    },
    changeLang() {
      this.$i18n.locale = this.lang
      localStorage.setItem('locale', this.lang)
    },
    // 颜色模式循环切换：自动（跟随系统）→ 浅色 → 深色 → 自动。
    cycleTheme() {
      const order = ['auto', 'light', 'dark']
      const next = order[(order.indexOf(this.themeMode) + 1) % order.length]
      this.themeMode = next
      try {
        localStorage.setItem('theme', next)
      } catch (e) {
        /* ignore */
      }
      this.applyTheme()
    },
    applyTheme() {
      let resolved = this.themeMode
      if (resolved === 'auto') {
        try {
          resolved = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
        } catch (e) {
          resolved = 'light'
        }
      }
      document.documentElement.setAttribute('data-theme', resolved)
    },
    fieldName(key) {
      return this.$t(key).replace(' *', '')
    },
    // 日志时间显示：服务端（SQLite CURRENT_TIMESTAMP）存的是 UTC，
    // 这里补上 Z 标记交给 Date 转换为浏览器所在时区的本地时间显示。
    formatLogTime(s) {
      if (!s) return ''
      const d = new Date(String(s).replace(' ', 'T') + (/[Zz]|[+-]\d{2}:?\d{2}$/.test(String(s)) ? '' : 'Z'))
      if (isNaN(d.getTime())) return String(s)
      const p = (n) => String(n).padStart(2, '0')
      return (
        d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
        ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds())
      )
    },
    async init() {
      // 优先用本地 token；经飞牛统一网关内嵌打开时 Authorization 头会被网关剥离，
      // 因此失败或返回异常时回退到同源会话 Cookie（登录时由服务端下发，HttpOnly）。
      let me = null
      let lastErr = null
      const candidates = this.token ? [this.token, ''] : ['']
      for (const tok of candidates) {
        try {
          const r = await api.me(tok)
          if (r && r.username) {
            me = r
            break
          }
          lastErr = new Error(this.$t('msg.sessionInvalid'))
        } catch (e) {
          lastErr = e
        }
      }
      if (!me) {
        this.clearAuth()
        // 401 表示会话已失效（含飞牛账号切换导致旧会话被拒），静默回到登录页；
        // 其余异常（网络/服务端错误）才提示，避免误报。
        if (!(lastErr && lastErr.status === 401)) {
          this.error = lastErr ? String(lastErr.message || lastErr) : ''
        }
        return
      }
      // 无本地 token 而能取到用户信息，说明身份来自会话 Cookie（网关直通场景）。
      this.sessionAuth = !this.token
      this.username = me.username
      this.role = me.role
      this.myId = me.id
      this.meEmail = me.email || ''
      this.myAvatar = me.avatar || ''
      this.vaultKeyEnc = me.vault_key_enc || ''
      this.kdfSalt = me.kdf_salt || ''
      // 版本号由已认证接口下发（未认证的 /api/status 只给 build 摘要）。
      this.serverVersion = me.version || this.serverVersion
      // vault key 仅存内存：刷新后 token 仍在，但需重新输入密码解锁后才能读取密码条目。
      if (this.vaultUnlocked) await this.loadVault()
      if (this.isAdmin) await this.loadUsers()
    },
    async trySession() {
      // 无本地 token 时，尝试免 token 拉取 /api/me；此时浏览器会自动带上登录时下发的 HttpOnly Cookie，
      // 服务端据此识别已登录用户（网关会剥离 Authorization 头，Cookie 不受影响）。
      try {
        const me = await api.me('')
        if (!me || !me.username) return
        this.sessionAuth = true
        this.username = me.username
        this.role = me.role
        this.myId = me.id
        this.meEmail = me.email || ''
        this.myAvatar = me.avatar || ''
        this.vaultKeyEnc = me.vault_key_enc || ''
        this.kdfSalt = me.kdf_salt || ''
        // 版本号由已认证接口下发（未认证的 /api/status 只给 build 摘要）。
        this.serverVersion = me.version || this.serverVersion
        if (this.vaultUnlocked) await this.loadVault()
        if (this.isAdmin) await this.loadUsers()
      } catch (e) {
        // 未登录/会话失效：保持登录页。401 时顺带清掉本地残留凭据
        // （飞牛账号切换后旧令牌被服务端拒绝，避免界面沿用上一个账号的状态）。
        if (e && e.status === 401) this.clearAuth()
      }
    },
    async loadPublicSettings() {
      try {
        const r = await api.publicSettings()
        this.verifyMode = r.email_verify_mode || 'none'
        this.allowReg = !!r.allow_registration
        this.recycleEnabled = r.recycle !== false
        // 服务端默认语言：仅当用户尚未手动选择过语言时采用（安装向导选择的默认语言）
        if (!localStorage.getItem('locale') && r.default_language) {
          this.lang = r.default_language
          this.$i18n.locale = r.default_language
        }
        if (r.site) this.site = this.normalizeSite(r.site)
      } catch (e) {
        /* ignore */
      }
    },
    normalizeSite(s) {
      return { footer_text: s.footer_text || '' }
    },
    switchGate(m) {
      this.gateMode = m
      this.error = ''
      this.msg = ''
    },
    async doSetup() {
      this.error = ''
      try {
        // 初始化时即生成 vault key，用 master key 加密后随注册请求一并写入，避免二次交互。
        const { vaultKey, vaultKeyEnc, kdfSalt } = await this.buildNewVault(this.setupForm.password)
        const r = await api.setup(this.setupForm.username, this.setupForm.password, vaultKeyEnc, kdfSalt)
        this.applyAuth(r)
        vault.setVaultKey(vaultKey)
        this.vaultUnlocked = true
        this.vaultKeyEnc = vaultKeyEnc
        await this.init()
      } catch (e) {
        this.error = String(e.message || e)
      }
    },
    // 生成新的派生盐与 vault key，并返回用 master key 加密后的 vault key 密文。
    async buildNewVault(password) {
      if (!vault.hasCrypto()) throw new Error(this.$t('msg.cryptoUnavailable'))
      // 随机派生盐，随账号一并上传，避免「以用户名作盐」在改名后导致数据无法解密。
      const kdfSalt = vault.newSalt()
      const masterKey = await vault.deriveMasterKey(password, kdfSalt)
      const vaultKey = vault.randomBytes(32)
      const vaultKeyEnc = await vault.encryptVaultKey(masterKey, vaultKey)
      return { vaultKey, vaultKeyEnc, kdfSalt }
    },
    async sendRegCode() {
      this.error = ''
      try {
        await api.sendRegisterCode(this.regForm.email)
        this.msg = this.$t('msg.codeSent')
      } catch (e) {
        this.error = String(e.message || e)
      }
    },
    async sendResetCode() {
      this.error = ''
      try {
        await api.sendResetCode(this.resetForm.email)
        this.msg = this.$t('msg.codeSent')
      } catch (e) {
        this.error = String(e.message || e)
      }
    },
    async register() {
      this.error = ''
      try {
        const { vaultKey, vaultKeyEnc, kdfSalt } = await this.buildNewVault(this.regForm.password)
        const r = await api.register({ ...this.regForm, vault_key_enc: vaultKeyEnc, kdf_salt: kdfSalt })
        this.applyAuth(r)
        vault.setVaultKey(vaultKey)
        this.vaultUnlocked = true
        this.vaultKeyEnc = vaultKeyEnc
        await this.init()
      } catch (e) {
        this.error = String(e.message || e)
      }
    },
    async resetPassword() {
      this.error = ''
      try {
        await api.resetPassword(this.resetForm)
        this.msg = this.$t('msg.resetDone')
        this.resetForm = { email: '', code: '', password: '' }
        this.gateMode = 'login'
      } catch (e) {
        this.error = String(e.message || e)
      }
    },
    applyAuth(r) {
      this.token = r.token
      this.username = r.username
      this.role = r.role
      this.vaultKeyEnc = r.vault_key_enc || ''
      this.kdfSalt = r.kdf_salt || ''
      // R8-07：令牌仅存内存；username/role 为非凭据字段，可持久化以优化首屏。
      sessionStorage.setItem('username', r.username)
      sessionStorage.setItem('role', r.role)
    },
    async login() {
      this.error = ''
      try {
        const r = await api.login(this.loginForm.username, this.loginForm.password)
        if (this.isAdminLogin && r.role === 'user') {
          this.error = this.$t('login.adminOnly')
          return
        }
        this.applyAuth(r)
        // 登录时已持有账号密码，直接派生 master key 解锁密码库。
        await this.unlockWithPassword(this.loginForm.password, r.kdf_salt || r.username, r.vault_key_enc)
        // 历史账号首次启用端到端加密时，先把服务端静态密钥加密的旧数据迁移过来。
        await this.migrateLegacy()
        await this.init()
      } catch (e) {
        this.error = String(e.message || e)
      }
    },
    // 用账号密码派生 master key，解密（或首次创建）vault key。
    // salt 由调用方传入：优先 kdf_salt，历史账号回退用户名。
    async unlockWithPassword(password, salt, vaultKeyEnc) {
      if (!vault.hasCrypto()) throw new Error(this.$t('msg.cryptoUnavailable'))
      const masterKey = await vault.deriveMasterKey(password, salt)
      let vk
      if (!vaultKeyEnc) {
        // 首次启用端到端加密（含历史账号）：生成 vault key 并上传。
        vk = vault.randomBytes(32)
        const enc = await vault.encryptVaultKey(masterKey, vk)
        await api.putVaultKey(enc, this.token, password)
        this.vaultKeyEnc = enc
      } else {
        vk = await vault.decryptVaultKey(masterKey, vaultKeyEnc)
        this.vaultKeyEnc = vaultKeyEnc
      }
      vault.setVaultKey(vk)
      this.vaultUnlocked = true
    },
    // 解锁门（页面刷新后 token 仍在但内存中的 vault key 已丢失）。
    async unlockVault() {
      this.unlockError = ''
      try {
        await this.unlockWithPassword(this.unlockForm.password, this.kdfSalt || this.username, this.vaultKeyEnc)
        this.unlockForm.password = ''
        this.vaultRecovery = false
        await this.migrateLegacy()
        await this.loadVault()
        if (this.isAdmin) await this.loadUsers()
      } catch (e) {
        this.unlockError = this.$t('login.unlockFailed')
      }
    },
    // 密码被重置后的恢复路径：用旧密码解开旧 vault key，再用当前（新）密码重新包裹上传。
    // 全程在本地完成密钥运算，服务端只存新的 vault_key_enc，原密码库数据无损。
    async recoverVault() {
      this.unlockError = ''
      try {
        if (!vault.hasCrypto()) throw new Error(this.$t('msg.cryptoUnavailable'))
        if (!this.vaultKeyEnc) throw new Error('no vault key to recover')
        if (!this.unlockForm.password || !this.recoverForm.oldPassword) {
          this.unlockError = this.$t('login.recoverNeedBoth')
          return
        }
        // 依次尝试候选派生盐：当前随机盐 → 用户名（历史账号或以用户名作盐时的包裹方式）。
        // 这样即使派生盐曾被改动，只要旧密码 + 旧盐仍能解开 vault key，数据就能救回。
        const candidates = []
        for (const s of [this.kdfSalt, this.username]) {
          const v = (s || '').trim()
          if (v && !candidates.includes(v)) candidates.push(v)
        }
        let vk = null
        let usedSalt = ''
        for (const s of candidates) {
          try {
            const oldMaster = await vault.deriveMasterKey(this.recoverForm.oldPassword, s)
            vk = await vault.decryptVaultKey(oldMaster, this.vaultKeyEnc)
            usedSalt = s
            break
          } catch (e) {
            /* 换下一个候选盐重试 */
          }
        }
        if (!vk) {
          this.unlockError = this.$t('login.recoverFailed')
          return
        }
        // 重新包裹：使用服务端当前记录的派生盐，避免盐与密文再次不一致。
        const salt = this.kdfSalt || usedSalt
        const newMaster = await vault.deriveMasterKey(this.unlockForm.password, salt)
        const enc = await vault.encryptVaultKey(newMaster, vk)
        // 账号已有 vault_key_enc，改写解锁材料须带当前口令（R13-02）。
        await api.putVaultKey(enc, this.token, this.unlockForm.password)
        this.vaultKeyEnc = enc
        vault.setVaultKey(vk)
        this.vaultRecovery = false
        this.recoverForm.oldPassword = ''
        this.unlockForm.password = ''
        this.unlockError = ''
        this.vaultUnlocked = true
        await this.migrateLegacy()
        await this.loadVault()
        if (this.isAdmin) await this.loadUsers()
      } catch (e) {
        // 旧密码错误（解密失败）或网络异常
        this.unlockError = this.$t('login.recoverFailed')
      }
    },
    // 放弃旧密码库：清空服务端条目密文并重置 vault key，之后用新密码重新开始。
    // 旧密文删除后不可恢复，需用户确认。
    async resetVaultData() {
      if (!window.confirm(this.$t('login.resetVaultConfirm'))) return
      this.unlockError = ''
      try {
        await api.deleteVault(this.token)
        this.vaultKeyEnc = ''
        this.vaultRecovery = false
        this.recoverForm.oldPassword = ''
        // vault_key_enc 已置空：unlockWithPassword 会生成新 vault key 并上传。
        await this.unlockWithPassword(this.unlockForm.password, this.kdfSalt || this.username, '')
        this.unlockForm.password = ''
        this.unlockError = ''
        this.vaultUnlocked = true
        await this.loadVault()
        if (this.isAdmin) await this.loadUsers()
      } catch (e) {
        this.unlockError = String(e.message || e)
      }
    },
    lock() {
      // 仅锁定密码库：保留登录会话，清空内存中的 vault key，需重新输入账号密码解锁。
      this.menuOpen = false
      this.vaultUnlocked = false
      vault.clearVaultKey()
      this.entries = []
      this.trash = []
      this.allEntries = []
      this.users = []
      this.unlockError = ''
      this.unlockForm.password = ''
    },
    async logout() {
      // 会话 Cookie 是 HttpOnly 的，只能由服务端清除（失败也不影响本地登出）。
      try {
        await api.logout(this.token)
      } catch (e) {
        /* ignore */
      }
      this.clearAuth()
      this.entries = []
      this.trash = []
      this.allEntries = []
      this.users = []
    },
    clearAuth() {
      this.token = ''
      this.sessionAuth = false
      this.username = ''
      this.role = ''
      this.vaultUnlocked = false
      this.vaultKeyEnc = ''
      this.kdfSalt = ''
      vault.clearVaultKey()
      sessionStorage.removeItem('token')
      sessionStorage.removeItem('username')
      sessionStorage.removeItem('role')
    },
    switchTab(t) {
      this.tab = t
      this.error = ''
      this.msg = ''
      if (t === 'logs') this.loadLogs()
      if (t === 'settings') this.loadSettings()
      if (t === 'users' && this.isAdmin) this.loadUsers()
    },
    // 拉取整库并本地解密：password / notes 为密文，其余字段为明文元数据。
    // 同时取回网页端置顶偏好（失败不阻塞使用，仅退化为不置顶）。
    async loadVault() {
      const r = await api.getVault(this.token)
      const list = await vault.decryptEntries(r.entries || [])
      this.allEntries = list
      this.applyEntryView()
      if (list.some((e) => e.decryptFailed)) {
        this.error = this.$t('msg.decryptFailed')
      }
    },
    applyEntryView() {
      // 置顶条目固定在最前，其后按同步的 sort_order 排列。
      const pinRank = (e) => (e.pinned ? 0 : 1)
      this.entries = this.allEntries
        .filter((e) => !e.deleted)
        .sort(
          (a, b) => pinRank(a) - pinRank(b) || a.sort_order - b.sort_order || a.id - b.id
        )
      this.trash = this.allEntries.filter((e) => e.deleted)
    },
    // 整库加密后上传（端到端加密的唯一写路径）。
    // 上传后回拉一次：服务端会为新条目分配 uuid（置顶偏好按 uuid 记录）。
    async pushVault() {
      const encrypted = await vault.encryptEntries(this.allEntries)
      await api.putVault(encrypted, this.token)
      await this.loadVault()
    },
    // 网页端置顶：写入服务端按账号保存的偏好，不影响桌面端的按设备置顶。
    async togglePin(e) {
      if (!e.uuid) {
        this.error = this.$t('msg.pinNeedSave')
        return
      }
      try {
        e.pinned = !e.pinned
        await this.pushVault()
        this.msg = this.$t(e.pinned ? 'msg.pinned' : 'msg.unpinned')
      } catch (err) {
        this.error = String(err.message || err)
        await this.loadVault()
      }
    },
    onDragStart(e) {
      if (!this.canDrag) return
      this.dragId = e.id
    },
    onDragOver(e) {
      if (this.dragId != null && this.dragId !== e.id) this.dragOverId = e.id
    },
    onDragLeave(e) {
      if (this.dragOverId === e.id) this.dragOverId = null
    },
    onDragEnd() {
      this.dragId = null
      this.dragOverId = null
    },
    // 拖拽落点：在可见顺序中把被拖条目移动到目标位置；置顶组与普通组之间禁止互拖
    // （列表规则是置顶永远在前，跨组拖动只会被排序规则弹回）。
    async onDrop(target) {
      const from = this.dragId
      this.dragId = null
      this.dragOverId = null
      if (from == null || from === target.id) return
      const list = this.entries.slice()
      const fi = list.findIndex((x) => x.id === from)
      const ti = list.findIndex((x) => x.id === target.id)
      if (fi < 0 || ti < 0) return
      const fp = !!list[fi].pinned
      const tp = !!list[ti].pinned
      if (fp !== tp) {
        this.error = this.$t('msg.pinGroupLocked')
        return
      }
      const [moved] = list.splice(fi, 1)
      list.splice(ti, 0, moved)
      // 组内重排序号：置顶组与普通组各自连续，落库后随同步传播到桌面端。
      let p = 0
      let u = 0
      for (const e of list) {
        if (e.pinned) e.sort_order = ++p
        else e.sort_order = ++u
      }
      try {
        await this.pushVault()
      } catch (err) {
        this.error = String(err.message || err)
        await this.loadVault()
      }
    },
    renumber() {
      this.allEntries
        .filter((e) => !e.deleted)
        .sort((a, b) => a.sort_order - b.sort_order || a.id - b.id)
        .forEach((e, i) => {
          e.sort_order = i + 1
        })
    },
    nextId() {
      return this.allEntries.reduce((m, e) => Math.max(m, e.id || 0), 0) + 1
    },
    // 旧数据迁移：服务端历史上用静态密钥加密的条目，取回明文后用 vault key 重新加密。
    // 迁移成功后上报服务端落"已完成"标记，永久关闭 legacy 明文接口（一次性后门）。
    async migrateLegacy() {
      try {
        const r = await api.getLegacy(this.token)
        const legacy = r.entries || []
        if (legacy.length === 0) return
        const map = new Map(legacy.map((e) => [e.id, e]))
        const cipher = await api.getVault(this.token)
        const vk = vault.getVaultKey()
        const out = []
        for (const e of cipher.entries || []) {
          const old = map.get(e.id)
          if (!old) {
            // 已是端到端密文，原样保留。
            out.push(e)
            continue
          }
          // 旧数据：服务端取回的明文，用 vault key 重新加密后再上传。
          out.push({
            ...e,
            password: await vault.encryptString(vk, old.password || ''),
            notes: await vault.encryptString(vk, old.notes || '')
          })
        }
        await api.putVault(out, this.token)
        // 明文已全部重新加密上传 → 上报标记，服务端此后对 legacy 接口返回 410。
        try {
          await api.markLegacyDone(this.token)
        } catch (e2) {
          /* 标记失败不影响本次迁移，下次解锁会重试 */
        }
        this.msg = this.$t('msg.migrated', { n: legacy.length })
      } catch (e) {
        /* 迁移失败不阻塞使用，下次解锁会重试 */
      }
    },
    async restoreEntry(id) {
      try {
        const e = this.allEntries.find((x) => x.id === id)
        if (!e) return
        e.deleted = false
        e.sort_order = this.nextId()
        this.renumber()
        await this.pushVault()
        this.msg = this.$t('trash.restored')
      } catch (err) {
        this.error = String(err.message || err)
      }
    },
    async purgeEntry(id) {
      this.askConfirm(this.$t('trash.confirmPurge'), async () => {
        try {
          this.allEntries = this.allEntries.filter((e) => e.id !== id)
          await this.pushVault()
          this.msg = this.$t('trash.purged')
        } catch (err) {
          this.error = String(err.message || err)
        }
      })
    },
    async emptyTrash() {
      this.askConfirm(this.$t('trash.confirmEmpty'), async () => {
        try {
          this.allEntries = this.allEntries.filter((e) => !e.deleted)
          await this.pushVault()
          this.msg = this.$t('trash.emptied')
        } catch (err) {
          this.error = String(err.message || err)
        }
      })
    },
    async loadUsers() {
      const r = await api.listUsers(this.token)
      this.users = r.users || []
      // 顺带拉取"未迁移账号"提示；失败不阻塞用户列表展示。
      try {
        const p = await api.legacyPending(this.token)
        this.legacyPending = p.users || []
        this.legacyRemoveVersion = p.remove_version || ''
      } catch (e) {
        this.legacyPending = []
      }
    },
    async loadLogs() {
      try {
        const r = await api.listLogs(this.token)
        this.logs = r.logs || []
      } catch (e) {
        this.error = String(e.message || e)
      }
    },
    async loadSettings() {
      try {
        const r = await api.getSettings(this.token)
        const smtp = r.smtp || { host: '', port: 465, username: '', password: '', from: '', ssl: false, vendor: 'qq' }
        if (!smtp.vendor) smtp.vendor = 'qq'
        this.settings = {
          smtp,
          smtp_enabled: !!r.smtp_enabled,
          email_verify_mode: r.email_verify_mode || 'none',
          allow_registration: !!r.allow_registration,
          password_min_length: r.password_min_length || 6,
          password_require_complex: !!r.password_require_complex,
          recycle: r.recycle !== false,
          recycle_days: r.recycle_days || 30
        }
        if (r.site) this.site = this.normalizeSite(r.site)
        // 根据当前配置推算显示用的加密模式
        if (smtp.ssl) this.settingsSecureMode = 'ssl'
        else if (smtp.port === 587 || smtp.port === 2525) this.settingsSecureMode = 'tls'
        else this.settingsSecureMode = 'none'
        this.portAuto = true
      } catch (e) {
        this.error = String(e.message || e)
      }
    },
    onVendorChange() {
      const v = this.settings.smtp.vendor
      const presets = {
        qq:     { host: 'smtp.qq.com',      port: 465, ssl: true,  secure: 'ssl' },
        '126':  { host: 'smtp.126.com',     port: 465, ssl: true,  secure: 'ssl' },
        '163':  { host: 'smtp.163.com',     port: 465, ssl: true,  secure: 'ssl' },
        gmail:  { host: 'smtp.gmail.com',   port: 587, ssl: false, secure: 'tls' },
        outlook:{ host: 'smtp.office365.com', port: 587, ssl: false, secure: 'tls' },
        custom: { host: this.settings.smtp.host || '', port: this.settings.smtp.port || 465, ssl: !!this.settings.smtp.ssl, secure: this.settingsSecureMode || 'ssl' }
      }
      const p = presets[v]
      this.settings.smtp.host = p.host
      this.settings.smtp.port = p.port
      this.settings.smtp.ssl = p.ssl
      this.settingsSecureMode = p.secure
      this.portAuto = true
      // 非自定义模式：用户名与邮箱地址联动
      if (v !== 'custom') {
        this.settings.smtp.username = this.settings.smtp.from || this.settings.smtp.username
      }
    },
    onSecureChange() {
      if (!this.portAuto) return
      const m = this.settingsSecureMode
      const map = { ssl: 465, tls: 587, none: 25 }
      this.settings.smtp.port = map[m]
      this.settings.smtp.ssl = m === 'ssl'
    },
    onPortEdit() {
      this.portAuto = false
    },
    showVendorAuthHelp() {
      alert(this.$t('settings.vendorAuthHelp'))
    },
    onIconError(e) {
      // 图片服务器维护时可能加载失败，隐藏图标保留文字。
      e.target.style.display = 'none'
    },
    async saveSettings() {
      try {
        const s = this.settings.smtp
        // 非自定义厂商：用户名/发件人=邮箱地址，host/port/ssl 按厂商预设
        if (s.vendor !== 'custom') {
          s.username = s.from
          const presets = {
            qq:     { host: 'smtp.qq.com',      port: 465, ssl: true },
            '126':  { host: 'smtp.126.com',     port: 465, ssl: true },
            '163':  { host: 'smtp.163.com',     port: 465, ssl: true },
            gmail:  { host: 'smtp.gmail.com',   port: 587, ssl: false },
            outlook:{ host: 'smtp.office365.com', port: 587, ssl: false }
          }
          const p = presets[s.vendor]
          if (p) { s.host = p.host; s.port = p.port; s.ssl = p.ssl }
        }
        await api.updateSettings({
          vendor: s.vendor,
          host: s.host,
          port: s.port,
          username: s.username,
          password: s.password,
          from: s.from,
          ssl: s.ssl,
          smtp_enabled: this.settings.smtp_enabled,
          mode: this.settings.email_verify_mode,
          allow_registration: this.settings.allow_registration,
          password_min_length: this.settings.password_min_length,
          password_require_complex: this.settings.password_require_complex,
          recycle: this.settings.recycle,
          recycle_days: this.settings.recycle_days,
          site: this.site
        }, this.token)
        this.msg = this.$t('msg.saved')
        await this.loadSettings()
      } catch (e) {
        this.error = String(e.message || e)
      }
    },
    async exportSettings() {
      try {
        const r = await api.exportSettings(this.token)
        const blob = new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = this.$t('app.title') + '-config.json'
        a.click()
        URL.revokeObjectURL(url)
        this.msg = this.$t('msg.saved')
      } catch (e) {
        this.error = String(e.message || e)
      }
    },
    async importSettingsFile(e) {
      const file = e.target.files && e.target.files[0]
      if (!file) return
      try {
        const text = await file.text()
        const data = JSON.parse(text)
        await api.importSettings(data, this.token)
        this.msg = this.$t('msg.saved')
        await this.loadSettings()
      } catch (err) {
        this.error = String(err.message || err)
      } finally {
        e.target.value = ''
      }
    },
    async sendTestEmail() {
      if (!this.testEmail) {
        this.error = this.$t('settings.testEmailRequired')
        return
      }
      try {
        await api.testEmail(this.testEmail, this.token)
        this.msg = this.$t('settings.testSent')
      } catch (e) {
        this.error = String(e.message || e)
      }
    },
    startAdd() {
      this.form = this.emptyForm()
      this.formShow = false
      this.editing = {}
    },
    startEdit(e) {
      this.form = { ...e }
      this.formShow = false
      this.editing = { id: e.id }
    },
    async save() {
      if (!this.form.title) {
        this.error = this.$t('msg.titleRequired')
        return
      }
      if (!this.form.username) {
        this.error = this.$t('msg.usernameRequired')
        return
      }
      if (!this.form.password) {
        this.error = this.$t('msg.passwordRequired')
        return
      }
      if (!this.form.url) {
        this.error = this.$t('msg.urlRequired')
        return
      }
      try {
        const now = nowRfc3339()
        if (this.form.id) {
          const i = this.allEntries.findIndex((x) => x.id === this.form.id)
          if (i >= 0) this.allEntries[i] = { ...this.allEntries[i], ...this.form, updated_at: now }
        } else {
          const id = this.nextId()
          this.allEntries.push({
            ...normalizeEntry(this.form),
            id,
            sort_order: id,
            created_at: now,
            updated_at: now,
            deleted: false
          })
        }
        this.renumber()
        await this.pushVault()
        this.editing = null
        this.msg = this.$t('msg.saved')
      } catch (e) {
        this.error = String(e.message || e)
      }
    },
    async copyText(text) {
      if (!text) return
      try {
        const value = String(text)
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(value)
        } else {
          const ta = document.createElement('textarea')
          ta.value = value
          ta.style.position = 'fixed'
          ta.style.opacity = '0'
          document.body.appendChild(ta)
          ta.select()
          document.execCommand('copy')
          document.body.removeChild(ta)
        }
        this.msg = this.$t('msg.copied')
      } catch (e) {
        this.error = String(e)
      }
    },
    askConfirm(text, fn) {
      this.confirmBox = { text, onOk: fn }
    },
    async remove(e) {
      this.askConfirm(this.$t('msg.confirmDelete', { title: e.title }), async () => {
        try {
          if (this.recycleEnabled) {
            // 走回收站：打墓碑标记并保留密文，便于恢复。
            const item = this.allEntries.find((x) => x.id === e.id)
            if (item) {
              item.deleted = true
              item.sort_order = 0
              item.updated_at = nowRfc3339()
            }
          } else {
            this.allEntries = this.allEntries.filter((x) => x.id !== e.id)
          }
          this.renumber()
          await this.pushVault()
          this.msg = this.$t('msg.deleted')
        } catch (err) {
          this.error = String(err.message || err)
        }
      })
    },
    toggleReveal(id) {
      if (this.revealed.has(id)) this.revealed.delete(id)
      else this.revealed.add(id)
    },
    exportTxt() {
      const lines = [this.$t('app.title'), '='.repeat(60), '']
      for (const e of this.entries) {
        lines.push(this.fieldName('modal.title') + ': ' + e.title)
        lines.push(this.fieldName('modal.username') + ': ' + e.username)
        lines.push(this.fieldName('modal.password') + ': ' + e.password)
        lines.push(this.fieldName('modal.url') + ': ' + e.url)
        lines.push(this.fieldName('modal.category') + ': ' + e.category)
        lines.push(this.fieldName('modal.notes') + ': ' + e.notes)
        lines.push('-'.repeat(60))
      }
      const blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = this.$t('app.title') + '.txt'
      a.click()
      URL.revokeObjectURL(url)
      this.msg = this.$t('msg.exported', { n: this.entries.length })
    },
    onIO() {
      const v = this.ioFormat
      if (v === 'import-csv' || v === 'import-txt') {
        this.importFormat = v === 'import-txt' ? 'txt' : 'csv'
        this.$refs.fileInput.click()
      } else if (v === 'export-csv') {
        this.exportCsv()
      } else if (v === 'export-txt') {
        this.exportTxt()
      }
      this.ioFormat = ''
    },
    async importFile(e) {
      const file = e.target.files && e.target.files[0]
      const f = this.importFormat
      if (!file) return
      try {
        // 浏览器本地解析（兼容 UTF-8 / GBK），明文不经过服务端。
        const bytes = new Uint8Array(await file.arrayBuffer())
        const parsed = f === 'txt' ? parseTxtEntries(bytes) : parseCsvEntries(bytes)
        const now = nowRfc3339()
        for (const item of parsed) {
          const id = this.nextId()
          this.allEntries.push({
            ...normalizeEntry(item),
            id,
            sort_order: id,
            created_at: now,
            updated_at: now,
            deleted: false
          })
        }
        this.renumber()
        await this.pushVault()
        this.msg = this.$t('msg.imported', { n: parsed.length })
      } catch (err) {
        this.error = String(err.message || err)
      } finally {
        e.target.value = ''
        this.importFormat = ''
      }
    },
    exportCsv() {
      const keys = ['title', 'username', 'password', 'url', 'category', 'notes']
      const header = keys.map((k) => this.fieldName('modal.' + k))
      const rows = [header.map(csvEscape).join(',')]
      for (const e of this.entries) {
        rows.push([e.title, e.username, e.password, e.url, e.category, e.notes].map(csvEscape).join(','))
      }
      const csv = '\ufeff' + rows.join('\r\n')
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = this.$t('app.title') + '.csv'
      a.click()
      URL.revokeObjectURL(url)
      this.msg = this.$t('msg.exportedCsv', { n: this.entries.length })
    },
    downloadTemplate() {
      const keys = ['title', 'username', 'password', 'url', 'category', 'notes']
      const header = keys.map((k) => this.fieldName('modal.' + k)).join(',')
      // 附带一条示例数据（文案跟随应用语言），导入后可直接看到各列含义（密码建议导入前自行替换）。
      const example = [this.$t('tpl.site'), this.$t('tpl.user'), this.$t('tpl.pass'), this.$t('tpl.url'), this.$t('tpl.category'), this.$t('tpl.notes')]
      const csv = '\ufeff' + header + '\r\n' + example.map(csvEscape).join(',') + '\r\n'
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = this.$t('app.title') + ' - ' + this.$t('file.template') + '.csv'
      a.click()
      URL.revokeObjectURL(url)
    },
    openAddUser() {
      this.userError = ''
      this.newUser = { username: '', email: '', password: '', role: 'user' }
      this.showAddUser = true
    },
    async createUser() {
      this.userError = ''
      if (!this.newUser.username) {
        this.userError = this.$t('msg.usernameRequired')
        return
      }
      if (!this.newUser.email) {
        this.userError = this.$t('msg.emailRequired')
        return
      }
      if (!this.newUser.password || this.newUser.password.length < 6) {
        this.userError = this.$t('msg.passwordRequired')
        return
      }
      try {
        await api.createUser(this.newUser, this.token)
        this.showAddUser = false
        this.newUser = { username: '', email: '', password: '', role: 'user' }
        this.msg = this.$t('msg.userAdded')
        await this.loadUsers()
      } catch (e) {
        this.userError = String(e.message || e)
      }
    },
    downloadUserTemplate() {
      const keys = ['username', 'password', 'email', 'role']
      const header = keys.map((k) => this.$t('users.' + k)).join(',')
      // 附带一条示例数据（文案跟随应用语言）：role 支持「普通用户 / 管理员」，留空默认普通用户。
      const example = [this.$t('tpl.uName'), this.$t('tpl.uPass'), this.$t('tpl.uEmail'), this.$t('tpl.uRole')]
      const csv = '\ufeff' + header + '\r\n' + example.map(csvEscape).join(',') + '\r\n'
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = this.$t('app.title') + ' - ' + this.$t('users.template') + '.csv'
      a.click()
      URL.revokeObjectURL(url)
    },
    // 导出当前用户列表（CSV，含 ID/用户名/邮箱/角色/状态/创建时间；不含密码等敏感字段）。
    exportUsers() {
      const header = ['ID', this.$t('users.username'), this.$t('users.email'), this.$t('users.role'), this.$t('users.statusLabel') || '状态', this.$t('users.createdAt') || '创建时间']
      const rows = [header.map(csvEscape).join(',')]
      for (const u of this.users) {
        rows.push([u.id, u.username, u.email || '', this.roleLabel(u.role), u.status, this.formatLogTime(u.created_at)].map(csvEscape).join(','))
      }
      const csv = '\ufeff' + rows.join('\r\n')
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = this.$t('app.title') + ' - ' + this.$t('users.export') + '.csv'
      a.click()
      URL.revokeObjectURL(url)
      this.msg = this.$t('msg.userExported', { n: this.users.length })
    },
    async importUsersFile(e) {
      const file = e.target.files && e.target.files[0]
      if (!file) return
      try {
        const text = await file.text()
        const r = await api.importUsers(text, this.token)
        this.msg = this.$t('msg.usersImported', { n: r.count, m: r.skipped })
        await this.loadUsers()
      } catch (err) {
        this.error = String(err.message || err)
      } finally {
        e.target.value = ''
      }
    },
    async removeUser(u) {
      this.askConfirm(this.$t('msg.confirmDeleteUser', { username: u.username }), async () => {
        try {
          await api.deleteUser(u.id, this.token)
          this.msg = this.$t('msg.userDeleted')
          await this.loadUsers()
        } catch (err) {
          this.userError = String(err.message || err)
        }
      })
    },
    async toggleStatus(u) {
      const next = u.status === 'active' ? 'disabled' : 'active'
      try {
        await api.updateUserStatus(u.id, next, this.token)
        this.msg = next === 'active' ? this.$t('msg.enabled') : this.$t('msg.disabled')
        await this.loadUsers()
      } catch (e) {
        this.userError = String(e.message || e)
      }
    },
    roleLabel(role) {
      if (role === 'superadmin') return this.$t('role.superadmin')
      if (role === 'admin') return this.$t('role.admin')
      return this.$t('role.user')
    },
    avatarUrl(id) {
      // 相对路径，兼容统一网关前缀
      return 'api/avatar/' + id + '?v=' + this.avatarVersion
    },
    canManageUser(u) {
      if (u.id === this.myId) return false
      if (this.role === 'superadmin') return true
      // 与后端 CanManageUser 对齐（R8-01）：admin 只能管理普通用户，不能操作同级/上级管理员。
      if (this.role === 'admin') return u.role === 'user'
      return false
    },
    openMe() {
      this.meForm = { username: this.username, email: this.meEmail, email_code: '', current_password: '', new_password: '' }
      this.showMe = true
    },
    // 自助改绑邮箱：向新邮箱发送所有权验证码（管理员改他人邮箱不需要验证码）。
    async sendMyEmailCode() {
      const email = (this.meForm.email || '').trim()
      if (!email) {
        this.error = this.$t('login.emailRequired')
        return
      }
      this.emailCodeSending = true
      this.error = ''
      try {
        await api.sendMyEmailCode({ email }, this.token)
        this.msg = this.$t('me.codeSent')
      } catch (e) {
        this.error = String(e.message || e)
      } finally {
        this.emailCodeSending = false
      }
    },
    triggerAvatar() {
      this.$refs.avatarInput.click()
    },
    async uploadAvatar(e) {
      const file = e.target.files && e.target.files[0]
      if (!file) return
      try {
        const dataUrl = await new Promise((resolve, reject) => {
          const fr = new FileReader()
          fr.onload = () => resolve(fr.result)
          fr.onerror = reject
          fr.readAsDataURL(file)
        })
        const base64 = String(dataUrl).split(',')[1] || ''
        const ext = (file.name.split('.').pop() || 'png').toLowerCase()
        const r = await api.uploadAvatar({ data: base64, ext }, this.token)
        this.myAvatar = r.avatar
        this.avatarVersion++
        this.msg = this.$t('msg.avatarUpdated')
      } catch (err) {
        this.error = String(err.message || err)
      } finally {
        e.target.value = ''
      }
    },
    async saveMe() {
      try {
        // 改绑邮箱须先完成新邮箱验证码校验（R7-01），并填写当前密码。
        if (this.meEmailChanged) {
          if (!(this.meForm.email_code || '').trim()) {
            this.error = this.$t('me.emailCodeRequired')
            return
          }
          if (!this.meForm.current_password) {
            this.error = this.$t('me.currentPasswordRequired')
            return
          }
        }
        // 主密钥由账号密码 + 派生盐得出：密码变更（或老账号的用户名变更）后，
        // 必须用新的 master key 重新包裹 vault key，且与密码变更在同一请求内提交。
        // 若当前未解锁，本页无法重新包裹 —— 此时必须拒绝操作，否则旧密文将永久无法解密。
        const oldUsername = this.username
        const changing = !!(this.meForm.new_password || this.meForm.username !== oldUsername)
        let vk = null
        if (changing && this.vaultKeyEnc && !this.vaultUnlocked) {
          this.error = this.$t('msg.unlockRequiredForCredentialChange')
          return
        }
        if (changing && this.vaultUnlocked && this.vaultKeyEnc) {
          const oldMaster = await vault.deriveMasterKey(this.meForm.current_password, this.kdfSalt || oldUsername)
          vk = await vault.decryptVaultKey(oldMaster, this.vaultKeyEnc)
        }
        // 组装与密码变更同批提交的新盐与新 vault_key_enc。
        let newSalt = this.kdfSalt
        this.meForm.kdf_salt = ''
        this.meForm.vault_key_enc = ''
        if (changing && vk) {
          if (!newSalt) newSalt = vault.newSalt()
          const newPassword = this.meForm.new_password || this.meForm.current_password
          const newMaster = await vault.deriveMasterKey(newPassword, newSalt)
          const enc = await vault.encryptVaultKey(newMaster, vk)
          this.meForm.kdf_salt = newSalt
          this.meForm.vault_key_enc = enc
        }
        const upd = await api.updateMe(this.meForm, this.token)
        // 改密后服务端递增令牌版本（旧令牌立即失效）并为当前会话重新签发，
        // 这里必须先换用新令牌，否则后续请求会 401。
        if (upd && upd.token) {
          // 令牌仅更新内存副本；服务端已在响应中下发新的 HttpOnly 会话 Cookie（R8-07），
          // 刷新后由该 Cookie 续期。
          this.token = upd.token
        }
        if (this.meForm.vault_key_enc) {
          this.vaultKeyEnc = this.meForm.vault_key_enc
          this.kdfSalt = this.meForm.kdf_salt
        }
        this.meForm.current_password = ''
        this.meForm.new_password = ''
        this.meForm.email_code = ''
        this.meForm.kdf_salt = ''
        this.meForm.vault_key_enc = ''
        this.showMe = false
        this.msg = this.$t('msg.meUpdated')
        const me = await api.me(this.token)
        this.username = me.username
        this.meEmail = me.email || ''
        // 以服务端记录为准回读派生盐与密文，确保本地与库内状态一致（避免再次漂移）。
        this.kdfSalt = me.kdf_salt || this.kdfSalt
        this.vaultKeyEnc = me.vault_key_enc || this.vaultKeyEnc
        sessionStorage.setItem('username', me.username)
      } catch (e) {
        this.error = String(e.message || e)
      }
    },
    startEditUser(u) {
      // 非超级管理员不得授予管理员角色：编辑框内强制回落到普通用户，
      // 与后端 R9-01 的校验一致（避免下拉框出现无匹配选项）。
      const editableRole = this.role === 'superadmin' ? u.role : 'user'
      this.userForm = { username: u.username, email: u.email || '', password: '', role: editableRole, status: u.status }
      this.editingUser = u
    },
    async saveUser() {
      try {
        await api.updateUser(this.editingUser.id, this.userForm, this.token)
        this.editingUser = null
        this.msg = this.$t('msg.userUpdated')
        await this.loadUsers()
      } catch (e) {
        this.userError = String(e.message || e)
      }
    }
  }
}
</script>

<style scoped>
.gate {
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
}
.gate-card {
  width: 340px;
  background: #fff;
  padding: 32px;
  border-radius: 12px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.gate-card h1 {
  font-size: 20px;
  text-align: center;
  margin-bottom: 8px;
}
.gate-links {
  display: flex;
  justify-content: space-between;
  gap: 8px;
}
.recovery {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-top: 4px;
  padding-top: 12px;
  border-top: 1px solid #eee;
}
.link {
  background: transparent;
  color: var(--fnos-primary);
  padding: 4px;
  font-size: 13px;
}
.code-row {
  display: flex;
  gap: 8px;
}
.code-row input {
  flex: 1;
}
.code-row button {
  flex-shrink: 0;
  width: auto;
}
/* 禁用态按钮（如回收站为空时的「清空回收站」）：灰显且不可点击 */
button:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}
/* 关于页：logo 居中，信息在下 */
.about-card {
  max-width: 560px;
  margin: 32px auto;
  padding: 28px 32px;
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 12px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.06);
  display: flex;
  flex-direction: column;
  text-align: left;
}
.about-head {
  display: flex;
  align-items: center;
  gap: 20px;
}
.about-logo {
  width: 72px;
  height: 72px;
  border-radius: 16px;
  flex-shrink: 0;
}
.about-info {
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 14px;
  color: #374151;
}
.about-title {
  font-size: 16px;
  font-weight: 600;
  color: #111827;
  margin-bottom: 2px;
}
.about-line {
  margin: 0;
}
.about-divider {
  width: 100%;
  height: 1px;
  background: #e5e7eb;
  margin: 20px 0 12px;
}
.about-subtitle {
  font-size: 13px;
  font-weight: 600;
  color: #111827;
  margin: 0 0 8px;
  align-self: flex-start;
}
.about-changelog {
  width: 100%;
  max-height: 240px;
  overflow-y: auto;
  text-align: left;
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-right: 4px;
}
.cl-item {
  font-size: 12.5px;
  color: #6b7280;
}
.cl-item.current .cl-ver {
  color: var(--fnos-primary, #2563eb);
  font-weight: 700;
}
.cl-ver {
  font-weight: 600;
  color: #374151;
  margin-bottom: 2px;
}
.cl-tag {
  margin-left: 6px;
  font-size: 11px;
  font-weight: 500;
  color: #2563eb;
  background: #eff6ff;
  border: 1px solid #bfdbfe;
  border-radius: 999px;
  padding: 0 8px;
}
.cl-items {
  margin: 0;
  padding-left: 16px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.inline {
  margin: 8px 0;
}
.lang-select {
  background: #f9fafb;
  color: #1f2937;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  padding: 6px 8px;
  font-size: 13px;
  outline: none;
  width: auto;
  min-width: 96px;
}
.menu-select {
  width: auto;
  min-width: 96px;
  cursor: pointer;
}
.menu-label {
  align-self: center;
  color: #6b7280;
  font-size: 13px;
}
.lang-fixed {
  position: fixed;
  top: 14px;
  right: 14px;
  z-index: 9999;
}
.app {
  height: 100%;
  display: flex;
  flex-direction: column;
  padding: 16px 24px;
}
.topbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  padding-right: 120px;
}
.user-info {
  display: flex;
  align-items: center;
  gap: 12px;
  color: #6b7280;
}
.user-menu {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  position: relative;
  padding: 4px 8px;
  border-radius: 6px;
}
.user-menu:hover {
  background: #f3f4f6;
}
.user-name {
  font-weight: 500;
  max-width: 140px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.caret {
  font-size: 10px;
  color: #9ca3af;
}
.user-dropdown {
  position: absolute;
  top: calc(100% + 6px);
  right: 0;
  background: #fff;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
  min-width: 160px;
  z-index: 10001;
  overflow: hidden;
}
.dropdown-item {
  display: block;
  width: 100%;
  text-align: left;
  background: transparent;
  border: none;
  border-radius: 0;
  padding: 10px 14px;
  font-size: 14px;
  color: #1f2937;
}
.dropdown-item:hover {
  background: #f3f4f6;
}
.menu-backdrop {
  position: fixed;
  inset: 0;
  z-index: 10000;
}
.avatar {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  object-fit: cover;
  flex-shrink: 0;
}
.avatar-lg {
  width: 56px;
  height: 56px;
}
.avatar-fallback {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: var(--fnos-primary);
  color: #fff;
  font-weight: 600;
}
.avatar-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
}
.layout {
  flex: 1;
  display: flex;
  min-height: 0;
  gap: 16px;
}
.sidebar {
  width: 152px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 8px 0;
  border-right: 1px solid #e5e7eb;
}
.sidebar button {
  background: transparent;
  color: #6b7280;
  border-radius: 6px;
  padding: 10px 14px;
  text-align: left;
  width: 100%;
}
.sidebar button:hover {
  background: #f3f4f6;
}
.sidebar button.active {
  color: var(--fnos-primary);
  background: var(--fnos-primary-light);
  font-weight: 600;
}
.sidebar-footer {
  margin-top: auto;
  padding-top: 8px;
  border-top: 1px solid #e5e7eb;
  display: flex;
  align-items: center;
  gap: 16px;
  padding-left: 12px;
}
/* 用 .sidebar button.theme-toggle 提高优先级，避免被 .sidebar button 的 width:100% 覆盖 */
.sidebar button.theme-toggle {
  width: 18px;
  height: 36px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  color: #6b7280;
  border-radius: 4px;
  padding: 0;
  font-size: 16px;
  line-height: 1;
}
.theme-toggle:hover {
  background: #f3f4f6;
}
.theme-icon {
  font-size: 16px;
}
.gh-link {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 36px;
  border-radius: 4px;
  color: #6b7280;
  flex-shrink: 0;
}
.gh-link:hover {
  background: #f3f4f6;
  color: #111827;
}
.about-link {
  color: var(--fnos-primary);
  text-decoration: none;
  word-break: break-all;
}
.about-link:hover {
  text-decoration: underline;
}
.content {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  overflow-y: auto;
}
.panel {
  flex: 1;
  min-height: 0;
}
.toolbar {
  display: flex;
  gap: 8px;
  margin-bottom: 14px;
  align-items: center;
  flex-wrap: wrap;
}
.toolbar-main,
.toolbar-sub {
  display: contents;
}
.toolbar input {
  flex: 1;
}
.add-user {
  display: flex;
  gap: 8px;
  width: 100%;
}
.add-user select {
  width: 140px;
}
.list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.grid-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
  gap: 8px;
  align-items: start;
}
.row {
  display: flex;
  align-items: center;
  gap: 16px;
  background: #fff;
  padding: 12px 16px;
  border-radius: 8px;
  border: 1px solid #e5e7eb;
}
.main {
  flex: 1;
  min-width: 0;
}
.entry {
  display: flex;
  flex-direction: column;
  gap: 8px;
  background: #fff;
  padding: 12px 16px;
  border-radius: 8px;
  border: 1px solid #e5e7eb;
}
.entry-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
}
.entry-meta {
  display: flex;
  flex-direction: column;
  gap: 4px;
  color: #6b7280;
  font-size: 12px;
}
.meta-line {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.label {
  color: #9ca3af;
  flex-shrink: 0;
}
.title {
  font-weight: 600;
}
.meta {
  display: flex;
  gap: 12px;
  color: #6b7280;
  font-size: 12px;
  margin-top: 4px;
  align-items: center;
}
.tag {
  background: #eef2ff;
  color: #4f46e5;
  padding: 1px 8px;
  border-radius: 10px;
}
.ok {
  color: #16a34a;
}
.off {
  color: #dc2626;
}
.pw {
  display: flex;
  align-items: center;
  gap: 8px;
}
.mono {
  font-family: 'Consolas', monospace;
}
.field {
  cursor: pointer;
}
.field:hover {
  color: var(--fnos-primary);
}
.copy-btn {
  background: transparent;
  color: var(--fnos-primary);
  border: 1px solid var(--fnos-primary);
  padding: 2px 8px;
  font-size: 12px;
  border-radius: 4px;
  flex-shrink: 0;
  cursor: pointer;
}
.copy-btn:hover {
  background: var(--fnos-primary-light);
}
.ops {
  display: flex;
  gap: 6px;
}
.empty {
  text-align: center;
  color: #9ca3af;
  margin-top: 40px;
}
.mask {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.4);
  display: flex;
  align-items: center;
  justify-content: center;
}
.modal {
  width: 420px;
  max-height: 90%;
  overflow-y: auto;
  background: #fff;
  border-radius: 12px;
  padding: 24px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.modal h2 {
  margin-bottom: 8px;
}
.modal-confirm {
  width: 360px;
}
.confirm-text {
  color: #374151;
  line-height: 1.6;
  margin-bottom: 8px;
}
.modal label {
  color: #6b7280;
  font-size: 12px;
  margin-top: 6px;
}
.pw-row {
  display: flex;
  gap: 8px;
}
.pw-row input {
  flex: 1;
}
.modal-actions {
  display: flex;
  gap: 8px;
  justify-content: flex-end;
  margin-top: 12px;
}
.toast {
  position: fixed;
  top: 20px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 9999;
  padding: 10px 18px;
  border-radius: 8px;
  font-size: 14px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
  max-width: calc(100% - 32px);
}
.toast-error {
  background: #fef2f2;
  color: #dc2626;
  border: 1px solid #fecaca;
}
.toast-msg {
  background: #f0fdf4;
  color: #16a34a;
  border: 1px solid #bbf7d0;
}
/* Settings Card */
.settings-card {
  background: #fff;
  border-radius: 12px;
  border: 1px solid #e5e7eb;
  overflow: hidden;
}
.card-header {
  padding: 10px 16px;
  background: #f9fafb;
  border-bottom: 1px solid #e5e7eb;
}
.card-header h3 {
  font-size: 13px;
  font-weight: 600;
  color: #111827;
}
.card-body {
  padding: 12px 16px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.card-footer {
  padding: 10px 16px;
  border-top: 1px solid #e5e7eb;
  display: flex;
  justify-content: flex-end;
}
.card-divider {
  height: 1px;
  background: #e5e7eb;
}
.form-label {
  color: #374151;
  font-size: 12px;
  font-weight: 500;
  margin-bottom: -2px;
}
.form-label .link-inline {
  color: var(--fnos-primary);
  font-weight: 400;
  margin-left: 8px;
  text-decoration: none;
  cursor: pointer;
}
.form-label .link-inline:hover {
  text-decoration: underline;
}
.select-block {
  width: 100%;
}
.card-header-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}
.select-inline {
  width: auto;
  min-width: 90px;
}
.test-email-row {
  display: flex;
  gap: 8px;
  margin-top: 4px;
}
.test-email-row input {
  flex: 1;
}
.test-email-row button {
  flex-shrink: 0;
}
.settings-card input,
.settings-card select {
  padding: 6px 10px;
  font-size: 13px;
}
.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
}
.form-col {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.form-col .form-label {
  margin-bottom: 0;
}
.tip {
  background: #eff6ff;
  color: var(--fnos-primary-active);
  font-size: 11px;
  padding: 6px 10px;
  border-radius: 6px;
  border: 1px solid #bfdbfe;
}
/* Site Footer */
.site-footer {
  flex-shrink: 0;
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid #e5e7eb;
  text-align: center;
  color: #9ca3af;
  font-size: 12px;
}
.footer-line {
  margin-bottom: 6px;
}
.footer-links {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 16px;
  justify-content: center;
  align-items: center;
}
.footer-link {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  color: #6b7280;
  text-decoration: none;
  white-space: nowrap;
}
a.footer-link:hover {
  color: var(--fnos-primary);
}
.beian-icon {
  width: 14px;
  height: 14px;
  flex-shrink: 0;
}

/* 手机端布局适配 */
@media (max-width: 640px) {
  .gate-card {
    width: calc(100% - 32px);
    padding: 24px;
  }
  .app {
    padding: 12px 14px;
  }
  .topbar {
    flex-direction: column;
    align-items: flex-start;
    gap: 10px;
    padding-right: 0;
  }
  .user-info {
    flex-wrap: wrap;
    gap: 8px;
  }
  .layout {
    flex-direction: column;
  }
  .sidebar {
    width: 100%;
    flex-direction: row;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
    border-right: none;
    border-bottom: 1px solid #e5e7eb;
    padding: 4px 0;
  }
  .sidebar button {
    padding: 8px 14px;
    white-space: nowrap;
    flex-shrink: 0;
    width: auto;
  }
  .toolbar {
    flex-direction: column;
    align-items: stretch;
  }
  .toolbar-main,
  .toolbar-sub {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .toolbar-main input {
    flex: 1;
    min-width: 0;
  }
  .toolbar-sub {
    flex-wrap: nowrap;
  }
  .entry-head {
    flex-wrap: wrap;
  }
  .add-user {
    flex-wrap: wrap;
  }
  .add-user input,
  .add-user select {
    flex: 1 1 100%;
    width: 100%;
  }
  .row {
    flex-direction: column;
    align-items: stretch;
    gap: 10px;
  }
  .row .pw,
  .row .ops {
    justify-content: space-between;
  }
  .modal {
    width: calc(100% - 32px);
    max-height: 92%;
  }
  .form-grid {
    grid-template-columns: 1fr;
  }
  .hide-mobile {
    display: none;
  }
}

/* ===== 深色主题：组件级表面与文字覆盖（全局部分见 style.css） ===== */
html[data-theme='dark'] .gate-card,
html[data-theme='dark'] .modal,
html[data-theme='dark'] .settings-card,
html[data-theme='dark'] .entry,
html[data-theme='dark'] .about-card {
  background: #1e293b;
  border-color: #334155;
}
html[data-theme='dark'] .sidebar {
  border-right-color: #334155;
}
html[data-theme='dark'] .theme-toggle,
html[data-theme='dark'] .gh-link,
html[data-theme='dark'] .user-info {
  color: #94a3b8;
}
html[data-theme='dark'] .sidebar button:hover,
html[data-theme='dark'] .theme-toggle:hover,
html[data-theme='dark'] .gh-link:hover,
html[data-theme='dark'] .user-menu:hover {
  background: #1e293b;
}
html[data-theme='dark'] .sidebar-footer {
  border-top-color: #334155;
}
html[data-theme='dark'] .title,
html[data-theme='dark'] .about-title,
html[data-theme='dark'] .about-subtitle,
html[data-theme='dark'] .cl-ver,
html[data-theme='dark'] .card-header h3,
html[data-theme='dark'] .modal h2 {
  color: #e2e8f0;
}
html[data-theme='dark'] .meta,
html[data-theme='dark'] .label,
html[data-theme='dark'] .about-line,
html[data-theme='dark'] .cl-items,
html[data-theme='dark'] .empty,
html[data-theme='dark'] .confirm-text {
  color: #94a3b8;
}
html[data-theme='dark'] .card-header {
  background: #0f172a;
  border-bottom-color: #334155;
}
html[data-theme='dark'] .card-divider {
  background: #334155;
}
html[data-theme='dark'] .tag {
  background: #1e3a5f;
  color: #93c5fd;
}
html[data-theme='dark'] .dropdown-menu {
  background: #1e293b;
  border-color: #334155;
}
html[data-theme='dark'] .cl-tag {
  background: #1e3a5f;
  border-color: #334155;
  color: #93c5fd;
}

/* ===== 置顶与拖拽排序（网页端，偏好按账号保存在服务端） ===== */
.entry-pinned {
  border-left: 3px solid var(--fnos-primary);
}
.entry[draggable='true'] {
  cursor: grab;
}
.entry-dragging {
  opacity: 0.45;
}
.entry-drop-target {
  border-color: var(--fnos-primary);
  background: #f0f6ff;
}
.entry-head .title {
  display: flex;
  align-items: center;
  gap: 4px;
  min-width: 0;
}
.pin-mark {
  display: inline-flex;
  align-items: center;
  color: var(--fnos-primary);
  flex-shrink: 0;
}
.pin-btn.pin-on {
  color: var(--fnos-primary);
  border-color: var(--fnos-primary);
}
html[data-theme='dark'] .entry-drop-target {
  background: #1e3a5f;
}
</style>
