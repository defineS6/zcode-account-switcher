'use strict';
/**
 * ZCode OAuth 凭据写盘 + 账号快照
 *
 * 流程（CLI OAuth + 系统浏览器）：
 *   1. oauthCli.ZaiAuthFlow.poll() 在用户登录后拿到 {token, zaiAccessToken, refreshToken, user}
 *      （token 是 CLI OAuth 返回的 zcode JWT，自带 billing 查询权限）
 *   2. finishLogin(tokenSet) → writeOAuthCredentials 加密写盘
 *   3. manager.capture() 做账号快照
 *   4. triggerBusinessLogin(zaiAccessToken) → POST api.z.ai/api/auth/z/login
 *      （逆向自 ZCode app.asar ZaiProviderAdapter.exchangeToken：
 *        客户端在换 token 后立刻用 zai.access_token 调此接口，
 *        服务端在此处为新 user_id 初始化 billing plan；跳过这步 = 没有 plan）
 *
 * 本模块不负责登录 URL 生成 / 网络换 token（那些在 oauthCli.js）。
 * 这里只保留：把换好的 token 集合安全地写入 ZCode 登录态文件 + 工具函数。
 */
const fs = require('fs');
const path = require('path');
const { CREDENTIALS_FILE, CONFIG_FILE } = require('./paths');
const { encrypt } = require('./zcodeCrypto');
const { extractFingerprint } = require('./fingerprint');
const manager = require('./manager');

// api.z.ai business login 端点（逆向自 ZCode 客户端 ZaiBusinessTokenResolver）
// ZCode 客户端在完成 OAuth 换 token 后立刻 POST 此接口，服务端在此初始化新账号 billing plan
const BUSINESS_LOGIN_URL = 'https://api.z.ai/api/auth/z/login';

// ===== Z.ai provider 配置（写盘字段用）=====
// 与 oauthBrowser.OAUTH 保持一致；bigmodel 入口已移除（新流程仅 zai）
const PROVIDER = {
  id: 'zai',
  providerIds: ['builtin:zai-start-plan', 'builtin:zai-coding-plan', 'builtin:zai'],
};

/**
 * 把 oauthBrowser 换好的 token 集合写入 ZCode 登录态文件，然后捕获账号快照。
 *
 * @param {object} opts
 * @param {object} opts.tokenSet - oauthBrowser.exchangeToken() 的返回
 * @param {string} opts.tokenSet.token - zcode JWT（必填）
 * @param {string} [opts.tokenSet.zaiAccessToken] - zai oauth access_token
 * @param {string} [opts.tokenSet.refreshToken] - zai refresh_token
 * @param {object} [opts.tokenSet.user] - 用户信息（email/name/avatar...）
 * @param {string} [opts.label] - 账号自定义名称（空则用邮箱）
 * @param {string} [opts.note='']
 * @param {boolean} [opts.overwrite=true]
 */
async function finishLogin({ tokenSet, label, note = '', overwrite = true } = {}) {
  if (!tokenSet || !tokenSet.token) throw new Error('缺少 token（zcode JWT）');

  const userInfo = normalizeUserInfo(tokenSet.user || {});

  // 保留原登录态内容（写盘前快照到内存），capture 后恢复 —— 确保新增账号不影响当前登录账号
  const prevCredentials = fs.existsSync(CREDENTIALS_FILE) ? fs.readFileSync(CREDENTIALS_FILE, 'utf8') : null;
  const prevConfig = fs.existsSync(CONFIG_FILE) ? fs.readFileSync(CONFIG_FILE, 'utf8') : null;

  // 写入新账号 token（capture 快照需要读到 v2 目录的最新登录态）
  writeOAuthCredentials(tokenSet, userInfo);

  const captured = manager.capture({ label, note, overwrite });

  // 恢复原登录态：把 v2 目录的 credentials/config 写回 capture 之前的内容
  // 这样 ZCode 客户端与工具前端读取的"当前账号"都保持不变（新增账号不切换）
  if (prevCredentials !== null) fs.writeFileSync(CREDENTIALS_FILE, prevCredentials, 'utf8');
  if (prevConfig !== null) fs.writeFileSync(CONFIG_FILE, prevConfig, 'utf8');

  // 触发服务端 billing plan 初始化：
  // 逆向自 ZCode 客户端 ZaiProviderAdapter.exchangeToken() →
  //   businessTokenResolver.resolve(accessToken) →
  //     POST https://api.z.ai/api/auth/z/login {token: accessToken}
  // 服务端在处理此请求时为新 user_id 创建/初始化 billing plan。
  // CLI OAuth 流程只返回 token，不自动调这个端点，必须手动补上。
  //
  // 策略：快速检查（~10s）同步返回结果，同时启动后台长轮询（~4min）确保 plan 最终初始化。
  // 服务端创建 plan 是异步过程，可能需要较长时间。
  const billingReady = await triggerBusinessLogin(tokenSet.zaiAccessToken, tokenSet.token);

  // 如果快速检查未就绪，启动后台轮询，UI 端的 [8s/20s/40s] 重试会自动拿到结果
  if (!billingReady && tokenSet.token) {
    const { buildBillingUrl, BILLING_CURRENT_URL } = require('./quota');
    const url = buildBillingUrl(BILLING_CURRENT_URL);
    const longDelays = [15000, 30000, 60000, 90000, 120000]; // 15s/30s/60s/90s/120s
    (async () => {
      for (const delay of longDelays) {
        await sleep(delay);
        try {
          const res = await fetch(url, {
            method: 'GET',
            headers: { accept: 'application/json', authorization: 'Bearer ' + tokenSet.token },
          });
          if (!res.ok) continue;
          const json = await res.json();
          const plans = json && json.data && Array.isArray(json.data.plans) ? json.data.plans : [];
          if (plans.length > 0) break; // plan 已初始化，后台轮询结束
        } catch (_) {}
      }
    })();
  }

  return {
    userInfo,
    fingerprint: extractFingerprint(),
    account: captured.meta,
    created: captured.created,
    skipped: captured.skipped,
    billingReady,
  };
}

/**
 * 触发服务端为新账号初始化 billing plan。
 *
 * 逆向自 ZCode 客户端 ZaiProviderAdapter.exchangeToken() 中的
 * businessTokenResolver.resolve(accessToken)：
 *   POST https://api.z.ai/api/auth/z/login { token: <zai_oauth_access_token> }
 *
 * 服务端在处理此请求时为 user_id 创建 billing plan（ZCode Start Plan）。
 * CLI OAuth 流程不自动调此接口，必须手动补上，否则新账号永远没有 plan。
 *
 * 服务端是异步处理的：POST 成功后 plan 不一定立刻出现在 billing/current，
 * 需要配合 checkBillingReady 轮询等待。首次 POST 失败（code:500）也可能是
 * 服务端延迟初始化，因此需要多次重试。
 *
 * @param {string} zaiAccessToken  - zai OAuth access_token（poll 返回的 zai.access_token）
 * @param {string} zcodeJwt        - zcode JWT（用于后续 billing 状态验证）
 * @returns {Promise<boolean>}     - billing plan 是否就绪
 */
async function triggerBusinessLogin(zaiAccessToken, zcodeJwt) {
  // 无论 zaiAccessToken 是否可用，都先检查 billing 是否已有 plan
  // （避免重复 POST 造成多余开销）
  if (await checkBillingReady(zcodeJwt, true)) return true;

  if (zaiAccessToken) {
    // 多次重试 POST，服务端可能在首次收到请求时才开始初始化
    const postDelays = [0, 3000, 10000]; // 立即、3s、10s
    for (let i = 0; i < postDelays.length; i++) {
      if (postDelays[i] > 0) await sleep(postDelays[i]);
      try {
        const res = await fetch(BUSINESS_LOGIN_URL, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            accept: 'application/json',
          },
          body: JSON.stringify({ token: zaiAccessToken }),
        });
        const json = await res.json().catch(() => null);
        if (json && (json.code === 0 || json.code === 200 || json.success === true)) {
          // POST 成功，轮询 billing 是否就绪
          if (await checkBillingReady(zcodeJwt)) return true;
        }
      } catch (_) {
        // 网络抖动不中断流程
      }
    }
  }

  // POST 全部失败或无 access_token，仍尝试等待 billing 自动初始化
  // （服务端可能在注册时异步创建 plan，或 POST 本身已触发了延迟初始化）
  return checkBillingReady(zcodeJwt);
}

/**
 * 检查 billing/current 的 plans 是否已就绪，渐进式重试。
 *
 * 使用 buildBillingUrl（带 app_version + platform 参数）查询，与 ZCode 客户端一致。
 * 服务端创建 billing plan 是异步过程，可能需要较长时间，因此采用渐进式重试：
 *   快速轮询（1s/3s/6s）→ 等待服务端处理（15s/30s/60s/90s）→ 最后检查（120s）
 * 总等待时间约 4 分钟。
 *
 * @param {string} zcodeJwt
 * @param {boolean} quickOnly - true 时只做前 3 次快速检查（首次判断已有 plan 时用）
 * @returns {Promise<boolean>}
 */
async function checkBillingReady(zcodeJwt, quickOnly = false) {
  if (!zcodeJwt) return false;
  const { buildBillingUrl, BILLING_CURRENT_URL } = require('./quota');
  const url = buildBillingUrl(BILLING_CURRENT_URL);
  const delays = quickOnly
    ? [500, 2000, 5000]                       // 快速检查模式：只等 ~7.5s
    : [1000, 3000, 6000, 15000, 30000, 60000, 90000, 120000]; // 完整模式：渐进等 ~4min
  for (const delay of delays) {
    await sleep(delay);
    try {
      const res = await fetch(url, {
        method: 'GET',
        headers: { accept: 'application/json', authorization: 'Bearer ' + zcodeJwt },
      });
      if (!res.ok) continue;
      const json = await res.json();
      const plans = json && json.data && Array.isArray(json.data.plans) ? json.data.plans : [];
      if (plans.length > 0) return true;
    } catch (_) {
      // 网络抖动不中断重试
    }
  }
  return false;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * 把 token 集合加密写入 credentials.json + config.json。
 *
 * 写盘字段（与 ZCode 客户端真实结构一致）：
 *   credentials.json:
 *     oauth:active_provider          = enc(zai)
 *     oauth:zai:access_token         = enc(zaiAccessToken)
 *     oauth:zai:refresh_token        = enc(refreshToken)
 *     oauth:zai:user_info            = enc(user JSON)
 *     zcodejwttoken                  = enc(token)            ← 调 API 用的 JWT
 *   config.json:
 *     provider[builtin:zai-*].options.apiKey = token(明文 JWT，含 user_id)
 */
function writeOAuthCredentials(tokenSet, userInfo = {}) {
  backupCurrentLoginState('oauth');

  const credentials = readJsonIfExists(CREDENTIALS_FILE, {});
  const config = readJsonIfExists(CONFIG_FILE, {});

  const zcodeJwtToken = tokenSet.token;          // 调 API 的 JWT
  const accessToken = tokenSet.zaiAccessToken;    // zai oauth access_token
  const refreshToken = tokenSet.refreshToken;

  credentials['oauth:active_provider'] = encrypt(PROVIDER.id);
  if (accessToken) credentials[`oauth:${PROVIDER.id}:access_token`] = encrypt(accessToken);
  if (refreshToken) credentials[`oauth:${PROVIDER.id}:refresh_token`] = encrypt(refreshToken);
  if (zcodeJwtToken) credentials.zcodejwttoken = encrypt(zcodeJwtToken);
  credentials[`oauth:${PROVIDER.id}:user_info`] = encrypt(JSON.stringify(userInfo || {}));

  if (!config.provider || typeof config.provider !== 'object') config.provider = {};
  if (zcodeJwtToken) updateConfigProviders(config, PROVIDER, zcodeJwtToken);

  atomicWriteJson(CREDENTIALS_FILE, credentials);
  atomicWriteJson(CONFIG_FILE, config);

  return { credentialsFile: CREDENTIALS_FILE, configFile: CONFIG_FILE };
}

/**
 * 把 zai 的 apiKey(JWT) 写到 config.json 各 zai provider 槽位，并禁用其它 provider。
 */
function updateConfigProviders(config, provider, apiKey) {
  for (const id of provider.providerIds) {
    if (!config.provider[id] || typeof config.provider[id] !== 'object') {
      config.provider[id] = { enabled: true, options: {} };
    }
    if (!config.provider[id].options || typeof config.provider[id].options !== 'object') {
      config.provider[id].options = {};
    }
    config.provider[id].enabled = true;
    config.provider[id].options.apiKey = apiKey;
  }
}

// ===== 工具函数 =====

/** 归一化 oauthBrowser 返回的 user 对象为标准 userInfo */
function normalizeUserInfo(user) {
  const u = user || {};
  return {
    email: u.email || u.mail || '',
    name: u.name || u.username || u.nickName || u.displayName || '',
    avatar: u.avatar || u.avatarUrl || u.picture || '',
    user_id: u.user_id || u.userId || u.id || u.customerNumber || u.sub || '',
  };
}

function resolveOauthBackupDir() {
  if (process.env.ZCAS_DATA_DIR) return path.join(process.env.ZCAS_DATA_DIR, '.last');
  try {
    const { app } = require('electron');
    if (app && app.isPackaged) return path.join(app.getPath('userData'), '.last');
  } catch (_) {}
  return path.join(__dirname, '..', '.last');
}

function backupCurrentLoginState(reason = 'backup') {
  const dir = path.join(resolveOauthBackupDir(), reason + '-' + timestamp());
  fs.mkdirSync(dir, { recursive: true });
  if (fs.existsSync(CREDENTIALS_FILE)) fs.copyFileSync(CREDENTIALS_FILE, path.join(dir, 'credentials.json'));
  if (fs.existsSync(CONFIG_FILE)) fs.copyFileSync(CONFIG_FILE, path.join(dir, 'config.json'));
  return dir;
}

function readJsonIfExists(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (e) {
    throw new Error('读取 JSON 失败 ' + filePath + ': ' + e.message);
  }
}

function atomicWriteJson(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = filePath + '.zcas.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, filePath);
}

function timestamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

module.exports = {
  PROVIDER,
  finishLogin,
  writeOAuthCredentials,
  updateConfigProviders,
  normalizeUserInfo,
};
