# Cloudflare KV 管理页

这是一个单文件的 Cloudflare Workers / Pages 管理页，用于管理一个内部 Cloudflare 账号的 KV：登录后列出命名空间、按前缀浏览键，并新建、读取、修改或删除 UTF-8 文本值。

实现入口是 [`_worker.js`](./_worker.js)，不是 `_workers.js`。对于 Cloudflare Pages，它是 Advanced Mode 的约定入口；对于 Workers，将此文件配置为模块入口即可。

## 安全模型

本实现面向“自己或团队管理固定账号”的内部工具，不会收集 Cloudflare 的账号密码，也不会把 Cloudflare API Token 交给浏览器。Worker 仅以部署环境中的固定、账号级 API Token 调用 Cloudflare API；网页登录使用独立的管理密码，并签发 8 小时、`HttpOnly`、`SameSite=Strict`、`Secure` 的加密会话 Cookie。Worker 会将 HTTP 的页面访问重定向至 HTTPS，并拒绝 HTTP 写请求；仍应在 Cloudflare 中启用 Always Use HTTPS。

所有已登录用户都拥有该 Token 的 KV 权限。因此生产环境应同时用 Cloudflare Access 限制站点访问，并限制 Pages 预览域名。此代码不把未经验证的 Access 请求头当作身份凭据；若要把 Access 作为唯一认证机制，须按 Cloudflare 要求校验 Access JWT 的签名、`aud` 和 `iss`。若需要让任意 Cloudflare 用户授权后管理各自账号，应改用 Cloudflare OAuth 授权码流程，不能复用这个固定 Token 方案。

必须在 Cloudflare WAF 为精确路径 `POST /api/session` 配置按 IP 的限速/阶梯 Challenge 或封禁。此单文件实现没有持久化登录失败计数，不能自行防御无限在线猜测。退出登录仅清除当前浏览器 Cookie；如果密码或 Cookie 泄露，轮换 `SESSION_SECRET` 可立即使全部既有会话失效。

## 部署前配置

在 Cloudflare 创建一个仅限目标账号的 API Token，权限至少为 **Workers KV Storage Write**（只浏览时可用 Read）。把以下值配置为 Workers/Pages 的加密 Secret，绝不写入仓库、前端代码或日志：

| Secret | 用途 |
| --- | --- |
| `CF_ACCOUNT_ID` | 目标 Cloudflare 账号 ID（32 位十六进制） |
| `CF_API_TOKEN` | 上述最小权限 Account API Token |
| `ADMIN_PASSWORD` | 管理页登录密码，至少 12 个字符 |
| `SESSION_SECRET` | 用密码管理器生成的至少 32 个随机字符，用于加密 Cookie 会话 |
| `ALLOWED_NAMESPACE_IDS`（可选） | 逗号分隔的 KV namespace ID 白名单；未设置时显示 Token 可访问的全部 namespace |

Pages 部署时，确保 `_worker.js` 位于实际构建输出目录的根目录。它处理 `/api/*` 和根页面；其余请求会交由 `env.ASSETS.fetch()` 返回静态资产。Workers 部署时，配置 `_worker.js` 为模块入口，并创建同名 Secrets。

## 行为与限制

- 保存前会重新读取当前 key 的 metadata 和绝对过期时间，并用 multipart 请求尽力写回，降低常规编辑意外清除它们的风险；该读-改-写过程没有原子条件写入，外部并发写入仍可能覆盖或造成旧属性被写回。未检测到内容变化时不会发起写入，避免无意义地覆盖外部更新。
- 仅支持 UTF-8 文本，单个可编辑值上限为 1 MiB；二进制或更大的值会被拒绝，避免错误重编码或耗尽页面资源。
- value 会作为 UTF-8 Blob multipart 字段上传，以保留 BOM 与 LF、CRLF、CR 的原始字节。浏览器 textarea 会统一显示为 LF：原值为单一换行风格时，编辑后会恢复该风格；原值混合换行时仅允许查看，改动后会被拒绝保存，避免静默改写。
- 新建使用独立的创建流程，先检查同名键通常不存在，再写入一个无 metadata、永不过期的 UTF-8 值；空字符串是有效值。Cloudflare KV 没有条件创建接口，因此该检查与写入之间仍存在并发覆盖窗口。创建失败时不会把现有编辑流程放宽为可自动新建。
- 修改仍仅针对读取到的已存在键，并会保留当前 metadata 和过期时间；现有键名不能直接改名。Cloudflare KV 没有原子 rename，不能安全地把“先新建再删除”伪装成改名。
- 删除要求在页面中输入完整键名确认，服务端也会校验确认值、登录会话、同源请求与（如已配置的）namespace 白名单。删除不可恢复，且 KV 没有版本条件删除：从打开键到确认删除之间若外部更新或重建同名键，删除仍可能作用于当时的值。成功后的列表刷新受 KV 最终一致性影响，可能暂时仍显示已删除键或暂时看不到新键。
- 原过期时间不足 60 秒的键会被拒绝保存，避免为了编辑值而隐式改变 TTL 或让 Cloudflare 拒绝请求。
- Cloudflare KV 为最终一致性存储，且同一 key 的并发保存仍是最后写入者生效。对重要配置应先在专用测试 namespace 验证，并建立外部审计/备份流程。

## 本地检查

项目不依赖第三方包，使用 Node 20+ 即可：

```powershell
node --test worker.test.mjs
node --check _worker.js
```

如果环境安装了 npm，也可使用 `npm test` 和 `npm run check`。

测试使用假的 API Token 和模拟 Cloudflare API，不会访问账号或改动真实 KV。真实部署后的读写验证需要在取得账号操作授权后，于专用测试 namespace 执行并恢复测试数据；至少应覆盖 metadata、TTL、BOM 与 LF/CRLF/CR/混合换行值的读取和保存。

参考：[Pages Advanced Mode](https://developers.cloudflare.com/pages/functions/advanced-mode/)、[KV API](https://developers.cloudflare.com/api/go/resources/kv/)、[Cloudflare Pages Secrets](https://developers.cloudflare.com/pages/functions/bindings/)、[Cloudflare Access JWT 校验](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)、[WAF Rate Limiting](https://developers.cloudflare.com/waf/rate-limiting-rules/)。

