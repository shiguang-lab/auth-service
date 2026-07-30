# 飞书登录与注册接入

飞书作为 ZITADEL 的组织级 Generic OAuth Provider 接入，沿用拾光现有的
共享会话、账号注册和外部身份绑定机制。

```text
登录/注册页
  -> auth-service 创建一次性事务
  -> ZITADEL IDP Intent
  -> auth-service 飞书 OAuth 兼容端点
  -> 飞书授权
  -> ZITADEL 取回稳定 open_id
  -> 已绑定: 直接创建拾光会话
     未绑定: 进入 /register 补全账号 -> 创建 ZITADEL 用户和 IDP Link -> 创建拾光会话
```

兼容端点的原因:飞书当前 token 接口要求 JSON 请求，用户信息返回为
`{code,data}`;ZITADEL Generic OAuth 使用标准表单换 token，并只从用户信息
顶层读取 ID。Auth Service 只做协议形状转换，不保存飞书 token 或 App Secret，
并使用非敏感的 `FEISHU_APP_ID` 拒绝其他应用借用适配端点。

## 1. 飞书开放平台配置

在飞书开放平台进入对应应用:

1. 在 **开发配置 > 安全设置 > 重定向 URL** 添加:

   ```text
   https://sso.shiguanglab.com/idps/callback
   ```

2. 启用网页应用登录能力。
3. 配置应用可用范围，确保目标测试用户可以使用应用。
4. 发布一个可用版本。未发布或用户不在可用范围时，飞书会拒绝授权。

登录本身不申请通讯录权限。用户资料接口无需额外 scope;邮箱可能因飞书
租户资料或权限策略而缺失，首次注册页会要求用户填写拾光账号邮箱。

## 2. 保存凭据

在部署机的 auth-service 源码目录执行:

```bash
cp deploy/feishu-oauth.env.example deploy/feishu-oauth.env
chmod 600 deploy/feishu-oauth.env
```

填写 `FEISHU_APP_ID` 和 `FEISHU_APP_SECRET`。该文件已被 `.gitignore` 忽略，
不得放进 `auth.env.example`、`oidc-providers.env` 或任何提交记录。

## 3. 创建 ZITADEL Provider

NAS 默认路径已内置在脚本中:

```bash
./deploy/bootstrap-feishu-idp.sh
```

脚本会:

1. 建立短时 ZITADEL 管理会话;
2. 创建 Feishu Generic OAuth Provider;
3. 使用 Confidential Client 的 App Secret 交换授权码，允许注册与账号绑定，
   但关闭 ZITADEL 自动建号;
4. 将 Provider 加入组织登录策略;
5. 把非秘密的 Provider ID 和 App ID 写入 `deploy/feishu-provider.env`。

Provider 已存在时脚本直接退出。App Secret 轮换或端点配置更新后执行:

```bash
FORCE_BOOTSTRAP=1 ./deploy/bootstrap-feishu-idp.sh
```

这会更新同一个 Provider，不会创建新的身份命名空间，也不会破坏已有绑定。

飞书开放平台创建的自建应用属于 Confidential Client。该 Provider 不启用
ZITADEL Generic OAuth PKCE，因为飞书 v3 会拒绝 ZITADEL 生成且经验证匹配的
verifier;授权码交换仍由 App Secret、一次性 code、state 和精确 redirect URI
共同保护。

非 NAS 环境可覆盖 `ZITADEL_ENV_FILE`、`ZITADEL_LOGIN_PAT_FILE`、
`ZITADEL_API_URL`、`ZITADEL_PUBLIC_HOST` 和 `SHIGUANG_PUBLIC_ORIGIN`。

## 4. 生效与验收

重新创建 auth-service，使 Compose 读取生成的 `FEISHU_IDP_ID`:

```bash
docker compose -f deploy/docker-compose.nas.yml up -d --build auth-service
```

至少完成以下验收:

- 新飞书用户从 `/register` 选择飞书，授权后进入账号补全页，提交后立即登录;
- 同一用户退出后从 `/login` 选择飞书，不再进入注册页，直接回到 `return_to`;
- 拒绝飞书授权时返回登录失败页，不创建拾光会话;
- 非法或过期 state、无效 user access token 均不能创建会话;
- `/api/auth/session` 返回 ZITADEL 的规范账号资料和 `amr=federated`;
- App Secret 不出现在容器环境、日志、git diff 或 Provider 配置文件中。

## 5. 常见问题

- `unsupported_provider`:auth-service 尚未读取 `FEISHU_IDP_ID`;检查
  `deploy/feishu-provider.env` 后重启容器。
- 飞书提示 redirect URL 不合法:必须配置 ZITADEL 回调
  `https://sso.shiguanglab.com/idps/callback`，不是拾光的 OIDC callback。
- 飞书返回应用不可用:检查应用发布状态和用户可用范围。
- 授权后进入注册页但邮箱为空:这是允许的;飞书未返回可用邮箱时由用户填写。
- 已注册用户仍进入注册页:检查 ZITADEL 用户的 IDP Link 是否指向当前
  `FEISHU_IDP_ID`;不要删除并重建 Provider。
