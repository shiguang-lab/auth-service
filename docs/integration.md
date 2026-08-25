# 拾光统一认证接入指南

面向要接入 `*.shiguanglab.com` 统一登录体系的第一方产品。读完本文你应该能:
在网关登记产品路由、验证 `X-SG-Identity` 断言、消费个人/组织上下文、
完成本地开发与上线检查。

契约所有者:auth-service(本仓库)。网关路由策略见
[access-gateway](../../access-gateway/README.md);信任边界与整体架构见
[architecture.md](architecture.md)。参考实现:superagents
(`superagents/apps/bff/src/auth/unified-identity.service.ts`)。

---

## 1. 架构与信任链

```text
Browser ──共享 cookie `__Secure-sg_session`(域 .shiguanglab.com)──▶
  access-gateway(Caddy,公网唯一入口)
    1. 删除外部伪造的 X-SG-* / X-User-* 头
    2. forward_auth → auth-service /v1/forward-auth(校验会话与 entitlement)
    3. 剥离 Cookie / Authorization,只注入签名断言 X-SG-Identity
  ──▶ 产品服务(验断言 → 资源级授权)
```

三条铁律:

1. **产品永远收不到共享 cookie 和 ZITADEL token**,只收短时断言;
2. **断言只信网关这一跳**:产品服务不得对公网直接暴露,任何其它入口收到
   `X-SG-Identity` 一律拒绝;
3. **产品不建用户表**:`sub` 就是全库的 userId,展示名走断言 `name` claim 或
   身份查询门面(§6),审计记录只存 `sub`。

---

## 2. 接入流程总览

| 步骤 | 动作 | 责任方 |
|---|---|---|
| 1 | 确定产品域名、`product-id`、`audience`、entitlement(约定 `<product>:access`) | 产品 + 平台 |
| 2 | auth-service `DEFAULT_ENTITLEMENTS` 增加该 entitlement(或后续接精细授权) | 平台 |
| 3 | 网关 Caddyfile 新增 host 块(§3),评审合并后重建网关 | 平台 |
| 4 | 产品实现断言验证中间件(§4)并接双端点语义(§5) | 产品 |
| 5 | 本地开发联调(§7)、上线检查清单(§8) | 产品 |

---

## 3. 网关侧登记(每个产品一个 host 块)

在 access-gateway `Caddyfile` 按下面模板添加;**认证策略是显式的、按产品评审的
网关变更**,没有默认放行。

```caddyfile
@myproduct host myproduct.shiguanglab.com
handle @myproduct {
	# 公开路径(健康检查、静态资源)——仍要剥离身份头
	@myproductPublic path /health /health/* /assets/*
	handle @myproductPublic {
		route {
			request_header -X-SG-Identity
			request_header -X-SG-*
			request_header -X-User-*
			reverse_proxy {$MYPRODUCT_UPSTREAM:myproduct:8080} {
				header_up -Cookie
				header_up -Authorization
				header_down -Set-Cookie
			}
		}
	}

	# 共享会话端点:上下文切换 / 统一登出 / 组织目录(同源直通 auth-service)
	@myproductSharedAuth path /api/auth/context /api/auth/logout /api/account/*
	handle @myproductSharedAuth {
		route {
			request_header -X-SG-Identity
			request_header -X-SG-*
			request_header -X-User-*
			reverse_proxy {$AUTH_SERVICE_UPSTREAM:auth-service:8081} {
				header_up X-SG-Gateway-Token {$GATEWAY_SHARED_TOKEN}
			}
		}
	}

	# 其余全部要求登录 + entitlement
	handle {
		route {
			request_header -X-SG-Identity
			request_header -X-SG-*
			request_header -X-User-*
			forward_auth {$AUTH_SERVICE_UPSTREAM:auth-service:8081} {
				uri /v1/forward-auth
				header_up X-SG-Gateway-Token {$GATEWAY_SHARED_TOKEN}
				header_up X-SG-Product-ID myproduct
				header_up X-SG-Audience myproduct-api
				header_up X-SG-Required-Entitlements myproduct:access
				copy_headers X-SG-Identity
			}
			reverse_proxy {$MYPRODUCT_UPSTREAM:myproduct:8080} {
				header_up -Cookie
				header_up -Authorization
				header_down -Set-Cookie
			}
		}
	}
}
```

要点:

- `X-SG-Audience` 将成为断言 `aud`,产品验签时必须精确匹配;
- 路径匹配同时写裸路径与子路径(`/account /account/*`),Caddy 的
  `/account/*` 不匹配 `/account`;
- 未登录的 HTML GET 会被 302 到
  `https://shiguanglab.com/login?return_to=<原地址>`,API 请求返回 401 JSON;
- 产品上游收不到 cookie,也无法向父域种 cookie(`header_down -Set-Cookie`)。

---

## 4. 断言契约:`X-SG-Identity`

RS256 签名的 JWT,JWS 头 `typ: "sg-identity+jwt"`、`kid` 指向 JWKS 中的公钥。

**JWKS**:公网 `https://shiguanglab.com/.well-known/sg-identity-jwks.json`;
NAS 内网(推荐,免公网回环)`http://auth-service:8081/.well-known/jwks.json`
(需接入 `shiguang-auth-edge` docker 网络)。缓存 ≤5 分钟,按 `kid` 轮换。

**Claims**:

| Claim | 类型 | 语义 |
|---|---|---|
| `iss` | string | `https://shiguanglab.com`(部署配置 `IDENTITY_ISSUER`) |
| `aud` | string | 你的产品 audience(网关头决定) |
| `sub` | string | **用户唯一 id,全库直接使用**;稳定且永不复用 |
| `sid` | string | 平台会话 id(登出即失效) |
| `name` | string | 展示名,只用于显示,不落库 |
| `org_id` | string | **当前组织上下文**;为空/缺失 = 个人上下文 |
| `roles` | string[] | 平台角色 ∪ 当前组织角色(见下) |
| `entitlements` | string[] | 产品准入(如 `superagents:access`) |
| `auth_time` | number | 认证时刻(Unix 秒) |
| `amr` | string[] | `pwd` / `federated` |
| `exp`/`nbf`/`iat`/`jti` | — | 标准字段;TTL 默认 60s,最长 2m |

**验证清单(缺一不可)**:

1. JWS 头 `alg == RS256` 且 `typ == "sg-identity+jwt"`;
2. 按 `kid` 取 JWKS 公钥验签;
3. `iss` 精确匹配;`aud` 包含你的 audience;
4. `exp/nbf/iat` 校验(允许 ≤10s 时钟偏移);
5. `sub` 非空;
6. `entitlements` 包含你的产品 entitlement。

**角色语义**:

- `org:admin / org:member / org:viewer` —— 组织内角色,仅组织上下文出现;
- `system-admin`(全局系统管理员)等**平台角色**:与上下文无关,
  个人/组织断言中都存在;用于平台级资源(如内置 Agent 管理)的门禁;
- `platform:points-admin / platform:points-auditor`分别对应积分平台管理和全局只读审计;
  接入方管理员不是 IAM 全局角色,其唯一授权依据是 Points Service 中基于断言
  `(issuer, sub)` 的 ACTIVE application membership。Auth Service 只提供可信身份,
  不签发或推导应用成员关系;
- 建议映射:个人上下文 = 本人全权;组织上下文按 org:* 收敛产品内角色。

**租户建议**:用二元组做数据隔离键——
`org_id 存在 → ("org", org_id)`,否则 `("user", sub)`。同一用户的个人数据与
组织数据是两份互不可见的数据集。

---

## 5. 浏览器侧共享端点(同源,经网关)

产品前端用同源 fetch(带 cookie)调用;POST 需 `Content-Type: application/json`,
auth-service 会校验 `Origin` 必须是第一方来源(你的产品域名需在
`ALLOWED_RETURN_ORIGINS` 中)。

| 方法 | 路径 | 用途 | 成功响应(要点) |
|---|---|---|---|
| GET | `/api/auth/session` | 会话回显 | `{authenticated, subject, displayName, email, organization:{id,name}\|null, roles, platformRoles, entitlements}` |
| POST | `/api/auth/context` | 切换上下文,body `{organizationId}`(空串=个人) | `{organization, roles}`;非成员 404 |
| POST | `/api/auth/logout` | 统一登出(清共享 cookie + 吊销上游会话) | `{redirect}` |
| GET | `/api/account/orgs` | 我的组织列表 | `{organizations:[{id,name,roles}]}` |
| POST | `/api/account/orgs` | 创建组织 `{name}`(2–60 字符) | 201;重名 409 |
| GET | `/api/account/orgs/{id}/members` | 成员列表(需本组织成员) | `{members:[{userId,displayName,loginName,roles}]}` |
| POST | `/api/account/orgs/{id}/members` | 邀请 `{loginName, role}`(需 org:admin) | 201;不存在 404;已在 409 |
| PATCH | `/api/account/orgs/{id}/members/{userId}` | 改角色 `{role}`(需 org:admin) | 200;最后管理员降级 409 `last_admin` |
| DELETE | `/api/account/orgs/{id}/members/{userId}` | 移除成员(admin 或本人退出) | 204;最后管理员 409 |

注意:登录/注册页面与接口(`/login`、`/api/auth/login/*`、`/api/auth/register*`、
`/api/auth/federated/*`)只在主站 `shiguanglab.com` 提供,产品域**不要**代理它们;
产品未登录时跳 `https://shiguanglab.com/login?return_to=<回跳地址>`
(回跳地址的 origin 必须在 `ALLOWED_RETURN_ORIGINS`)。
官网产品介绍页也使用同一个入口模型：介绍和展示留在 `shiguanglab.com`，
登录成功后的工作台回到产品独立域名，例如
`https://shiguanglab.com/login?return_to=https%3A%2F%2Fpoint.shiguanglab.com%2F`。

**切换上下文后必须整页刷新**(或全量重拉数据):断言的 org_id 变了,
所有已缓存的租户数据都作废。

---

## 6. 服务间身份查询门面(署名解析 / 选人器)

产品后端持 `IDENTITY_API_TOKEN`(独立于网关 token,向平台申请)直连
auth-service(内网):

```text
POST /v1/identity/users/batch-get          Authorization: Bearer <IDENTITY_API_TOKEN>
  body: {"ids": ["<sub>", ...]}            # ≤200 个
  → {"users":[{id, loginName, displayName, email, state}]}

GET  /v1/identity/orgs/{orgId}/members     Authorization: Bearer <IDENTITY_API_TOKEN>
  → {"members":[{userId, loginName, displayName, roles}]}
```

用法约束:结果做短 TTL 缓存;解析不到的 `sub` 显示「已注销用户」;
**不要**把 displayName 写进业务表(PIPL 删除义务要求 PII 集中在 IAM 单点)。

积分系统的选人器使用独立的 `POINTS_IDENTITY_SERVICE_TOKEN`，只允许
Points BFF/服务端 secret store 持有，Points Web 和浏览器不得持有或直连：

```text
POST /v1/identity/users/search             Authorization: Bearer <POINTS_IDENTITY_SERVICE_TOKEN>
  body: {"query":"alice","limit":10}       # query trim 后 3..64 字符，limit 1..10
  -> {"users":[{id,loginName,displayName,state}]}  # 仅 ACTIVE，无 email

POST /v1/identity/users/resolve            Authorization: Bearer <POINTS_IDENTITY_SERVICE_TOKEN>
  body: {"userId":"<exact-zitadel-sub>"}
  -> {"user":{id,loginName,displayName,state}}     # 仅精确 ACTIVE；否则 404
```

新增成员必须先 search 供用户选择，再由 Points 服务端在落库前 resolve
精确复核。目录不可用返回 503 并停止写入；不得用模糊搜索结果直接创建成员。

---

## 7. 本地开发

### 7.1 固定开发身份

推荐"开发身份注入"模式(参考 superagents):本地不起网关/auth-service,
产品用与生产完全相同的验证代码路径,仅在断言缺失时注入固定身份:

- 开关 `*_DEV_IDENTITY=1`,可配 subject/展示名/模拟组织;
- **生产环境启动时若发现开关打开必须直接抛错拒绝启动**;
- 需要联调真实登录时,再本地起 auth-service(memory session)+ gateway
  (`make run`,见各仓库 README)。

### 7.2 生产账号 Local Broker

需要 localhost API 使用真实生产账号、但不把凭据或共享 cookie 交给浏览器时，
可由平台为指定产品开启 Local Broker。该能力只接受真实账号密码，不接受 subject，
并在服务端白名单中固定 product、audience、required entitlement。客户端只能选择
白名单中的 productId，Broker 创建后不能切换产品：

```text
localhost Node proxy --账号密码--> POST /api/auth/local-broker
                     <--opaque broker + 1m identity assertion--
localhost Node proxy --Broker--> POST /api/auth/local-broker/refresh
                     <--新的 audience-bound identity assertion--
localhost browser --> Node proxy --X-SG-Identity--> localhost product API
```

生产配置示例：

```dotenv
LOCAL_BROKER_ENABLED=true
LOCAL_BROKER_POLICIES=[{"productId":"asset-hub","audience":"asset-hub-api","requiredEntitlements":["asset-hub:access"]},{"productId":"opc","audience":"superagents-bff","requiredEntitlements":["superagents:access"]}]
LOCAL_BROKER_TTL=12h
DEFAULT_ENTITLEMENTS=superagents:access,asset-hub:access
```

Broker 和密码只能留在 localhost Node 进程内，不得返回浏览器、写磁盘或输出日志。
修改账号通过本地 env 后重启，不提供账号切换 UI。普通浏览器 session 不能调用
Broker refresh，Broker 也不能作为 `.shiguanglab.com` 共享 cookie 使用。

---

## 8. 上线检查清单

- [ ] 网关 host 块已评审合并,`caddy validate` 通过,公开路径最小化
- [ ] 未登录:HTML GET 302 到统一登录且 `return_to` 正确;API 401
- [ ] 断言验证六条全部实现,伪造/过期/错 aud 的断言被拒
- [ ] 产品服务不对公网暴露任何绕过网关的入口
- [ ] 个人/组织上下文切换后数据完全隔离
- [ ] 统一登出后产品会话立即失效
- [ ] `ALLOWED_RETURN_ORIGINS` 已包含产品 origin
- [ ] 无本地用户表、无密码存储、业务表用户引用只存 `sub`
- [ ] dev 身份开关在生产 fail-fast

## 9. 静态资源接入(公共媒体服务)

平台提供统一的公开静态资源服务(图片等"发布型"资源),由 MinIO +
网关只读入口组成,**没有独立的媒体服务进程**。

```text
读(公网匿名): https://static.shiguanglab.com/<product>/<path>
                → Cloudflare CDN → Seoul → 网关(仅 GET/HEAD)→ MinIO public-media
写(内网凭据): S3 PutObject → http://minio:9000(opc-infra 网络)或
                http://100.87.115.78:9000(Tailscale)
```

接入物料(向平台申请):S3 access key 一对 + 产品前缀(如 `opc/`)。
凭据按前缀限权,写不了别家目录;读是匿名的,不需要凭据。

约定与要求:

- **只放公开资源**。产品内的私有附件(带租户/ACL 语义)留在产品自己的
  资产系统,不进公共桶;
- 对象命名推荐内容寻址:`<product>/<sha256>.<ext>`,并在上传时设置
  `Cache-Control: public, max-age=31536000, immutable`(内容不变才可 immutable)
  与正确的 `Content-Type`;
- 浏览器端上传一律经产品后端中转(校验类型/大小后 PutObject),**不发
  预签名 URL**:S3 写入面只在内网,公网网关只放行 GET/HEAD;
- 人工上传:MinIO Console(Tailscale `http://100.87.115.78:9001`)或 `mc`。

```ts
// Node 示例(@aws-sdk/client-s3)
const s3 = new S3Client({
  endpoint: "http://minio:9000",
  region: "us-east-1",
  credentials: { accessKeyId, secretAccessKey },
  forcePathStyle: true,
});
await s3.send(new PutObjectCommand({
  Bucket: "public-media",
  Key: `opc/${sha256hex}.png`,
  Body: buffer,
  ContentType: "image/png",
  CacheControl: "public, max-age=31536000, immutable",
}));
// 公网 URL: https://static.shiguanglab.com/opc/<sha256hex>.png
```

## 10. 排错速查

| 现象 | 常见原因 |
|---|---|
| 网关 503 `session_store_unavailable` | auth-service/Redis 不可用(fail closed 属预期) |
| 403 `missing_entitlement` | 会话无产品 entitlement:检查 `DEFAULT_ENTITLEMENTS` 与网关 `X-SG-Required-Entitlements` |
| 403 `invalid_origin`(POST 共享端点) | 产品 origin 不在 `ALLOWED_RETURN_ORIGINS` |
| 断言验签失败 | JWKS 地址/缓存、`kid` 轮换、`typ` 不是 `sg-identity+jwt` |
| 切组织后仍看到旧数据 | 前端未整页刷新/未失效缓存 |
| 平台角色不生效 | 角色在登录时写入会话:重新登录 |
