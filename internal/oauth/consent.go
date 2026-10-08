package oauth

import (
	"html/template"
	"net/http"
)

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>授权登录 · 拾光</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; color: #f8f8ff; background: #050714;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", sans-serif; }
.login-page { min-height: 100vh; display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }
.login-story { position: relative; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: #050611 url('/assets/auth-visual-bg-design-1.webp') 50% 50% / cover no-repeat; }
.login-story::after { content: ''; position: absolute; inset: 0; pointer-events: none;
  background: linear-gradient(90deg, rgba(4, 5, 15, .02), rgba(4, 5, 15, .1)); }
.login-brand { position: absolute; z-index: 3; top: clamp(30px, 4.2vh, 48px); left: clamp(32px, 5vw, 76px);
  display: flex; align-items: center; gap: 12px; color: #fff; text-decoration: none; }
.login-brand img { width: 40px; height: 40px; object-fit: contain; }
.login-brand span { display: grid; line-height: 1; }
.login-brand strong { font-size: 19px; font-weight: 700; letter-spacing: .08em; }
.login-brand small { margin-top: 6px; font-size: 9px; font-weight: 650; letter-spacing: .09em; color: rgba(255,255,255,.86); }
.login-story-content { position: relative; z-index: 2; width: min(66%, 570px); margin-top: -2vh; }
.login-story-eyebrow { margin: 0 0 24px; font-size: 11px; font-weight: 650; letter-spacing: .24em; color: rgba(207,213,255,.58); }
.login-story-content h2 { margin: 0; font-size: clamp(42px, 3.15vw, 62px); font-weight: 650; line-height: 1.32; letter-spacing: .03em; }
.login-story-content em { color: transparent; background: linear-gradient(105deg, #d547ff 5%, #a145ff 42%, #5b7dff 100%);
  background-clip: text; -webkit-background-clip: text; font-style: normal; }
.login-story-copy { margin: 38px 0 0; color: rgba(235,237,250,.74); font-size: clamp(14px, 1vw, 17px); line-height: 2; }
.login-values { display: flex; gap: 26px; margin-top: 42px; color: rgba(230,232,249,.68); font-size: 13px; }
.login-values span + span { border-left: 1px solid rgba(255,255,255,.16); padding-left: 26px; }
.login-account { position: relative; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  padding: 88px clamp(34px, 5.5vw, 92px) 64px;
  background: radial-gradient(circle at 30% 50%, rgba(58,46,141,.12), transparent 48%), #070a18; }
.login-account::before { content: ''; position: absolute; inset: 0 auto 0 0; width: 1px;
  background: linear-gradient(180deg, transparent, rgba(139,109,255,.12) 18%, rgba(139,109,255,.2) 50%, rgba(139,109,255,.12) 82%, transparent); }
.login-panel { width: min(100%, 500px); }
.login-heading { margin-bottom: 28px; text-align: center; }
.login-kicker { display: block; margin-bottom: 12px; color: rgba(157,125,255,.68); font-size: 10px; font-weight: 700; letter-spacing: .2em; }
h1 { margin: 0; font-size: clamp(28px, 2vw, 36px); line-height: 1.25; font-weight: 650; letter-spacing: .02em; }
.login-heading p { margin: 13px 0 0; color: rgba(224,226,241,.55); font-size: 14px; line-height: 1.7; }
.account { display: flex; align-items: center; gap: 12px; padding: 16px; border: 1px solid rgba(255,255,255,.1); border-radius: 10px;
  background: rgba(255,255,255,.035); overflow-wrap: anywhere; }
.account-icon { display: grid; place-items: center; width: 40px; height: 40px; flex: none; border-radius: 50%; color: #c69bff; background: rgba(155,108,255,.13); }
.account-icon svg { width: 23px; height: 23px; fill: none; stroke: currentColor; stroke-width: 1.5; }
.account small { display: block; margin-bottom: 5px; color: rgba(224,226,241,.5); font-size: 12px; }
.account strong { font-size: 14px; font-weight: 550; }
.permissions-title { margin: 26px 0 12px; color: rgba(248,248,255,.9); font-size: 14px; font-weight: 500; overflow-wrap: anywhere; }
ul { display: grid; gap: 10px; margin: 0; padding: 0; list-style: none; }
li { display: flex; align-items: flex-start; gap: 12px; padding: 12px 14px; border: 1px solid rgba(255,255,255,.08); border-radius: 10px;
  background: rgba(255,255,255,.035); color: rgba(248,248,255,.8); font-size: 13px; line-height: 1.6; }
li > span:first-child { color: #76dcae; }
.actions { display: grid; grid-template-columns: 1fr 1.35fr; gap: 12px; margin-top: 28px; }
button { min-height: 54px; padding: 12px 16px; border: 1px solid rgba(255,255,255,.13); border-radius: 8px;
  color: #ececff; background: rgba(255,255,255,.045); font: inherit; font-size: 15px; font-weight: 600; cursor: pointer; }
button.primary { border: 0; color: #fff; background: linear-gradient(100deg, #a72bff 0%, #804cff 48%, #5f7cff 100%);
  box-shadow: 0 14px 38px rgba(111,55,255,.18); }
button:hover { filter: brightness(1.12); }
button:focus-visible, a:focus-visible { outline: 2px solid #c69bff; outline-offset: 4px; }
.trust { margin: 22px 0 0; color: rgba(224,226,241,.44); font-size: 12px; line-height: 1.8; text-align: center; }
@media (max-width: 1120px) { .login-story-content { width: 72%; } .login-account { padding-left: 46px; padding-right: 46px; } .login-values { gap: 18px; } .login-values span + span { padding-left: 18px; } }
@media (max-width: 820px) {
  .login-page { display: block; min-height: 100dvh; position: relative; }
  .login-story { position: absolute; inset: 0; min-height: 100%; }
  .login-story::after { background: rgba(5,7,18,.82); backdrop-filter: blur(3px); }
  .login-story-content { display: none; }
  .login-brand { top: 24px; left: 24px; }
  .login-account { z-index: 2; min-height: 100dvh; padding: 108px 24px 52px; background: transparent; }
  .login-account::before { display: none; }
  .login-panel { padding: 30px; border: 1px solid rgba(255,255,255,.11); border-radius: 14px; background: rgba(8,10,25,.82);
    box-shadow: 0 30px 80px rgba(0,0,0,.38); backdrop-filter: blur(18px); }
}
@media (max-width: 480px) { .login-account { padding-left: 16px; padding-right: 16px; } .login-panel { padding: 24px 20px; } }
</style>
</head>
<body>
<main class="login-page">
  <section class="login-story" aria-label="拾光品牌介绍">
    <a class="login-brand" href="/" aria-label="返回拾光首页"><img src="/assets/微信图片_20260722101545_795_4.svg" alt=""><span><strong>拾光</strong><small>SHIGUANG</small></span></a>
    <div class="login-story-content">
      <p class="login-story-eyebrow">SHIGUANG CONNECT</p>
      <h2>一次授权<br><em>连接你的创作空间。</em></h2>
      <p class="login-story-copy">使用拾光统一账号，连接你信任的应用。<br>账号和密码始终只在拾光登录页中使用。</p>
      <div class="login-values"><span>安全可靠</span><span>统一账号</span><span>由你掌控</span></div>
    </div>
  </section>
  <section class="login-account" aria-labelledby="consent-title">
    <div class="login-panel">
      <header class="login-heading">
        <span class="login-kicker">SHIGUANG ACCOUNT</span>
        <h1 id="consent-title">授权登录</h1>
        <p>允许 <strong>{{ .ClientName }}</strong> 使用你的拾光账号？</p>
      </header>
      <div class="account">
        <span class="account-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="3.25"/><path d="M5.75 19c.55-3.3 2.64-5 6.25-5s5.7 1.7 6.25 5"/></svg></span>
        <div><small>当前拾光账号</small><strong>{{ if .DisplayName }}{{ .DisplayName }}{{ else }}已登录拾光账号{{ end }}</strong></div>
      </div>
      <h2 class="permissions-title">允许后，{{ .ClientName }} 可以：</h2>
      <ul aria-label="应用请求的权限">
        {{ range .Scopes }}<li><span aria-hidden="true">✓</span><span>{{ .Description }}</span></li>{{ end }}
      </ul>
      <form method="post" action="/oauth/authorize">
        <input type="hidden" name="consent_id" value="{{ .PendingID }}">
        <div class="actions">
          <button type="submit" name="decision" value="deny">取消</button>
          <button class="primary" type="submit" name="decision" value="allow">允许并继续</button>
        </div>
      </form>
      <p class="trust">仅在你允许后连接应用。<br>请确认这是你刚刚发起的登录请求。</p>
    </div>
  </section>
</main>
</body>
</html>
`))

var errorTemplate = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>请求无法完成</title>
<style>
:root { color-scheme: light dark; }
body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
       font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", sans-serif;
       background: #f5f6f8; color: #1f2329; }
.card { width: min(420px, calc(100vw - 32px)); background: #fff; border-radius: 12px; padding: 28px 24px;
        box-shadow: 0 6px 24px rgba(15, 23, 42, .08); }
h1 { font-size: 18px; margin: 0 0 8px; }
p { margin: 0; color: #646a73; font-size: 14px; line-height: 1.6; }
@media (prefers-color-scheme: dark) {
  body { background: #17181a; color: #e8eaed; }
  .card { background: #212326; box-shadow: none; }
  p { color: #9aa0a6; }
}
</style>
</head>
<body>
<main class="card">
  <h1>请求无法完成</h1>
  <p>{{ .Message }}</p>
</main>
</body>
</html>
`))

func (h *Handler) renderConsent(response http.ResponseWriter, prompt *ConsentPrompt) {
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.WriteHeader(http.StatusOK)
	if err := consentTemplate.Execute(response, prompt); err != nil {
		h.logger.Error("render consent page", "error", err)
	}
}

func (h *Handler) renderError(response http.ResponseWriter, status int, message string) {
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.WriteHeader(status)
	if err := errorTemplate.Execute(response, map[string]string{"Message": message}); err != nil {
		h.logger.Error("render oauth error page", "error", err)
	}
}
