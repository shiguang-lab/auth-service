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
<title>授权确认</title>
<style>
:root { color-scheme: light dark; }
body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
       font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", sans-serif;
       background: #f5f6f8; color: #1f2329; }
.card { width: min(420px, calc(100vw - 32px)); background: #fff; border-radius: 12px; padding: 28px 24px;
        box-shadow: 0 6px 24px rgba(15, 23, 42, .08); }
h1 { font-size: 18px; margin: 0 0 6px; }
p.lead { margin: 0 0 18px; color: #646a73; font-size: 13px; }
ul { list-style: none; margin: 0 0 22px; padding: 0; }
li { display: flex; gap: 10px; padding: 10px 0; border-bottom: 1px solid #f0f1f3; font-size: 14px; }
li:last-child { border-bottom: none; }
code { font-size: 12px; color: #8f959e; }
.actions { display: flex; gap: 12px; }
button { flex: 1; padding: 10px 16px; border-radius: 8px; font-size: 14px; cursor: pointer; border: 1px solid transparent; }
button.primary { background: #1f6feb; color: #fff; }
button.ghost { background: #fff; color: #1f2329; border-color: #dee0e3; }
@media (prefers-color-scheme: dark) {
  body { background: #17181a; color: #e8eaed; }
  .card { background: #212326; box-shadow: none; }
  p.lead, code { color: #9aa0a6; }
  li { border-color: #2f3236; }
  button.ghost { background: #212326; color: #e8eaed; border-color: #3a3d42; }
}
</style>
</head>
<body>
<main class="card">
  <h1>{{ .ClientName }} 请求访问你的账号</h1>
  <p class="lead">该应用将获得以下权限：</p>
  <ul>
    {{ range .Scopes }}<li><span>{{ .Description }}</span><code>{{ .Scope }}</code></li>{{ end }}
  </ul>
  <form method="post" action="/oauth/authorize">
    <input type="hidden" name="consent_id" value="{{ .PendingID }}">
    <div class="actions">
      <button class="ghost" type="submit" name="decision" value="deny">拒绝</button>
      <button class="primary" type="submit" name="decision" value="allow">授权</button>
    </div>
  </form>
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
