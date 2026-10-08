package oauth

import (
	"html/template"
	"net/http"
)

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

func (h *Handler) renderError(response http.ResponseWriter, status int, message string) {
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.WriteHeader(status)
	if err := errorTemplate.Execute(response, map[string]string{"Message": message}); err != nil {
		h.logger.Error("render oauth error page", "error", err)
	}
}
