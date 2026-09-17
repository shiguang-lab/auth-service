package oauth

import (
	"html/template"
	"net/http"
)

var deviceTemplate = template.Must(template.New("device").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>连接应用</title><style>
body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",sans-serif;background:#f5f6f8;color:#1f2329}.card{width:min(420px,calc(100vw - 32px));box-sizing:border-box;background:#fff;border-radius:14px;padding:30px 26px;box-shadow:0 8px 30px rgba(15,23,42,.09)}h1{font-size:20px;margin:0 0 8px}.lead{color:#646a73;font-size:14px;line-height:1.6}.code{font:600 24px ui-monospace,monospace;letter-spacing:.08em;margin:20px 0}.scopes{padding:0;list-style:none;color:#4e5969;font-size:13px}.scopes li{padding:7px 0}.actions{display:flex;gap:12px;margin-top:22px}button{flex:1;border-radius:8px;padding:11px;border:1px solid #d9dce1;background:#fff;cursor:pointer}.primary{background:#1f6feb;color:#fff;border-color:#1f6feb}.done{color:#16794d;font-size:15px;line-height:1.7}@media(prefers-color-scheme:dark){body{background:#17181a;color:#e8eaed}.card{background:#212326}.lead,.scopes{color:#a8adb5}button{background:#212326;color:#e8eaed;border-color:#444}}
</style></head><body><main class="card">{{if .Message}}<h1>设备连接已处理</h1><p class="done">{{.Message}}</p>{{else}}<h1>连接 {{.ClientName}}</h1><p class="lead">确认发起连接的应用中显示相同验证码。授权令牌只会交给此次请求对应的客户端。</p><div class="code">{{.UserCode}}</div><ul class="scopes">{{range .Scopes}}<li>✓ {{.Description}}</li>{{end}}</ul><form method="post" action="/oauth/device"><input type="hidden" name="user_code" value="{{.UserCode}}"><div class="actions"><button name="decision" value="deny">拒绝</button><button class="primary" name="decision" value="allow">确认连接</button></div></form>{{end}}</main></body></html>`))

func (h *Handler) renderDevice(response http.ResponseWriter, prompt DevicePrompt, message string) {
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	response.WriteHeader(http.StatusOK)
	if err := deviceTemplate.Execute(response, struct {
		DevicePrompt
		Message string
	}{prompt, message}); err != nil {
		h.logger.Error("render device page", "error", err)
	}
}
