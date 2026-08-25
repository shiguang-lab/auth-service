package localidentity

import (
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/shiguanglab/auth-service/internal/platformroleadmin"
)

func TestScopedRoleReplacementPreservesOtherProductsAndGlobalRoles(t *testing.T) {
	current := []string{
		platformroleadmin.IAMManagerRole,
		platformroleadmin.HuiguangUserRole,
		platformroleadmin.YingguangUserRole,
		platformroleadmin.PointsAuditorRole,
	}
	points := replaceScopedRoles(current, []string{platformroleadmin.PointsAdminRole}, platformroleadmin.ManageableRoles)
	wantPoints := []string{
		platformroleadmin.HuiguangUserRole,
		platformroleadmin.IAMManagerRole,
		platformroleadmin.PointsAdminRole,
		platformroleadmin.YingguangUserRole,
	}
	slices.Sort(wantPoints)
	if !slices.Equal(points, wantPoints) {
		t.Fatalf("points replacement = %#v, want %#v", points, wantPoints)
	}

	products := replaceScopedRoles(current, []string{platformroleadmin.LingguangDevRole}, platformroleadmin.ProductManageableRoles)
	wantProducts := []string{platformroleadmin.IAMManagerRole, platformroleadmin.LingguangDevRole}
	slices.Sort(wantProducts)
	if !slices.Equal(products, wantProducts) {
		t.Fatalf("product replacement = %#v, want %#v", products, wantProducts)
	}
}

func TestSafeReturnToAcceptsOnlyLocalPathsAndConfiguredOrigin(t *testing.T) {
	service := &Service{cfg: Config{Origin: "http://127.0.0.1:18080"}}
	tests := []struct {
		input string
		want  string
	}{
		{"", "/"},
		{"/applications?status=active", "/applications?status=active"},
		{"http://127.0.0.1:18080/applications", "http://127.0.0.1:18080/applications"},
		{"//attacker.example/path", "/"},
		{"https://attacker.example/path", "/"},
		{"http://user@127.0.0.1:18080/path", "/"},
	}
	for _, test := range tests {
		if got := service.safeReturnTo(test.input); got != test.want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestLoginPageRendersSafeLocalFixtureEntry(t *testing.T) {
	service := &Service{cfg: Config{Origin: "http://127.0.0.1:18080"}}
	request := httptest.NewRequest("GET", "/login?return_to=%2Fpoints%3Ftab%3Dledger%26next%3D%3Cscript%3E", nil)
	response := httptest.NewRecorder()

	service.LoginPage(response, request)
	body := response.Body.String()

	for _, want := range []string{
		"拾光统一登录",
		"积分系统",
		"LOCAL · 无密钥验收",
		`<label for="userId">登录身份`,
		`aria-live="polite"`,
		"正在建立本地会话",
		"login_failed",
		"local-ordinary",
		"local-owner",
		"local-other-owner",
		"local-auditor",
		"local-points-admin",
		"local-iam-admin",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered login page missing %q", want)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;") || !strings.Contains(body, "&amp;next") {
		t.Fatal("return target was not HTML-escaped in the rendered page")
	}
	if strings.Contains(body, "<script>") && strings.Contains(body, "<script>alert") {
		t.Fatal("return target became executable markup")
	}
	if strings.Contains(body, `name="userId" type="text"`) || strings.Contains(body, "IdentityToken") || strings.Contains(body, "client_secret") {
		t.Fatal("login page exposed an arbitrary identity input or credential field")
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestLoginPageRejectsExternalReturnTargetBeforeRendering(t *testing.T) {
	service := &Service{cfg: Config{Origin: "http://127.0.0.1:18080"}}
	request := httptest.NewRequest("GET", "/login?return_to=https%3A%2F%2Fattacker.example%2Fsteal", nil)
	response := httptest.NewRecorder()

	service.LoginPage(response, request)
	body := response.Body.String()
	if !strings.Contains(body, "<code>/</code>") {
		t.Fatal("external return target was not reduced to the local root")
	}
	if strings.Contains(body, "attacker.example") {
		t.Fatal("external return target leaked into the rendered page")
	}
}
