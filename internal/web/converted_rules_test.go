package web

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/kontsevoye/boxctl/internal/ruleconvert"
)

type testConvertedRules struct{}

func (testConvertedRules) ConvertedRules(context.Context) ([]ruleconvert.Status, error) {
	return []ruleconvert.Status{{ID: "fixture", Name: "source-rules", Format: "binary", Target: "sing-box", LastError: "upstream HTTP 503"}}, nil
}
func TestConvertedRulesRequireAuthentication(t *testing.T) {
	handler := newTestHandler(t, Services{Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}, ConvertedRules: testConvertedRules{}})
	response := perform(handler, http.MethodGet, "/api/v1/converted-rules", "", nil, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatal(response.Code)
	}
	cookie, _ := login(t, handler)
	response = perform(handler, http.MethodGet, "/api/v1/converted-rules", "", cookie, "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "upstream HTTP 503") {
		t.Fatalf("%d %s", response.Code, response.Body.String())
	}
	for _, sensitive := range []string{"sourceURL", "headers", "proxyURL", "secret"} {
		if strings.Contains(response.Body.String(), sensitive) {
			t.Fatalf("leaked %s", sensitive)
		}
	}
}
