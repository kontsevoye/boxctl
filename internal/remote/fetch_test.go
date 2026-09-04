package remote

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchFallsBackToRemnawaveMihomoPath(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/sub/token-value":
			http.Error(response, "generic subscription", http.StatusUnsupportedMediaType)
		case "/mihomo/token-value":
			if request.Header.Get("X-Hwid") != "device-id" {
				t.Errorf("missing HWID header")
			}
			response.Header().Set("Profile-Update-Interval", "24")
			response.Header().Set("ETag", `"revision"`)
			_, _ = response.Write([]byte("mode: rule\nproxies: []\n"))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	fetcher := Fetcher{
		Client: server.Client(),
		Validator: ValidatorFunc(func(_ context.Context, content []byte) error {
			if !strings.Contains(string(content), "proxies:") {
				return errors.New("not Mihomo YAML")
			}
			return nil
		}),
	}
	result, err := fetcher.Fetch(context.Background(), Request{
		URL: server.URL + "/sub/token-value", RemnawaveFallback: true, Headers: map[string]string{"x-hwid": "device-id"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.UsedFallback || result.SuggestedUpdate != 24*time.Hour || result.Fingerprint == "" {
		t.Fatalf("unexpected result %#v", result)
	}
}

func TestFetchUsesFallbackAfterValidationFailure(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/sub/") {
			_, _ = response.Write([]byte("generic-base64"))
			return
		}
		_, _ = response.Write([]byte("mode: rule\n"))
	}))
	defer server.Close()
	fetcher := Fetcher{Client: server.Client(), Validator: ValidatorFunc(func(_ context.Context, content []byte) error {
		if !strings.Contains(string(content), "mode:") {
			return errors.New("wrong format")
		}
		return nil
	})}
	result, err := fetcher.Fetch(context.Background(), Request{URL: server.URL + "/sub/token", RemnawaveFallback: true})
	if err != nil || !result.UsedFallback {
		t.Fatalf("fallback result=%#v err=%v", result, err)
	}
}

func TestFetchRejectsUnsafeURLAndHeaders(t *testing.T) {
	t.Parallel()
	fetcher := Fetcher{Validator: ValidatorFunc(func(context.Context, []byte) error { return nil })}
	if _, err := fetcher.Fetch(context.Background(), Request{URL: "http://example.com/sub/token"}); err == nil {
		t.Fatal("HTTP URL was accepted")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write([]byte("mode: rule"))
	}))
	defer server.Close()
	fetcher.Client = server.Client()
	if _, err := fetcher.Fetch(context.Background(), Request{URL: server.URL, Headers: map[string]string{"Authorization": "secret"}}); err == nil {
		t.Fatal("unsafe header was accepted")
	}
}

func TestFetchReturnsSafeMetadataOnNotModified(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("ETag", `"new-validator"`)
		response.Header().Set("Last-Modified", "Wed, 26 Aug 2026 08:00:00 GMT")
		response.Header().Set("Profile-Update-Interval", "12")
		response.Header().Set("Subscription-Userinfo", "download=25; total=100")
		response.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	fetcher := Fetcher{Client: server.Client(), Validator: ValidatorFunc(func(context.Context, []byte) error { return nil })}
	result, err := fetcher.Fetch(context.Background(), Request{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !result.NotModified || result.ETag != `"new-validator"` || result.LastModified == "" || result.SuggestedUpdate != 12*time.Hour || result.SubscriptionInfo == "" {
		t.Fatalf("result = %+v", result)
	}
}
