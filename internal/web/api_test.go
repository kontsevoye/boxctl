package web

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProfileAndSubscriptionZeroTimestampsAreOmitted(t *testing.T) {
	for name, value := range map[string]any{
		"profile":      Profile{},
		"subscription": ProxySubscription{},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"updatedAt", "lastCheckedAt", "nextUpdateAt", "expiresAt"} {
				if strings.Contains(string(encoded), `"`+field+`"`) {
					t.Fatalf("zero timestamp %q leaked into %s", field, encoded)
				}
			}
		})
	}
}
