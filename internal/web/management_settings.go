package web

import (
	"context"
	"net/http"
	"strings"
)

type ManagementConfig struct {
	PublicOrigin   string `json:"publicOrigin"`
	AllowedHosts   string `json:"allowedHosts"`
	TLSCertificate string `json:"tlsCertificate"`
	TLSKey         string `json:"tlsKey"`
}

type ManagementSettings struct {
	ManagementConfig
	Supported       bool   `json:"supported"`
	Revision        string `json:"revision"`
	PendingChanges  bool   `json:"pendingChanges"`
	RestartRequired bool   `json:"restartRequired"`
}

type ManagementSettingsUpdate struct {
	ManagementConfig
	Revision string `json:"revision"`
}

type ManagementSettingsService interface {
	ManagementSettings(context.Context) (ManagementSettings, error)
	UpdateManagementSettings(context.Context, ManagementSettingsUpdate) (ManagementSettings, error)
	ApplyManagementSettings(context.Context, string) error
}

// ValidateManagementAccess uses the same origin/host rules as server startup.
func ValidateManagementAccess(config ManagementConfig) error {
	if _, err := parseConfiguredPublicOrigin(config.PublicOrigin); err != nil {
		return &PublicError{Status: http.StatusBadRequest, Code: "invalid_public_origin", Message: "Public URL must contain only an HTTP(S) scheme and host, with an optional port"}
	}
	var hosts []string
	for _, host := range strings.Split(config.AllowedHosts, ",") {
		if host = strings.TrimSpace(host); host != "" {
			hosts = append(hosts, host)
		}
	}
	if _, err := normalizeAllowedHosts(hosts); err != nil {
		return &PublicError{Status: http.StatusBadRequest, Code: "invalid_allowed_hosts", Message: "Allowed hosts must be comma-separated host names without a scheme or port"}
	}
	return nil
}

func (s *Server) handleManagementSettings(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodPut) {
		return
	}
	if s.services.ManagementSettings == nil {
		if r.Method == http.MethodGet {
			writeData(w, http.StatusOK, ManagementSettings{})
		} else {
			writeUnsupported(w, r)
		}
		return
	}
	var settings ManagementSettings
	var err error
	if r.Method == http.MethodGet {
		settings, err = s.services.ManagementSettings.ManagementSettings(r.Context())
	} else {
		var update ManagementSettingsUpdate
		if !s.decodeJSON(w, r, &update) {
			return
		}
		settings, err = s.services.ManagementSettings.UpdateManagementSettings(r.Context(), update)
	}
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeData(w, http.StatusOK, settings)
}

func (s *Server) handleApplyManagementSettings(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if s.services.ManagementSettings == nil {
		writeUnsupported(w, r)
		return
	}
	var request struct {
		Revision string `json:"revision"`
	}
	if !s.decodeJSON(w, r, &request) {
		return
	}
	if err := s.services.ManagementSettings.ApplyManagementSettings(r.Context(), request.Revision); err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeData(w, http.StatusAccepted, struct {
		Restarting bool `json:"restarting"`
	}{true})
}
