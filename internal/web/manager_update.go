package web

import (
	"net/http"
	"strconv"
)

func (s *Server) handleManagerUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	if s.services.ManagerUpdates == nil {
		writeUnsupported(w, r)
		return
	}
	if r.Method == http.MethodGet {
		check := false
		if value := r.URL.Query().Get("checkUpdates"); value != "" {
			var err error
			check, err = strconv.ParseBool(value)
			if err != nil {
				writeAPIError(w, r, http.StatusBadRequest, "invalid_query", "checkUpdates must be true or false")
				return
			}
		}
		status, err := s.services.ManagerUpdates.UpdateStatus(r.Context(), check)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, status)
		return
	}
	var request struct {
		AllowFullRestart bool `json:"allowFullRestart"`
	}
	if !s.decodeJSON(w, r, &request) {
		return
	}
	job, err := s.services.ManagerUpdates.StartUpdate(r.Context(), request.AllowFullRestart)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeData(w, http.StatusAccepted, job)
}
