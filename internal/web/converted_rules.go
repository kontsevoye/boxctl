package web

import (
	"net/http"

	"github.com/kontsevoye/boxctl/internal/ruleconvert"
)

func (s *Server) handleConvertedRules(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.services.ConvertedRules == nil {
		writeData(w, http.StatusOK, []ruleconvert.Status{})
		return
	}
	status, err := s.services.ConvertedRules.ConvertedRules(r.Context())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeData(w, http.StatusOK, status)
}
