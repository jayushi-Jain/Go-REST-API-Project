package auth

import (
	"encoding/json"
	"net/http"

	"github.com/go-playground/validator/v10"
)

type Handler struct {
	service   *Service
	validator *validator.Validate
}

func NewHandler(service *Service) *Handler {
	return &Handler{
		service:   service,
		validator: validator.New(),
	}
}

func (h *Handler) respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (h *Handler) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.validator.Struct(req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	response, err := h.service.Register(req)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, response)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.validator.Struct(req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	response, err := h.service.Login(req)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, response)
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.validator.Struct(req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	response, err := h.service.RefreshToken(req)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, response)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	// In a production app, you'd invalidate the token in Redis/cache
	// For now, we'll just return success and let the client handle it
	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
}
