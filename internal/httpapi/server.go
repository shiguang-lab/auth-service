package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/shiguanglab/auth-service/internal/authorize"
	"github.com/shiguanglab/auth-service/internal/identity"
)

type Server struct {
	decision     *authorize.Service
	signer       *identity.Signer
	gatewayToken [32]byte
	logger       *slog.Logger
}

func NewServer(decision *authorize.Service, signer *identity.Signer, gatewayToken string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		decision:     decision,
		signer:       signer,
		gatewayToken: sha256.Sum256([]byte(gatewayToken)),
		logger:       logger,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", writeOK)
	mux.HandleFunc("GET /health/ready", writeOK)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.Handle("POST /v1/authorize", s.authenticateGateway(http.HandlerFunc(s.handleAuthorize)))
	return mux
}

func (s *Server) handleAuthorize(response http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(response, request.Body, 64<<10)
	defer request.Body.Close()
	var input authorize.Request
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if err := ensureEOF(decoder); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	decision := s.decision.Decide(request.Context(), input)
	s.logger.Info("authorization decision",
		"request_id", input.RequestID,
		"product_id", input.ProductID,
		"allow", decision.Allow,
		"status", decision.Status,
		"reason", decision.Reason,
	)
	writeJSON(response, http.StatusOK, decision)
}

func (s *Server) handleJWKS(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(response, http.StatusOK, s.signer.JWKS())
}

func (s *Server) authenticateGateway(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		raw := request.Header.Get("Authorization")
		token, ok := strings.CutPrefix(raw, "Bearer ")
		actual := sha256.Sum256([]byte(token))
		if !ok || subtle.ConstantTimeCompare(actual[:], s.gatewayToken[:]) != 1 {
			response.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(response, request)
	})
}

func writeOK(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	if response.Header().Get("Cache-Control") == "" {
		response.Header().Set("Cache-Control", "no-store")
	}
	response.WriteHeader(status)
	json.NewEncoder(response).Encode(value)
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	if err != nil {
		return err
	}
	return nil
}
