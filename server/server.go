package server

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"tfe_ssl_proxy/keykeeper"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type Server struct {
	keyKeeper *keykeeper.KeyKeeper
	router    *chi.Mux
}

func NewServer(kk *keykeeper.KeyKeeper) *Server {
	s := &Server{
		keyKeeper: kk,
		router:    chi.NewRouter(),
	}

	s.routes()
	return s
}

func (s *Server) routes() {
	s.router.Get("/stats", s.handleStats)
	s.router.Post("/ca", s.handleCertRequest)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := s.keyKeeper.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleCertRequest(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	keyringID := r.URL.Query().Get("keyring_id")
	sni := r.URL.Query().Get("sni")
	isValidStr := r.URL.Query().Get("is_valid")

	// Validate keyring_id
	_, err := uuid.Parse(keyringID)
	if err != nil {
		http.Error(w, "Invalid keyring_id", http.StatusBadRequest)
		return
	}

	// Parse is_valid parameter
	isValid := isValidStr == "1"

	// For demo purposes, we'll create a sample certificate
	sampleCert := createSampleCertificate()

	// Get keyring from keykeeper
	keyRing, err := s.keyKeeper.GetKeyRing(sni, keyringID, isValid, sampleCert)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get keyring: %v", err), http.StatusInternalServerError)
		return
	}

	// Convert to JSON
	jsonBytes, err := keykeeper.KeyRingToJSON(keyRing)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to serialize keyring: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)
}

// createSampleCertificate creates a sample certificate for demonstration
func createSampleCertificate() *x509.Certificate {
	// In a real implementation, this would be the actual certificate from the client
	// For demo purposes, we'll create a simple certificate
	cert := &x509.Certificate{
		Subject: x509.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com", "www.example.com"},
	}
	return cert
}
