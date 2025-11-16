package main

import (
	"fmt"
	"log"
	"net/http"
	"tfe_ssl_proxy/config"
	"tfe_ssl_proxy/keykeeper"
	"tfe_ssl_proxy/server"
)

func main() {
	// Load default configuration
	cfg := config.DefaultConfig()

	// Create key keeper
	keeper, err := keykeeper.NewKeyKeeper(cfg.KeyKeeper)
	if err != nil {
		log.Fatalf("Failed to create key keeper: %v", err)
	}

	// Create server
	srv := server.NewServer(keeper)

	// Start HTTP server
	fmt.Printf("Starting TFE SSL Proxy server on :8080\n")
	log.Fatal(http.ListenAndServe(":8080", srv))
}
