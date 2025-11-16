# TFE SSL Proxy

This is a Go implementation of the SSL certificate generation functionality found in the TFE (Tango Frontend Engine) project.

## Overview

The TFE SSL Proxy simulates the certificate generation capabilities of the original C++ TFE project. It supports two modes of operation:

1. **Debug Mode**: Generates certificates locally using pre-configured CA certificates
2. **Normal Mode**: Requests certificates from a remote certificate store service (simulated in this implementation)

## Features

- Certificate generation and forging based on original certificates
- CA certificate management for trusted and untrusted certificates
- Certificate caching with configurable expiration
- JSON serialization for certificate transmission
- Support for certificate chains

## Structure

- `config/` - Configuration management
- `certutils/` - Certificate utility functions
- `keykeeper/` - Main certificate management logic
- `main.go` - Example usage

## Usage

To run the example:

```bash
go run main.go
```

This will demonstrate:
1. Creating a key keeper with default configuration
2. Generating a forged certificate
3. Converting the certificate to JSON format
4. Using the cache to retrieve the same certificate

## Configuration

The key keeper can be configured with various options:

- `mode`: "debug" or "normal"
- `trusted_ca_path`: Path to trusted CA certificate
- `untrusted_ca_path`: Path to untrusted CA certificate
- `cert_store_host`: Remote certificate store host (for normal mode)
- `cert_store_port`: Remote certificate store port (for normal mode)
- `no_cache`: Disable certificate caching
- `hash_expire_seconds`: Cache expiration time
- `hash_slot_size`: Cache slot size
- `cert_expire_time`: Certificate validity period (in hours)
- `enable_health_check`: Enable health checks for remote certificate store

## Implementation Details

### Certificate Generation

The system can generate certificates in two ways:

1. **Local Generation (Debug Mode)**:
   - Uses pre-configured CA certificates
   - Generates new certificates based on original certificates but signed by the CA
   - Useful for testing and development

2. **Remote Request (Normal Mode)**:
   - Simulates requesting certificates from a remote certificate store
   - In a real implementation, this would make HTTP requests to a certificate generation service

### Caching

Certificates are cached to improve performance:
- Cache key is based on domain name and validity status
- Configurable expiration time
- Thread-safe cache access

### JSON Serialization

Certificates are serialized to JSON for transmission:
- Includes certificate, private key, and certificate chain
- Compatible with the original TFE JSON format