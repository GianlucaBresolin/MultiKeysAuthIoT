# Server

This module contains the backend of the system and implements the server side of
the multi-key authentication protocol for the IoT device. 

## Responsibilities

The Elixir application starts a CoAP server that handles three main resources:

- `auth/m1`: starts an authentication session;
- `auth/m3`: completes the challenge and validates the device;
- `data`: receives data from the device after authentication.

The server:

- receives and validates device messages;
- selects a subset of keys for the challenge;
- derives the session key used for subsequent communication;
- stores session state until it expires;
- updates the keys when a session ends or expires.

## Main dependencies

The project uses:

- Elixir and OTP;
- `gen_coap` for the CoAP stack;
- `Jason` for JSON serialization;
- `:httpc` for communication with HashiCorp Vault;
- TLS certificates for Vault communication.

## Vault integration

The server does not persist the device keys directly in the application.
Instead, it stores them in HashiCorp Vault using a service token  initialized by
the `vault-init` service.

`Server.SecureVault` is responsible for:

- building the read and write URLs for a specific device;
- authenticating with the service token;
- sending HTTPS requests using the local CA certificate;
- storing and retrieving keys for a device UID.

## Configuration

The main environment variables are:

- `IOT_UIDS`: identifiers of the supported IoT devices;
- `SERVER_KEYS`: server-side key list;
- `P`: number of keys used in the challenge;
- `VAULT_ADDR`: Vault address;
- `VAULT_CACERT`: local CA certificate path;
- `AUTH_SESSION_TIMEOUT`: maximum authentication session lifetime.

## Running

When started through Docker Compose, the server is built using
`server/dockerfile` and executed as an Elixir application with CoAP support. 

To run it locally with Mix:

```bash
cd server
mix deps.get
mix run --no-halt
```

## Notes

- The server is intended for a controlled test environment.
- Keys are initialized and stored in Vault when the system starts.
- `Server.Application` registers the CoAP handlers and starts the UDP listener on port `5683`.
