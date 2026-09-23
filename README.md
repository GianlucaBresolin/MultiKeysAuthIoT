# MultiKeyAuthIoT

This repository implements a multi-key authentication prototype for an IoT
device communicating with a server over CoAP. Key management  is handled through
HashiCorp Vault, while the IoT device is emulated in QEMU.

## Overview

The project demonstrates a model in which:

- an IoT device owns a set of initial keys;
- the server authenticates the device through a challenge-response session;
- keys are securely distributed and stored through Vault;
- device-server communication uses CoAP and AES-CBC encryption with a
  dynamically derived session key. 

## Architecture

The system is divided into the following components:

- `server/`: Elixir application that exposes CoAP resources and coordinates
  authentication; 
- `iot_device/`: Rust bare-metal firmware for an ARM-emulated IoT device;
- `vault-init/`: HashiCorp Vault bootstrap that initializes policies and service
  tokens; 
- `tls/`: locally generated TLS certificates for Vault;
- `docker-compose.yml`: Docker service orchestration.

## Authentication flow

The protocol is based on the following messages:

- M1: the device starts a session and sends its UID and session ID;
- M2: the server selects a subset of keys and replies with a challenge;
- M3: the device computes a response using the selected keys;
- M4: the server validates the response and establishes a session key;
- data: the device sends encrypted telemetry using the active session key.

The device combines master keys and derived keys to implement multi-key
authentication. Keys can be updated when the authentication  session expires.

## Prerequisites

To run the project, install:

- Docker and Docker Compose;
- OpenSSL;
- Bash;
- Git;
- a machine with QEMU and virtio support.

## Quick start

1. Generate the keys and the `.env` file:

   ```bash
   ./run_experiment.sh
   ```

   The script asks how many keys to generate, creates random base64-encoded
   keys, and writes the configuration used by Docker Compose. 

2. Start the services:

   ```bash
   docker compose up --build
   ```

3. If a configured `.env` file already exists, it can be reused instead of
   generating a new configuration. 

## Main configuration variables

The root `.env` file contains values such as:

- `KEYS`: initial device keys;
- `SERVER_KEYS`: keys known by the server;
- `SKEY`: device secret key;
- `KEY_COUNT`: number of generated keys;
- `P`: number of keys selected for a challenge.

## Repository structure

- `server/`: Elixir backend with CoAP and Vault integration;
- `iot_device/`: Rust bare-metal firmware for the emulated device;
- `tls/`: locally generated Vault TLS certificates;
- `vault-init-out/`: Vault initialization output, including the service token; 
- `run_experiment.sh`: helper script for generating the test configuration;
- `docker-compose.yml`: definition of all services.

## Notes

- Vault is initialized locally at Compose startup and uses a self-signed
  certificate. 
- The `iot_device` component runs in QEMU with an ARM bare-metal kernel rather
  than as a standard Linux application. 

## Module documentation

For more information, see:
- [`server/README.md`](server/README.md)
- [`iot_device/README.md`](iot_device/README.md)
