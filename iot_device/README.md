# IoT Device

This module contains the firmware for the emulated IoT device, written in Rust
for a bare-metal ARM environment. 

## Purpose

The device is designed to:

- read the initial keys and the secret key `SKEY` from the build environment;
- initialize the local key store;
- start an authentication session with the CoAP server;
- send encrypted telemetry after successful authentication;
- handle key updates when the session expires or authentication is restarted.

## Internal architecture

The main modules are:

- `config.rs`: parses environment variables and decodes base64-encoded keys;
- `secure_store.rs`: stores encrypted keys locally;
- `auth_manager.rs`: manages authentication sessions and key derivation;
- `communication_manager.rs`: manages the UDP socket and CoAP communication;
- `coap_utils.rs`: builds and parses CoAP packets;
- `crypto.rs`: provides cryptographic and key-derivation operations.

## Runtime requirements

The firmware runs in QEMU with an ARM guest; it is not a standard Linux process.
The `iot_device` container therefore compiles the target with:

```bash
cargo build --release --target aarch64-unknown-none
```

It then boots the resulting kernel in QEMU.

## Environment variables

The main values passed to the container are:

- `KEYS`: JSON array containing the initial keys;
- `SKEY`: device secret key;
- `IOT_UID`: device identifier;
- `P`: number of keys used in the challenge;
- `KEY_COUNT`: total number of available keys.

## Build and startup

The build is defined in `iot_device/dockerfile` and is performed automatically
by Docker Compose. QEMU is started with: 

- a virtual network and virtio-net interface;
- a virtio-rng device;
- a kernel compiled for `aarch64-unknown-none`.

## Local build

From this module directory, the firmware can be compiled with:

```bash
cargo build --release --target aarch64-unknown-none
```

In normal usage, however, the Docker Compose pipeline handles the build and the
QEMU boot process. 
## Notes

- The device uses `no_std` components and requires a minimal execution
  environment. 
- Security relies on limited handling of cryptographic material and keys derived
  at runtime. 
- Communication with the server is non-blocking and uses periodic polling of
  network traffic and the authenticated session.  
