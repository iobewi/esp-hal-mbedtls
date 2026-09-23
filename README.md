# esp-hal-mbedtls

Reusable `no_std` glue between `esp-hal` and `mbedtls-rs`.

The crate intentionally separates TLS mechanics from application policy. It
provides the ESP hardware RNG adapter, MbedTLS time hooks and singleton
initialization, certificate/key validation, server configuration construction,
and optional Embassy networking / picoserve adapters.

It does **not** own:

- certificate or CA persistence;
- NVS namespaces or keys;
- SNTP synchronization policy;
- application HTTP routes;
- reconnect/backoff policy.

## Features

- `esp32c3` / `esp32s3`: select the ESP HAL chip.
- `embassy-net`: enable DNS + TCP + TLS client connection.
- `picoserve`: additionally expose a connected TLS session as a picoserve
  Embassy socket.

No chip feature is enabled by default.

## TLS profile

The MbedTLS feature set matches the embedded profile validated by
`embewi-agent-esp`: TLS 1.2/1.3, ECDHE/ECDSA P-256, SHA-256/SHA-512,
AES/GCM/CBC and ChaCha20-Poly1305, with 16 KiB inbound and 2 KiB outbound
record buffers.

## Status

Pre-stable. Extraction from the hardware-tested TLS implementation in
`embewi-agent-esp`; integration and hardware TLS gates are required before
the first stable API.

## License

MIT.
