# TLS/QUIC performance measurements

Provenance (results are valid only for this combination):

- date: 2026-08-05T13:23:46Z
- host: Linux aarch64, Apple (17 cpus)
- commit: abaf53e
- rustc: rustc 1.96.0 (ac68faa20 2026-05-25)
- wasmtime: wasmtime 47.0.1 (3efe09e04 2026-07-20)

Rows are `bench,<name>,<detail>,<unit>,<median>,<min>,<max>` over
batches (see bench/README.md for batch shapes and caveats).

## native (hardware AES and carryless multiply via runtime detection)

```
bench,aead-seal,chacha20-poly1305/256,MB/s,414.9,404.2,418.0
bench,aead-open,chacha20-poly1305/256,MB/s,392.3,374.5,402.8
bench,header-mask,chacha20-poly1305,ns/op,153,159,151
bench,aead-seal,chacha20-poly1305/1200,MB/s,890.3,870.7,897.0
bench,aead-open,chacha20-poly1305/1200,MB/s,878.4,863.0,893.6
bench,header-mask,chacha20-poly1305,ns/op,151,157,150
bench,aead-seal,chacha20-poly1305/16384,MB/s,1247.9,1240.2,1261.1
bench,aead-open,chacha20-poly1305/16384,MB/s,1234.8,1225.1,1250.4
bench,header-mask,chacha20-poly1305,ns/op,151,152,150
bench,aead-seal,aes-128-gcm/256,MB/s,3174.3,3080.1,3282.7
bench,aead-open,aes-128-gcm/256,MB/s,3236.4,3175.0,3397.8
bench,header-mask,aes-128-gcm,ns/op,11,15,10
bench,aead-seal,aes-128-gcm/1200,MB/s,4485.9,3331.5,4562.6
bench,aead-open,aes-128-gcm/1200,MB/s,4422.4,4312.6,4446.3
bench,header-mask,aes-128-gcm,ns/op,11,11,10
bench,aead-seal,aes-128-gcm/16384,MB/s,5781.7,5703.8,5808.8
bench,aead-open,aes-128-gcm/16384,MB/s,5545.9,5522.8,5568.6
bench,header-mask,aes-128-gcm,ns/op,11,11,10
bench,handshake,ed25519,handshakes/s,9606,9492,9685
bench,tls-bulk,chacha20-poly1305,MB/s,591.2,586.9,593.1
bench,tls-bulk,aes-128-gcm,MB/s,2379.2,2345.1,2426.6
bench,quic-bulk,native,MB/s,281.4,280.9,281.5
```

## wasm32-wasip2 under Wasmtime (baseline features)

```
bench,aead-seal,chacha20-poly1305/256,MB/s,439.4,394.2,444.7
bench,aead-open,chacha20-poly1305/256,MB/s,424.9,322.2,427.0
bench,header-mask,chacha20-poly1305,ns/op,82,86,81
bench,aead-seal,chacha20-poly1305/1200,MB/s,524.3,517.1,526.4
bench,aead-open,chacha20-poly1305/1200,MB/s,518.6,514.1,522.5
bench,header-mask,chacha20-poly1305,ns/op,81,84,78
bench,aead-seal,chacha20-poly1305/16384,MB/s,581.6,577.4,589.0
bench,aead-open,chacha20-poly1305/16384,MB/s,586.1,580.0,590.5
bench,header-mask,chacha20-poly1305,ns/op,78,79,77
bench,aead-seal,aes-128-gcm/256,MB/s,170.2,167.8,171.7
bench,aead-open,aes-128-gcm/256,MB/s,161.2,126.6,164.4
bench,header-mask,aes-128-gcm,ns/op,186,188,184
bench,aead-seal,aes-128-gcm/1200,MB/s,185.5,181.8,187.6
bench,aead-open,aes-128-gcm/1200,MB/s,185.9,181.4,187.4
bench,header-mask,aes-128-gcm,ns/op,187,191,185
bench,aead-seal,aes-128-gcm/16384,MB/s,210.7,205.7,212.3
bench,aead-open,aes-128-gcm/16384,MB/s,211.2,207.5,212.2
bench,header-mask,aes-128-gcm,ns/op,185,188,185
bench,handshake,ed25519,handshakes/s,4178,4134,4225
bench,tls-bulk,chacha20-poly1305,MB/s,285.2,280.2,286.7
bench,tls-bulk,aes-128-gcm,MB/s,103.7,99.8,104.6
bench,quic-bulk,loopback,MB/s,159.6,159.0,160.3
```

## wasm32-wasip2 under Wasmtime (+simd128)

```
bench,aead-seal,chacha20-poly1305/256,MB/s,476.9,471.1,480.2
bench,aead-open,chacha20-poly1305/256,MB/s,471.7,464.5,474.5
bench,header-mask,chacha20-poly1305,ns/op,112,119,111
bench,aead-seal,chacha20-poly1305/1200,MB/s,620.1,611.5,629.9
bench,aead-open,chacha20-poly1305/1200,MB/s,615.2,605.8,624.9
bench,header-mask,chacha20-poly1305,ns/op,111,112,110
bench,aead-seal,chacha20-poly1305/16384,MB/s,715.3,708.9,727.0
bench,aead-open,chacha20-poly1305/16384,MB/s,710.6,701.8,716.4
bench,header-mask,chacha20-poly1305,ns/op,111,111,110
bench,aead-seal,aes-128-gcm/256,MB/s,179.3,130.7,181.2
bench,aead-open,aes-128-gcm/256,MB/s,177.8,176.6,179.2
bench,header-mask,aes-128-gcm,ns/op,194,198,192
bench,aead-seal,aes-128-gcm/1200,MB/s,197.1,195.7,199.6
bench,aead-open,aes-128-gcm/1200,MB/s,197.3,195.0,197.8
bench,header-mask,aes-128-gcm,ns/op,197,198,192
bench,aead-seal,aes-128-gcm/16384,MB/s,225.2,217.2,227.1
bench,aead-open,aes-128-gcm/16384,MB/s,224.0,220.9,226.3
bench,header-mask,aes-128-gcm,ns/op,193,194,192
bench,handshake,ed25519,handshakes/s,4484,4447,4546
bench,tls-bulk,chacha20-poly1305,MB/s,342.1,339.1,345.4
bench,tls-bulk,aes-128-gcm,MB/s,110.9,110.1,111.3
```

## composed polymorph:tls component under Wasmtime (component-model async)

```
bench,component-bulk,negotiated,MB/s,258.7,255.3,261.4
bench,component-handshake,ed25519,handshakes/s,1796.0,1756.0,1804.6
```
