# TLS/QUIC performance measurements

Provenance (results are valid only for this combination):

- date: 2026-08-06T11:43:06Z
- host: Linux aarch64, Apple (17 cpus)
- commit: e43cad4
- rustc: rustc 1.96.0 (ac68faa20 2026-05-25)
- wasmtime: wasmtime 47.0.1 (3efe09e04 2026-07-20)

Rows are `bench,<name>,<detail>,<unit>,<median>,<min>,<max>` over
batches (see bench/README.md for batch shapes and caveats).

## native (hardware AES and carryless multiply via runtime detection)

```
bench,aead-seal,chacha20-poly1305/256,MB/s,394.1,391.1,400.8
bench,aead-open,chacha20-poly1305/256,MB/s,382.7,373.6,387.4
bench,header-mask,chacha20-poly1305,ns/op,154,164,153
bench,aead-seal,chacha20-poly1305/1200,MB/s,900.9,885.1,905.5
bench,aead-open,chacha20-poly1305/1200,MB/s,883.8,874.7,891.8
bench,header-mask,chacha20-poly1305,ns/op,153,155,152
bench,aead-seal,chacha20-poly1305/16384,MB/s,1243.4,1180.8,1252.6
bench,aead-open,chacha20-poly1305/16384,MB/s,1245.9,1231.3,1255.5
bench,header-mask,chacha20-poly1305,ns/op,153,154,153
bench,aead-seal,aes-128-gcm/256,MB/s,3320.2,3194.7,3425.6
bench,aead-open,aes-128-gcm/256,MB/s,3247.3,2982.2,3451.9
bench,header-mask,aes-128-gcm,ns/op,10,12,10
bench,aead-seal,aes-128-gcm/1200,MB/s,4606.2,4568.8,4619.2
bench,aead-open,aes-128-gcm/1200,MB/s,4455.2,4353.9,4534.6
bench,header-mask,aes-128-gcm,ns/op,10,10,10
bench,aead-seal,aes-128-gcm/16384,MB/s,5987.3,5860.7,6109.4
bench,aead-open,aes-128-gcm/16384,MB/s,5652.8,5600.0,5825.2
bench,header-mask,aes-128-gcm,ns/op,10,10,10
bench,handshake,ed25519,handshakes/s,10151,9989,10446
bench,tls-bulk,chacha20-poly1305,MB/s,597.4,556.4,599.5
bench,tls-bulk,aes-128-gcm,MB/s,2284.0,2256.8,2320.6
bench,quic-bulk,native,MB/s,280.1,275.7,281.1
```

## wasm32-wasip2 under Wasmtime (baseline features)

```
bench,aead-seal,chacha20-poly1305/256,MB/s,424.7,422.7,432.2
bench,aead-open,chacha20-poly1305/256,MB/s,413.4,409.2,420.7
bench,header-mask,chacha20-poly1305,ns/op,97,98,94
bench,aead-seal,chacha20-poly1305/1200,MB/s,523.6,519.6,544.9
bench,aead-open,chacha20-poly1305/1200,MB/s,519.4,511.8,523.3
bench,header-mask,chacha20-poly1305,ns/op,99,101,93
bench,aead-seal,chacha20-poly1305/16384,MB/s,585.2,542.7,597.9
bench,aead-open,chacha20-poly1305/16384,MB/s,598.5,590.3,602.5
bench,header-mask,chacha20-poly1305,ns/op,91,94,90
bench,aead-seal,aes-128-gcm/256,MB/s,172.5,171.6,173.5
bench,aead-open,aes-128-gcm/256,MB/s,171.5,166.9,172.4
bench,header-mask,aes-128-gcm,ns/op,187,188,186
bench,aead-seal,aes-128-gcm/1200,MB/s,189.5,188.0,190.5
bench,aead-open,aes-128-gcm/1200,MB/s,189.1,188.1,190.2
bench,header-mask,aes-128-gcm,ns/op,188,189,186
bench,aead-seal,aes-128-gcm/16384,MB/s,213.9,209.8,215.0
bench,aead-open,aes-128-gcm/16384,MB/s,213.1,211.7,214.6
bench,header-mask,aes-128-gcm,ns/op,188,189,187
bench,handshake,ed25519,handshakes/s,4214,4181,4246
bench,tls-bulk,chacha20-poly1305,MB/s,283.1,280.7,285.0
bench,tls-bulk,aes-128-gcm,MB/s,105.5,104.2,105.9
bench,quic-bulk,loopback,MB/s,163.2,161.4,163.3
```

## wasm32-wasip2 under Wasmtime (+simd128)

```
bench,aead-seal,chacha20-poly1305/256,MB/s,478.4,476.2,479.4
bench,aead-open,chacha20-poly1305/256,MB/s,473.9,469.4,478.4
bench,header-mask,chacha20-poly1305,ns/op,124,128,123
bench,aead-seal,chacha20-poly1305/1200,MB/s,633.3,625.3,643.2
bench,aead-open,chacha20-poly1305/1200,MB/s,632.0,623.6,636.2
bench,header-mask,chacha20-poly1305,ns/op,123,125,123
bench,aead-seal,chacha20-poly1305/16384,MB/s,725.9,724.2,731.8
bench,aead-open,chacha20-poly1305/16384,MB/s,728.0,717.0,732.0
bench,header-mask,chacha20-poly1305,ns/op,124,125,123
bench,aead-seal,aes-128-gcm/256,MB/s,183.7,182.2,185.1
bench,aead-open,aes-128-gcm/256,MB/s,181.7,180.5,182.9
bench,header-mask,aes-128-gcm,ns/op,194,198,193
bench,aead-seal,aes-128-gcm/1200,MB/s,201.7,201.4,202.2
bench,aead-open,aes-128-gcm/1200,MB/s,200.4,199.3,201.5
bench,header-mask,aes-128-gcm,ns/op,194,195,193
bench,aead-seal,aes-128-gcm/16384,MB/s,230.8,228.4,231.6
bench,aead-open,aes-128-gcm/16384,MB/s,230.1,226.9,230.9
bench,header-mask,aes-128-gcm,ns/op,194,195,193
bench,handshake,ed25519,handshakes/s,4517,4489,4559
bench,tls-bulk,chacha20-poly1305,MB/s,349.8,347.5,354.2
bench,tls-bulk,aes-128-gcm,MB/s,112.8,112.5,113.5
```

## composed polymorph:tls component under Wasmtime (component-model async)

```
bench,component-bulk,negotiated,MB/s,259.6,253.8,261.9
bench,component-handshake,ed25519,handshakes/s,1809.2,1799.3,1827.6
```
