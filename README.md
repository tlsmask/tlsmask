## TLSMask

TLSMask is an advanced upstream proxy designed to dynamically emulate TLS client behavior for penetration testing and security research.

---

### 🔥 Features

- Custom TLS ClientHello generation from JA3 / JA4_r (Wireshark)
- High-fidelity TLS fingerprint reconstruction
- Cipher suite and extension ordering control
- HTTP/2 SETTINGS frame + pseudo-header shaping
- Built-in preset profiles (OkHttp4, more coming)
- Lightweight Alpine-based image (~29MB)

---

### 🚀 Quick Start

**Preset fingerprint (OkHttp4):**

    docker run -p 2255:2255 berkdedekarginoglu/tlsmask

**Custom fingerprint from Wireshark:**

    docker run -p 2255:2255 berkdedekarginoglu/tlsmask \
      --ja3 771,4865-4866-4867-49195-49196-52393-49199-49200-52392,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0 \
      --ja4r t12d1209h2_002f,0035,009c,009d,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0017,0023,ff01_0403,0804,0401,0503,0805,0501,0806,0601,0201

**List available presets:**

    docker run --rm berkdedekarginoglu/tlsmask --list

> **Note:** JA3 and JA4_r values contain no spaces, so quotes are not required.

---

### 🛠️ CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `--port` | Proxy listen port | `2255` |
| `--fingerprint` | Preset template name | `okhttp4` |
| `--ja3` | JA3 fullstring | — |
| `--ja4r` | JA4_r raw string | — |
| `--upstream` | Chain to upstream proxy | — |
| `--verbose` | Log requests with status codes | `true` |
| `--list` | List available presets | — |

---

### 🎯 Use Cases

- Testing systems that rely on TLS fingerprinting (WAF, bot protection)
- Mobile traffic emulation (Android / iOS)
- Red team operations
- Anti-bot system research

---

### ⚙️ How It Works

TLSMask acts as an upstream MITM proxy that:

1. Receives HTTPS traffic from your tool (Burp, Frida, scripts)
2. Terminates the incoming TLS connection using an in-memory self-signed CA
3. Re-establishes a new TLS connection to the target server using a controlled ClientHello fingerprint
4. Transparently relays the traffic with the new fingerprint

**Burp Suite:** Settings → Network → Connections → Upstream Proxy Servers → Add `127.0.0.1:2255`

---

## Internal TLS Engine

This project uses a patched version of bogdanfinn/tls-client located in `deps/tls-client`.

Modifications include custom TLS fingerprint profiles (e.g. Android/OkHttp).

---

### ⚠️ Disclaimer

This tool is intended for authorized security testing and research purposes only.
