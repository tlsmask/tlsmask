## TLSMask

TLSMask is an advanced upstream proxy designed to dynamically emulate TLS client behavior for penetration testing and security research.

---

### 🔥 Features

- Custom TLS ClientHello generation from JA3 / JA4_r (Wireshark)
- High-fidelity TLS fingerprint reconstruction
- Cipher suite and extension ordering control
- HTTP/2 SETTINGS frame + pseudo-header shaping
- Built-in preset profiles (OkHttp4, more coming)
- Zero external dependencies at runtime (vendored build)
- Lightweight Alpine-based image (~29MB)

---

### 🚀 Quick Start

**Preset fingerprint (OkHttp4):**

    docker run -p 2255:2255 berkdedekarginoglu/tlsmask \
      --port 2255 --fingerprint okhttp4 --verbose

**Custom fingerprint from Wireshark:**

    docker run -p 2255:2255 berkdedekarginoglu/tlsmask \
      --port 2255 \
      --ja3 "..." \
      --ja4r "..." \
      --verbose

**List available presets:**

    docker run --rm berkdedekarginoglu/tlsmask --list

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

---

### ⚠️ Disclaimer

This tool is intended for authorized security testing and research purposes only.
