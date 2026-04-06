## TLSMask

TLSMask is an upstream proxy for penetration testing that dynamically emulates TLS client behavior. It takes JA3 / JA4_r values directly from Wireshark and reproduces the exact TLS fingerprint on outbound connections allowing tools like Burp Suite to bypass TLS fingerprint-based blocking.

---

##  Features

- **One-liner hex import:** Paste a raw ClientHello hex stream from Wireshark and go
- Exact TLS ClientHello reconstruction from JA3 + JA4_r (Wireshark)
- Cipher suite and extension ordering preserved
- Padding extension (`0x0015`) support
- HTTP/2 SETTINGS frame + pseudo-header shaping
- Built-in preset profiles (OkHttp4, more coming)
- Chains to upstream proxies (e.g. Burp Suite)
- Lightweight Alpine-based Docker image (~29MB)

---

##  Real-World Validation

**Target:** Twitter API (`api.twitter.com`) behind Cloudflare + Envoy  
**Method:** Android app ClientHello captured in Wireshark, values passed directly to tlsmask

| Scenario | JA3 Hash | Result |
|----------|----------|--------|
| Burp Suite (no tlsmask) | `62f6a672...` | `403 Forbidden` |
| tlsmask (Android fingerprint) | `3a3a7739...` | `200 OK` |

Response confirmed:
```
X-Twitter-Response-Tags: BouncerCompliant
Server: cloudflare envoy
```

JA3 verified via [tls.peet.ws](https://tls.peet.ws):
```
Wireshark capture : 3a3a7739b7ee9b4dc9078b116b72ab96
tlsmask output    : 3a3a7739b7ee9b4dc9078b116b72ab96  ✓
```

---

##  How to Capture a Fingerprint (Wireshark)

**1. Filter the ClientHello in Wireshark:**
```
tls.handshake.type == 1 && tls.handshake.extensions_server_name == "target-domain"
```

**2. Choose your method:**
<img width="859" height="468" alt="image" src="https://github.com/user-attachments/assets/30562899-35bf-46f5-868d-e7ac655f6969" />
<img width="902" height="566" alt="image" src="https://github.com/user-attachments/assets/42bd082a-03a7-4634-80b2-a4c3863fbdf6" />
<img width="850" height="554" alt="image" src="https://github.com/user-attachments/assets/a045404c-405c-4189-8a62-b56768b910c6" />


| Method | What to copy | Flag |
|--------|-------------|------|
| **Hex Stream** (easiest) | Right-click the ClientHello packet → Copy → `...as a Hex Stream` | `--hex` |
| **JA3 + JA4_r** (manual) | Scroll to bottom of ClientHello → Right-click JA3 Fullstring → Copy → Value, then same for JA4_r | `--ja3` + `--ja4r` |

**3. Run TLSMask with the copied value:**
```bash
# Hex method (one flag, zero effort)
docker run -p 2255:2255 berkdedekarginoglu/tlsmask --hex <paste_hex>

# JA3 + JA4_r method
docker run -p 2255:2255 berkdedekarginoglu/tlsmask --ja3 <paste_ja3> --ja4r <paste_ja4r>
```

---

##  Quick Start

**Preset fingerprint (OkHttp4):**
```bash
docker run -p 2255:2255 berkdedekarginoglu/tlsmask
```

**From raw ClientHello hex (easiest — copy hex from Wireshark):**
```bash
docker run -p 2255:2255 berkdedekarginoglu/tlsmask \
  --hex 1603010200010001fc0303d823e8a050ad437556ad02500b1c7bad...
```

**From JA3 + JA4_r (manual):**
```bash
docker run -p 2255:2255 berkdedekarginoglu/tlsmask \
  --ja3 771,4865-4866-4867-49195-49196-52393-49199-49200-52392,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0 \
  --ja4r t13d0913h2_1301,1302,1303,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0015,0017,0023,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0501,0806,0601,0201
```

**List available presets:**
```bash
docker run berkdedekarginoglu/tlsmask --list
```

> `--ja3` and `--ja4r` must be used together. `--hex` can be used alone.

---

## ⚙️ How It Works

TLSMask sits between your testing tool and the target as an upstream MITM proxy:

1. Receives HTTPS traffic from your tool (Burp Suite, Frida, scripts)
2. Terminates the incoming TLS connection using an in-memory self-signed CA
3. Re-establishes a new TLS connection to the target using a controlled ClientHello
4. Transparently relays traffic with the spoofed fingerprint

**Workflow:**
```
Your Tool (Burp) → tlsmask :2255 → Target Server
                   [ClientHello with exact JA3/JA4]
```

---

## 🛠️ CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `--port` | Proxy listen port | `2255` |
| `--fingerprint` | Preset template name | `okhttp4` |
| `--hex` | Raw ClientHello hex stream (auto-extracts JA3+JA4_r) | — |
| `--ja3` | JA3 fullstring (requires --ja4r) | — |
| `--ja4r` | JA4_r raw string (requires --ja3) | — |
| `--upstream` | Chain to upstream proxy URL | — |
| `--verbose` | Log requests with status codes | `true` |
| `--list` | List available fingerprint presets | — |

---

##  Use Cases

- **Mobile app testing:** Reproduce the exact TLS fingerprint of an Android/iOS app after SSL unpinning
- **WAF/bot protection bypass:** Route Burp Suite traffic through a legitimate-looking TLS fingerprint
- **Fingerprint-allowlisted APIs:** Access endpoints that only accept specific client fingerprints
- **Red team operations:** Remove pentest tool signatures from outbound TLS traffic

---

## 🔗 Burp Suite Integration

```
Settings → Network → Connections → Upstream Proxy Servers → Add
  Destination host: *
  Proxy host:       127.0.0.1
  Proxy port:       2255
```

---

## ⚠️ Disclaimer

This tool is intended for authorized security testing and research purposes only. Do not use against systems you do not have explicit permission to test.
