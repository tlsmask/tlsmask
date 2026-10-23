<p align="center">
  <img src="ui/logo.png" width="112" alt="TLSMask logo">
</p>

<h1 align="center">TLSMask</h1>

<p align="center">
  An intercepting proxy that sends the TLS fingerprint you give it.
</p>

<p align="center">
  <a href="https://github.com/tlsmask/tlsmask/actions/workflows/ci.yml"><img src="https://github.com/tlsmask/tlsmask/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://hub.docker.com/r/berkdedekarginoglu/tlsmask"><img src="https://img.shields.io/docker/pulls/berkdedekarginoglu/tlsmask" alt="Docker pulls"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/tlsmask/tlsmask" alt="MIT license"></a>
</p>

![The TLSMask web UI: requests grouped by host, with the request as it went upstream on the right](docs/images/traffic.png)

TLSMask is an upstream proxy for penetration testing. Give it a ClientHello
captured in Wireshark, as a hex stream or as a JA3 + JA4_r pair, and it
reproduces that handshake on every outbound connection: the same cipher suites,
the same extensions in the same order, the same HTTP/2 settings. Put it behind
Burp Suite, a script or an instrumented mobile app, and the target sees the
client you captured rather than the tool you are testing with.

Everything is configured in the web UI. The proxy listens on `2255` and the UI
on `2256`.

## Features

- ClientHello rebuilt from a Wireshark hex stream or a JA3 + JA4_r pair, with
  cipher and extension order preserved
- Extensions the TLS library does not know are sent with their codepoint
  intact, so a capture from a current Chrome works unchanged
- Randomization that follows the browser: Chrome reshuffles its extensions and
  redraws GREASE on every handshake, Firefox does neither, and `auto` works out
  which one a fingerprint came from
- HTTP/2 SETTINGS, WINDOW_UPDATE and pseudo-header order shaped to match, so the
  Akamai fingerprint agrees with the TLS one
- The client's User-Agent goes out unchanged, and a client that sends none is
  not given Go's
- A list of upstream proxies used in rotation, and sessions that keep one exit
  IP, one TLS client and one cookie jar for a whole run
- A live request log grouped by host, showing each request as it went upstream
  and the response that came back
- A one-click test against [tls.peet.ws](https://tls.peet.ws) that shows what
  the target saw
- Proxy authentication, and a password on the UI
- A small Alpine image for amd64 and arm64

## Quick start

```bash
docker run -d --name tlsmask \
  -p 127.0.0.1:2255:2255 \
  -p 127.0.0.1:2256:2256 \
  -v tlsmask-data:/data \
  berkdedekarginoglu/tlsmask
```

Or build it from a clone with the compose file in this repository:

```bash
git clone https://github.com/tlsmask/tlsmask.git
cd tlsmask
docker compose up -d
```

Then:

1. Open **http://127.0.0.1:2256** and set a password. The form asks for the
   setup token printed at startup:
   ```bash
   docker exec tlsmask cat /data/setup-token
   ```
2. **Access**: copy the proxy URL. It carries a generated username and password.
3. **Certificate**: download `tlsmask-ca.crt` and install it with the command
   shown for your OS.
4. **Settings**: paste your fingerprint and press **Save Changes**. Until you
   do, the built-in `okhttp4` profile is used.
5. **Run Test**: check what the target sees.

```bash
curl -x http://USER:PASSWORD@127.0.0.1:2255 https://tls.peet.ws/api/clean
```

Both ports are bound to `127.0.0.1` on purpose. Read [Security](#security)
before publishing them any wider.

## Capturing a fingerprint with Wireshark

**1. Filter for the ClientHello:**

```
tls.handshake.type == 1 && tls.handshake.extensions_server_name == "target-domain"
```

**2. Copy it, one of two ways:**

| Method | What to copy | Where it goes |
|---|---|---|
| **Hex stream** (easiest) | Right-click the ClientHello packet → Copy → `...as a Hex Stream` | Settings → **Hex Dump**, then **Expand into JA3 + JA4** |
| **JA3 + JA4_r** | At the bottom of the ClientHello, right-click JA3 Fullstring → Copy → Value, then the same for JA4_r | Settings → **JA3** and **JA4** |

**3. With Preset set to Custom, press Save Changes, then Run Test.**

The two strings are not interchangeable and both are required: the JA3 carries
the cipher and extension order, the JA4_r the signature algorithms and ALPN.
The **JA4** field takes the raw JA4_r, not the hashed JA4.

![The Settings panel with a custom fingerprint](docs/images/settings.png)

**Randomize** decides whether the handshake changes between connections:

| Setting | Behaviour |
|---|---|
| `auto` | Works out whether the fingerprint is Chrome's or Firefox's and behaves like that browser. Anything else, such as okhttp or curl, stays fixed, because those clients are. The default. |
| `chrome` | Chrome and Edge behaviour: extension order permuted and GREASE redrawn on every handshake |
| `firefox` | Firefox behaviour: the same order every time |
| `off` | The same bytes on every handshake |

JA4 sorts extensions before hashing and both JA3 and JA4 ignore GREASE, so
randomizing never changes the JA4_r you configured. It only moves the JA3 hash,
the way a real browser's moves.

## Checking the result

![Run Test, showing the JA4 and HTTP/2 fingerprint tls.peet.ws received](docs/images/runtest.png)

**Run Test** sends one request through the proxy's own port to tls.peet.ws,
with your browser's User-Agent, and shows what came back. It exercises the
CONNECT, the generated certificate, the fingerprint and the upstream proxy, and
the request appears in the log with everything else.

Measured with TLSMask 2.0 replaying the ClientHello of Microsoft Edge 155,
compared with Edge itself:

| | Edge 155 | TLSMask |
|---|---|---|
| JA4 | `t13d1516h2_8daaf6152771_806a8c22fdea` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| JA4_r | 15 ciphers, 16 extensions, 11 signature algorithms | identical |
| HTTP/2 (Akamai) | `52d84b11737d980aef856699f885ca86` | `52d84b11737d980aef856699f885ca86` |
| JA3 hash | different on every connection | different on every connection |

Three runs in a row:

```
ja3_hash 5216d64d4493a5230c743135c2261a9c   ja4 t13d1516h2_8daaf6152771_806a8c22fdea
ja3_hash 6f571100e8b66e683618cffd7a80f67d   ja4 t13d1516h2_8daaf6152771_806a8c22fdea
ja3_hash ad4e44dfec75db3bd0a58f31244608fc   ja4 t13d1516h2_8daaf6152771_806a8c22fdea
```

### Real-world validation

**Target:** Twitter API (`api.twitter.com`) behind Cloudflare and Envoy

**Method:** the ClientHello of the Android app, captured in Wireshark and given
to TLSMask unchanged

| Scenario | JA3 hash | Result |
|---|---|---|
| Burp Suite alone | `62f6a672...` | `403 Forbidden` |
| Burp Suite through TLSMask (Android fingerprint) | `3a3a7739...` | `200 OK` |

The response came back with:

```
X-Twitter-Response-Tags: BouncerCompliant
Server: cloudflare envoy
```

and tls.peet.ws reported the same JA3 as the capture:

```
Wireshark capture : 3a3a7739b7ee9b4dc9078b116b72ab96
TLSMask output    : 3a3a7739b7ee9b4dc9078b116b72ab96
```

## Connecting a client

![The Access panel with the proxy credentials and a Python example](docs/images/access.png)

The proxy uses ordinary Basic proxy authentication, which every HTTP library
and intercepting proxy already supports. The values are in the **Access** panel:

| | |
|---|---|
| Host | `127.0.0.1` |
| Port | `2255` |
| Username | generated on first run; it never changes |
| Password | generated on first run; it can be regenerated |

```python
import requests

proxy = "http://USER:PASSWORD@127.0.0.1:2255"
r = requests.get("https://example.com",
                 proxies={"http": proxy, "https": proxy},
                 verify="tlsmask-ca.crt")
```

The panel has the same example for httpx, curl, Node.js, Go, Java, C#, PHP,
Ruby and Rust, with your credentials filled in.

A request without credentials gets `407 Proxy Authentication Required` and a
`Proxy-Authenticate: Basic` challenge, which is what clients that only send
credentials when asked are waiting for. TLSMask consumes the
`Proxy-Authorization` header; it is never forwarded to the target.

**Generate a New Proxy Password** replaces the password once you confirm. The
username stays the same, so only the password needs changing in client
configuration, and clients still using the old one get `407` straight away.

### Burp Suite

In *Settings → Network → Connections → Upstream proxy servers*, add:

```
Destination host:     *
Proxy host:           127.0.0.1
Proxy port:           2255
Authentication type:  Basic
Username, password:   from the Access panel
```

Burp keeps intercepting as usual. TLSMask sits behind it and replaces Burp's
ClientHello with the one you configured.

## Installing the CA

![The Certificate panel with install commands for Windows](docs/images/cert.png)

TLSMask terminates the client's TLS and opens its own connection to the target,
so clients are shown certificates signed by TLSMask's CA. Install the CA once
and they verify normally. The **Certificate** panel downloads it and shows the
commands for the OS it detects:

| OS | Command |
|---|---|
| Windows | `certutil -addstore -user Root tlsmask-ca.crt` |
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain tlsmask-ca.crt` |
| Debian, Ubuntu | `sudo cp tlsmask-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates` |
| Fedora, RHEL, CentOS | `sudo cp tlsmask-ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust` |
| Arch | `sudo trust anchor --store tlsmask-ca.crt` |

Browsers, Go, .NET and curl read the system store. Python, Node.js and Java
keep their own lists and need pointing at the file:

```bash
REQUESTS_CA_BUNDLE=tlsmask-ca.crt SSL_CERT_FILE=tlsmask-ca.crt python script.py
NODE_EXTRA_CA_CERTS=tlsmask-ca.crt node app.js
keytool -importcert -alias tlsmask -file tlsmask-ca.crt -cacerts -storepass changeit
```

The CA is generated on first start and kept in the data directory, so it
survives restarts as long as that directory is on a volume. **Regenerate**
replaces it; install the new one wherever the old one was trusted.

## Upstream proxies

Settings takes a list of upstream proxies, one per line:

```
host:port
host:port:user:pass
```

They are used in rotation, one per session. With the list empty, requests leave
from the machine TLSMask runs on. **Refuse requests that would leave without a
proxy** turns that into an error, so a mistake in the list never sends traffic
from your own IP. **Cooldown After Repeated Failures** takes a proxy that keeps
failing out of rotation for that long.

The list is the only thing that decides where a request leaves from. A client
cannot name a proxy of its own.

## Sessions

Without a session, each tunnel gets its own upstream proxy. A script that
touches two hosts in one flow then exits from two different IPs, and its next
run inherits whatever the last one left in the cookie jar. Targets tend to read
both as tampering.

A session ID ties one upstream proxy, one TLS client and one cookie jar to one
run. It goes in the username:

```python
import secrets, requests

sid = secrets.token_hex(4)
proxy = f"http://{USER}-session-{sid}:{PASSWORD}@127.0.0.1:2255"

s = requests.Session()
s.proxies = {"http": proxy, "https": proxy}
s.verify = "tlsmask-ca.crt"

# ... run the flow ...

requests.delete(f"http://127.0.0.1:2255/sessions/{sid}", auth=(USER, PASSWORD))
```

This is how commercial proxy providers do it, so it works with anything that
takes a proxy URL. A client that can set headers can send `X-TLS-Session: <id>`
instead.

Ending the session is optional. It expires after **Idle TTL** with no traffic
(ten minutes by default), so a long run is never cut off mid-flow, and after
**Release Connections After** without traffic it closes its sockets but keeps
its identity. Ending it yourself just frees the upstream proxy sooner.

The proxy port also answers a small control API, with the same username and
password as Basic authentication:

| Endpoint | |
|---|---|
| `GET /sessions` | list live sessions |
| `DELETE /sessions/<id>` | end one |
| `DELETE /sessions` | end all |
| `GET /stats` | what the proxy is holding right now |

## The web UI

![A recorded response: status, timing, upstream, headers and body](docs/images/response.png)

Requests stream in live, grouped by host, newest first. Filter by host, path,
session or connection, or show only failures. **Pause** holds new rows instead
of moving the list under the cursor, and **Resume** shows how many are waiting.

**Request** shows the request as TLSMask sent it upstream, header for header,
in the order it went out. **Response** shows the status, timing, the upstream
it went through, the headers and the body. Bodies are copied into a 32 KB
buffer as they stream past, so a large download goes through without the proxy
holding it; anything longer is marked as cut. The last 500 exchanges are kept.

**Fingerprint** shows the JA3 being impersonated and the GREASEd version that
actually goes on the wire.

### Signing in

<img src="docs/images/signin.png" width="640" alt="The sign-in page">

The first visit asks for a password of at least eight characters, and setting
it generates the proxy username and password. Until then, the proxy answers
every request with `407`. Anywhere other than the machine TLSMask runs on, the
form also asks for the setup token. In Docker that is always the case, since
the browser's request arrives from the bridge network rather than from
loopback.

The password is stored as a PBKDF2-SHA256 hash in `auth.json`, readable only by
its owner. Repeated wrong passwords lock the address out for two minutes.
Sign-ins last twelve hours and are held in memory, so a restart signs everyone
out.

**Forgot the password?** Reset it from the console:

```bash
docker exec tlsmask tlsmask reset-password
```

It prints a new setup token. Open the UI and set a new password with it. The
running proxy picks up the change without a restart, every browser is signed
out, and the proxy username and password stay as they were, so clients keep
working in the meantime.

## Reading the log

Two failures look alike and mean opposite things:

```
[#2316] [c51589]  ✗ relay: dial tcp 188.40.201.42:44068: i/o timeout
[#2401] [c51591]  ⊘ relay: client went away before the upstream replied
```

`✗` is TLSMask failing to reach the upstream. `⊘` is the client giving up
first, which is normal and not worth chasing upstream.

`[cNNNNN]` is the client's connection. A run of `⊘` sharing one connection
means a tunnel collapsed and took every request on it with it; different
connections mean that many clients each gave up on their own.

Every ten seconds a summary line marks the moment things change:

```
13:08:52  [health]  ok=251                    tunnels open=251 dialing=50
13:09:02  [health]  ok=50 proxy-refused=4158  tunnels open=301 dialing=50   <- the upstream turned here
```

## Configuration

Flags only decide where TLSMask listens and where it keeps its state.
Everything else is in Settings.

| Flag | Environment | Default |
|---|---|---|
| `--port` | | `2255` |
| `--ui-addr` | `TLSMASK_UI_ADDR` | one port above `--port`, on every interface |
| `--data-dir` | `TLSMASK_DATA_DIR` | `/data` in Docker, otherwise the user config directory (`%AppData%\tlsmask`, `~/Library/Application Support/tlsmask`, `~/.config/tlsmask`) |
| `--version` | | |

The data directory holds the whole state of an instance:

| File | |
|---|---|
| `tlsmask-ca.crt`, `tlsmask-ca.key` | the CA |
| `settings.json` | everything set in Settings |
| `auth.json` | the UI password hash and the proxy credentials |
| `setup-token` | present only while a password is waiting to be set |

Without a volume on `/data`, a container generates a new CA, comes back
unconfigured and asks for a password on every start.

## Security

Port `2255` needs the proxy credentials and port `2256` needs the password, so
being able to reach them is not the same as being able to use them. What the
password does not change is that the UI speaks plain HTTP. On a published port,
the password and the session cookie cross the network in clear, and the UI
shows raw requests: authorization headers, cookies and the upstream proxy
passwords.

That is why the Docker commands above publish both ports on `127.0.0.1` only.
Run outside Docker, TLSMask listens on every interface; start it with
`--ui-addr 127.0.0.1:2256` to keep the UI local. Expose either port more widely
only behind something that terminates TLS.

Target certificates are verified by default. Turning that off in Settings also
hides an upstream proxy that terminates TLS itself, and such a proxy replaces
your ClientHello with its own.

## Known limits

When a client speaks HTTP/2 to TLSMask, its header order is lost. Go's HTTP/2
server decodes HPACK into a map before any handler sees the request, so the
order is gone by then, and those requests go out in a fixed Chromium-like order
instead. If you need the client's exact order, speak HTTP/1.1 to the proxy
(`curl --http1.1`, or `CurlHttpVersion.V1_1` in curl_cffi). That path reads the
request off the wire and keeps its order.

## Upgrading from 1.x

2.0 moves configuration out of flags and into the web UI, and puts credentials
on both ports.

- `--hex`, `--ja3`, `--ja4r`, `--fingerprint`, `--upstream`, `--list` and
  `--verbose` are gone. The same settings are in the UI and are saved to the
  data directory.
- The proxy now requires a username and password. Add them to your clients and
  to Burp's upstream proxy entry.
- The CA used to live in memory and change on every start. It is now saved, so
  mount a volume on `/data` and install the CA once.

## Use cases

- **Mobile app testing:** reproduce the exact TLS fingerprint of an Android or
  iOS app after SSL unpinning
- **WAF and bot protection testing:** send Burp Suite traffic with a TLS
  fingerprint the target accepts
- **Fingerprint-allowlisted APIs:** reach endpoints that only accept specific
  client fingerprints
- **Red team operations:** keep pentest tool signatures out of outbound TLS
  traffic

## Building from source

Go 1.24 or later:

```bash
go build -ldflags="-X main.Version=$(git describe --tags)" -o tlsmask .
./tlsmask
```

```bash
go test ./...         # unit tests, and the end-to-end suite in tests/
go test -race ./...
```

| Directory | |
|---|---|
| `fingerprint/` | ClientHello and HTTP/2 construction |
| `proxy/` | the proxy, the control API and the web UI's handlers |
| `ui/` | the web interface, embedded in the binary |
| `cert/` | the CA and the per-host certificates |
| `tests/` | end-to-end tests against a real proxy on loopback |
| `deps/tls-client/` | a patched copy of [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) |

## Disclaimer

TLSMask is intended for authorized security testing and research only. Do not
use it against systems you do not have explicit permission to test.

## License

[MIT](LICENSE)
