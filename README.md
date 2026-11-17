# Custom Tunnel Pro

**Developer:** Liaqat Ali  
**Telegram:** `@LiaqatAliPro`  
**Application ID:** `com.customtunnelpro.vpn`

Professional Android VPN and tunneling application supporting Xray-Core (VLESS, VMess, Trojan, Shadowsocks, SOCKS5), 14 SSH tunnel modes (Direct, HTTP Proxy, HTTP CONNECT, Custom Payload, SSL/TLS, WebSocket WS/WSS, TLS+WS, SOCKS4/5, Proxy Chain, Local/Remote/Dynamic Port Forwarding), and HEV SOCKS5 TUN routing for both 64-bit (`arm64-v8a`) and 32-bit (`armeabi-v7a`) ARM Android architectures.

---

## 1. Architecture Overview

Custom Tunnel Pro implements a modular multi-engine VPN architecture running over the standard Android `VpnService` with complete lifecycle state machine and upstream socket protection (`VpnService.protect()`).

```
 +---------------------------------------------------------------+
 |                     Android Device Traffic                     |
 +-------------------------------+-------------------------------+
                                 |
                                 v
                +---------------------------------+
                |   Android VpnService (tun0)     |  MTU 1500, 198.18.0.1/24
                +---------------------------------+
                                 |
                                 v
                +---------------------------------+
                |    HEV SOCKS5 Tunnel (C/lwIP)   |  tun2socks bridge
                +---------------------------------+
                                 |
                     +-----------+-----------+
                     |                       |
                     v (127.0.0.1:10808)     v (127.0.0.1:10809)
         +-----------------------+   +-----------------------+
         |    Xray Core (Go)     |   |   SSH Engine (JSch)   |
         |  VLESS / VMess / TLS  |   | HTTP Custom Injector  |
         | Trojan / Shadowsocks  |   | Payload / Bug Host    |
         +-----------+-----------+   +-----------+-----------+
                     |                           |
                     +-------------+-------------+
                                   | (VpnService.protect())
                                   v
                      Upstream Internet Gateway
```

### Supported Protocol Engines
1. **Xray Core Engine (`libv2ray.aar` / `libgojni.so`)**:
   - Protocols: VLESS, VMess, Trojan, Shadowsocks, SOCKS5.
   - Transports: TCP, WebSocket (WS), gRPC.
   - Security: TLS, Reality (`pbk`, `sid`, `fp`), none.
   - Sniffing & DNS routing.
2. **HEV SOCKS5 Tunnel (`hev-socks5-tunnel.aar` / `libhev-socks5-tunnel.so`)**:
   - High-performance, lightweight tun2socks packet forwarder written in C using a modified lwIP stack.
   - Directly converts raw IP packets from the Android TUN file descriptor into standard TCP/UDP SOCKS5 connections.
3. **SSH Engine (`com.github.mwiede:jsch`) with HTTP Custom Payload Injector**:
   - Upstream socket protection via `VpnService.protect()` to prevent routing loops.
   - In-process RFC 1928 SOCKS5 proxy server bridge.
   - Custom HTTP Injector payload formatting with macro substitution (`[host]`, `[port]`, `[host_port]`, `[crlf]`, `[protocol]`, `[ua]`) for custom bug host and ISP header injection.
   - Remote HTTP proxy tunneling.

---

## 2. ABI & Architecture Verification

AegisTunnel explicitly targets and verifies both ARM architectures:
- **`arm64-v8a`** (64-bit ARM)
- **`armeabi-v7a`** (32-bit ARM)

Native libraries are **not committed to this source repository**. GitHub Actions downloads the pinned Xray and HEV Android AARs during every build. Those AARs provide the Java bindings and native shared objects for both `arm64-v8a` and `armeabi-v7a`. The workflow also downloads fresh `geoip.dat` and `geosite.dat` assets before Gradle starts.

Dependency sources:
- Xray Android AAR (`libv2ray.aar`): https://github.com/2dust/AndroidLibXrayLite/releases/tag/v26.10.21
- HEV Android AAR (`hev-socks5-tunnel.aar`): https://github.com/heiher/hev-socks5-tunnel/releases/tag/2.19.3
- GeoIP / GeoSite databases: https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest

The workflow verifies SHA-256 hashes for the pinned AARs, checks both ABI entries and required Java classes, then verifies the final APK contains all four native libraries plus both routing databases. A missing or invalid dependency fails the build instead of producing an incomplete APK.

### Verification Command
```bash
unzip -l app/build/outputs/apk/debug/app-debug.apk | grep -E "lib/(arm64-v8a|armeabi-v7a)"
```
Output:
```
lib/arm64-v8a/libgojni.so
lib/arm64-v8a/libhev-socks5-tunnel.so
lib/armeabi-v7a/libgojni.so
lib/armeabi-v7a/libhev-socks5-tunnel.so
```

---

## 3. Key Features

- **Connection Lifecycle State Machine**:
  `Disconnected` → `Validating` → `RequestingVpnPermission` → `StartingEngine` → `Connecting` → `Connected` → `Reconnecting` → `Stopping`.
- **Zero-Fake Guarantee**:
  - Never displays fabricated server pings, simulated speeds, or fake connection statuses.
  - Latency is measured by initiating an actual TCP socket handshake to the configured host and port.
- **Privacy & Redacted Logging**:
  - In-memory circular log buffer.
  - Automatically redacts passwords, tokens, private keys, and UUIDs using regular expression filters.
  - Zero analytics or traffic logging.
- **DNS & IPv6 Leak Isolation**:
  - Secure tunnel DNS resolver selection (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9, AdGuard, Custom).
  - Strict IPv6 isolation to prevent dual-stack leakage outside the tunnel.
  - Optional LAN subnet bypass (192.168.0.0/16, 10.0.0.0/8).
- **Import & Export**:
  - Supports clipboard & file import for `vmess://`, `vless://`, `trojan://`, `ss://`, `ssh://`, and standard Xray JSON outbounds.
  - Share and export profile configurations to clipboard or Android Share Sheet.

---

## 4. Building and Testing

### Build APK
The recommended build is GitHub Actions (`.github/workflows/build-apk.yml`). It downloads and verifies the pinned Xray/HEV AARs and the latest GeoIP/GeoSite assets before Gradle runs. Push to `main` or manually start **Build and Release Debug APK** from the Actions tab.

For a local build, run the dependency-download and verification commands from the workflow first, then run:
```bash
gradle :app:assembleDebug
```

### Run Unit and Robolectric Tests
After preparing the same build-time dependencies, run:
```bash
gradle :app:testDebugUnitTest
```
Tests cover:
- `ConfigParser` (VLESS, Trojan, VMess, SSH, raw JSON)
- `ConfigParser` error handling & syntax validation
- `PayloadInjector` macro string replacement
- `AppLogger` credential and token redaction
- `XrayEngineAdapter` JSON configuration schema generation
- `VpnState` transition properties
- Robolectric resource verification
