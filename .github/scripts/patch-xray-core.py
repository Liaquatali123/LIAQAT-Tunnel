#!/usr/bin/env python3
"""Apply protocol-scoped plaintext VLESS/Trojan opt-ins to pinned Xray source."""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: patch-xray-core.py /path/to/infra/conf/xray.go")

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")


def replace_once(old: str, new: str, label: str) -> None:
    global source
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"Patch safety check failed for {label}: expected 1 match, found {count}")
    source = source.replace(old, new, 1)


replace_once(
    '\tTargetStrategy string           `json:"targetStrategy"`\n\t// Explicit app-scoped opt-ins for legacy plaintext outbounds.\n\tAllowInsecureVless bool         `json:"allowInsecureVless"`\n\tAllowInsecureTrojan bool        `json:"allowInsecureTrojan"`\n}',
    '\tTargetStrategy string           `json:"targetStrategy"`\n'
    '\t// AllowInsecureVless is an app-scoped opt-in for legacy plaintext VLESS outbounds.\n'
    '\tAllowInsecureVless bool         `json:"allowInsecureVless"`\n}',
    "outbound config field",
)
replace_once(
    'func validateOutboundTransportSecurity(rawConfig interface{}, senderSettings *proxyman.SenderConfig, allowInsecureVless bool, allowInsecureTrojan bool) error {',
    'func validateOutboundTransportSecurity(rawConfig interface{}, senderSettings *proxyman.SenderConfig, allowInsecureVless bool) error {',
    "validation function signature",
)
replace_once(
    'if !allowInsecureVless && requiresTransportSecurity(vlessCfg.Address) {',
    'if !allowInsecureVless && requiresTransportSecurity(vlessCfg.Address) {',
    "VLESS-only validation gate",
)
replace_once(
    'if requiresTransportSecurity(tjCfg.Servers[0].Address) {',
    'if !allowInsecureTrojan && requiresTransportSecurity(tjCfg.Servers[0].Address) {',
    "Trojan-only validation gate",
)
replace_once(
    'if err := validateOutboundTransportSecurity(rawConfig, senderSettings, c.AllowInsecureVless, c.AllowInsecureTrojan); err != nil {',
    'if err := validateOutboundTransportSecurity(rawConfig, senderSettings, c.AllowInsecureVless); err != nil {',
    "validation call",
)

if "AllowInsecureVless bool" not in source or "AllowInsecureTrojan bool" not in source:
    raise SystemExit("Patched outbound field missing")
if "if !allowInsecureVless && requiresTransportSecurity(vlessCfg.Address)" not in source or "if !allowInsecureTrojan && requiresTransportSecurity(tjCfg.Servers[0].Address)" not in source:
    raise SystemExit("Patched VLESS-only gate missing")
if "validateOutboundTransportSecurity(rawConfig, senderSettings, c.AllowInsecureVless, c.AllowInsecureTrojan)" not in source:
    raise SystemExit("Patched validation call missing")

path.write_text(source, encoding="utf-8")
print("Applied protocol-scoped plaintext VLESS/Trojan opt-ins. All other core security checks remain unchanged.")
