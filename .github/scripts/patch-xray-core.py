#!/usr/bin/env python3
"""Apply protocol-scoped plaintext VLESS/Trojan opt-ins to pinned Xray source."""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: patch-xray-core.py /path/to/infra/conf/xray.go")

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
bt = chr(96)
target_strategy = '\tTargetStrategy string           ' + bt + 'json:"targetStrategy"' + bt + '\n}'
patched_fields = (
    '\tTargetStrategy string           ' + bt + 'json:"targetStrategy"' + bt + '\n'
    '\t// Explicit app-scoped opt-ins for legacy plaintext VLESS/Trojan outbounds.\n'
    '\tAllowInsecureVless bool         ' + bt + 'json:"allowInsecureVless"' + bt + '\n'
    '\tAllowInsecureTrojan bool        ' + bt + 'json:"allowInsecureTrojan"' + bt + '\n}'
)

def replace_once(old: str, new: str, label: str) -> None:
    global source
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"Patch safety check failed for {label}: expected 1 match, found {count}")
    source = source.replace(old, new, 1)

replace_once(target_strategy, patched_fields, "outbound config fields")
replace_once(
    'func validateOutboundTransportSecurity(rawConfig interface{}, senderSettings *proxyman.SenderConfig) error {',
    'func validateOutboundTransportSecurity(rawConfig interface{}, senderSettings *proxyman.SenderConfig, allowInsecureVless bool, allowInsecureTrojan bool) error {',
    "validation function signature",
)
replace_once(
    'if requiresTransportSecurity(vlessCfg.Address) {',
    'if !allowInsecureVless && requiresTransportSecurity(vlessCfg.Address) {',
    "VLESS-only validation gate",
)
replace_once(
    'if requiresTransportSecurity(tjCfg.Servers[0].Address) {',
    'if !allowInsecureTrojan && requiresTransportSecurity(tjCfg.Servers[0].Address) {',
    "Trojan-only validation gate",
)
replace_once(
    'if err := validateOutboundTransportSecurity(rawConfig, senderSettings); err != nil {',
    'if err := validateOutboundTransportSecurity(rawConfig, senderSettings, c.AllowInsecureVless, c.AllowInsecureTrojan); err != nil {',
    "validation call",
)

for required in (
    "AllowInsecureVless bool",
    "AllowInsecureTrojan bool",
    "if !allowInsecureVless && requiresTransportSecurity(vlessCfg.Address)",
    "if !allowInsecureTrojan && requiresTransportSecurity(tjCfg.Servers[0].Address)",
    "validateOutboundTransportSecurity(rawConfig, senderSettings, c.AllowInsecureVless, c.AllowInsecureTrojan)",
):
    if required not in source:
        raise SystemExit("Patched Xray source is missing required guard: " + required)

path.write_text(source, encoding="utf-8")
print("Applied protocol-scoped plaintext VLESS/Trojan opt-ins. All other core security checks remain unchanged.")
