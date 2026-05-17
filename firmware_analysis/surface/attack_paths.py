"""Build network entry points and infer attack paths from parsed firmware findings."""

from typing import Optional, TypedDict

from parsers import _MAX_EVIDENCE, _SERVICE_PORT_MAP


# ── Types ─────────────────────────────────────────────────────────────────────

class EntryPoint(TypedDict):
    type: str
    port: int
    protocol: str
    binary: Optional[str]
    interface: str
    source: str


class AttackPath(TypedDict):
    id: str
    title: str
    severity: str
    description: str
    entry_point: str
    steps: list[str]
    evidence: list[str]


# ── Constants ─────────────────────────────────────────────────────────────────

_PROTO_PORT_MAP = {
    "snmp":  (161,  "udp", "snmp"),
    "upnp":  (1900, "udp", "upnp"),
    "tr069": (7547, "tcp", "tr069"),
    "mqtt":  (1883, "tcp", "mqtt"),
}


# ── Entry point builder ───────────────────────────────────────────────────────

def build_entry_points(init: dict, web: dict, protocols: dict) -> list[EntryPoint]:
    eps: list[EntryPoint] = []
    seen = set()

    for svc in init["detected_services"]:
        if svc in _SERVICE_PORT_MAP:
            port, proto, svc_type = _SERVICE_PORT_MAP[svc]
            if (port, proto) not in seen:
                seen.add((port, proto))
                eps.append({
                    "type":      svc_type,
                    "port":      port,
                    "protocol":  proto,
                    "binary":    svc,
                    "interface": "unknown",
                    "source":    "init_scripts",
                })

    for port in web["inferred_ports"]:
        key = (port, "tcp")
        if key not in seen and (web["httpd_binaries"] or web["cgi_scripts"] or web["lua_handlers"]):
            seen.add(key)
            svc_type = "https" if port == 443 else "http"
            eps.append({
                "type":      svc_type,
                "port":      port,
                "protocol":  "tcp",
                "binary":    web["httpd_binaries"][0] if web["httpd_binaries"] else "httpd",
                "interface": "unknown",
                "source":    "web_server_config",
            })

    for proto, info in protocols.items():
        if info["present"] and proto in _PROTO_PORT_MAP:
            port, net_proto, ep_type = _PROTO_PORT_MAP[proto]
            if (port, net_proto) not in seen:
                seen.add((port, net_proto))
                eps.append({
                    "type":      ep_type,
                    "port":      port,
                    "protocol":  net_proto,
                    "binary":    None,
                    "interface": "unknown",
                    "source":    "protocols_config",
                })

    for port in init["explicit_ports"]:
        if not any(p == port for p, _ in seen):
            seen.add((port, "tcp"))
            eps.append({
                "type":      "unknown",
                "port":      port,
                "protocol":  "tcp",
                "binary":    None,
                "interface": "unknown",
                "source":    "init_script_port_binding",
            })

    return eps


# ── Attack path inferrers ─────────────────────────────────────────────────────

def _ap_telnet(entry_points: list, **_) -> AttackPath | None:
    if not any(ep["type"] == "telnet" for ep in entry_points):
        return None
    return {
        "id":          "ap-telnet",
        "title":       "Unencrypted Telnet Remote Shell",
        "severity":    "critical",
        "description": (
            "Telnet daemon exposes an unencrypted remote shell. "
            "All traffic is cleartext and trivially interceptable on the LAN."
        ),
        "entry_point": "telnet:23",
        "steps": [
            "Connect to port 23 (telnet) on the LAN interface",
            "Attempt login with default or hardcoded credentials",
            "Gain interactive shell (typically as root on embedded devices)",
        ],
        "evidence": ["init_scripts.txt: telnetd detected in network services"],
    }


def _ap_http_admin(entry_points: list, web: dict, **_) -> AttackPath | None:
    http_eps = [ep for ep in entry_points if ep["type"] in ("http", "https")]
    if not http_eps:
        return None
    evidence = [f"web_server_config: httpd binary found — {', '.join(web['httpd_binaries'][:3])}"]
    if web["cgi_scripts"]:
        evidence.append(f"web_interface.txt: {len(web['cgi_scripts'])} CGI scripts")
    if web["lua_handlers"]:
        evidence.append(f"web_interface.txt: {len(web['lua_handlers'])} Lua handlers")
    return {
        "id":          "ap-http-admin",
        "title":       "HTTP Admin Interface Exposure",
        "severity":    "high",
        "description": (
            "HTTP admin interface is reachable. "
            "CGI handlers and Lua scripts may accept unauthenticated or weakly authenticated requests."
        ),
        "entry_point": f"http:{http_eps[0]['port']}",
        "steps": [
            f"Access HTTP interface on port {http_eps[0]['port']}",
            "Enumerate endpoints: CGI scripts, Lua handlers, HTML forms",
            "Attempt authentication bypass or default credential login",
            "Exploit any unsanitized parameter to achieve RCE",
        ],
        "evidence": evidence,
    }


def _ap_cgi_injection(init: dict, web: dict, **_) -> AttackPath | None:
    if not (init["has_command_injection"] and (web["cgi_scripts"] or web["lua_handlers"])):
        return None
    return {
        "id":          "ap-cgi-injection",
        "title":       "Remote Code Execution via CGI/Lua Command Injection",
        "severity":    "critical",
        "description": (
            "Command injection patterns (eval, backtick, $()) found in init scripts "
            "alongside CGI or Lua HTTP handlers. Unsanitized HTTP parameters likely reach shell commands."
        ),
        "entry_point": "http",
        "steps": [
            "Identify CGI or Lua endpoints that accept user-controlled parameters",
            "Inject shell metacharacters: semicolon, backtick, $(), pipes",
            "Achieve remote command execution, typically as root",
        ],
        "evidence": [
            f"init_scripts.txt: injection patterns — {', '.join(init['injection_evidence'][:3])}",
            f"web_interface.txt: {len(web['cgi_scripts'])} CGI, {len(web['lua_handlers'])} Lua handlers",
        ],
    }


def _ap_default_creds(credentials: dict, init: dict, **_) -> AttackPath | None:
    if not (credentials["default_credentials"] or init["has_hardcoded_creds"]):
        return None
    evidence = (
        ["init_scripts.txt: hardcoded credential patterns in init scripts"] if init["has_hardcoded_creds"] else []
    ) + (
        [f"default_credentials.txt: {len(credentials['default_credentials'])} default credential references"]
        if credentials["default_credentials"] else []
    )
    return {
        "id":          "ap-default-creds",
        "title":       "Authentication Bypass via Default or Hardcoded Credentials",
        "severity":    "high",
        "description": (
            "Default or hardcoded credentials found in firmware. "
            "These frequently remain unchanged on deployed devices."
        ),
        "entry_point": "any authenticated service",
        "steps": [
            "Identify login interfaces: HTTP admin, SSH, Telnet",
            "Try common default credentials: admin/admin, admin/password, root/root",
            "If credentials match, gain privileged access",
        ],
        "evidence": evidence,
    }


def _ap_static_creds(credentials: dict, **_) -> AttackPath | None:
    if not credentials["hardcoded_in_configs"]:
        return None
    return {
        "id":          "ap-static-creds",
        "title":       "Credential Extraction from Firmware Image",
        "severity":    "high",
        "description": (
            "Passwords, API keys, or secrets hardcoded in configuration files. "
            "Extractable from any firmware image download without device access."
        ),
        "entry_point": "offline — firmware image",
        "steps": [
            "Obtain firmware image (vendor download page or TFTP/HTTP update URL)",
            "Extract and mount root filesystem with unsquashfs",
            "Read plaintext credentials from config files",
            "Authenticate to live device or cloud API using extracted credentials",
        ],
        "evidence": [f"credentials.txt: {len(credentials['hardcoded_in_configs'])} credential references in config files"],
    }


def _ap_tr069(protocols: dict, **_) -> AttackPath | None:
    if not protocols.get("tr069", {}).get("present"):
        return None
    return {
        "id":          "ap-tr069",
        "title":       "TR-069/CWMP Remote Management Exploitation",
        "severity":    "high",
        "description": (
            "TR-069 (CWMP) allows ISP remote management of the device. "
            "ACS impersonation or CWMP authentication weaknesses grant full remote control."
        ),
        "entry_point": "tr069:7547",
        "steps": [
            "Reach port 7547 from WAN (or perform ACS impersonation via DNS/MITM)",
            "Exploit weak CWMP authentication or unauthenticated endpoints",
            "Use SetParameterValues or Download RPC to push arbitrary config or firmware",
        ],
        "evidence": ["protocols.txt: TR-069/CWMP references found"],
    }


def _ap_upnp(protocols: dict, **_) -> AttackPath | None:
    if not protocols.get("upnp", {}).get("present"):
        return None
    return {
        "id":          "ap-upnp",
        "title":       "UPnP/SSDP Port Forwarding Abuse",
        "severity":    "medium",
        "description": (
            "UPnP on LAN allows unauthorized port forwarding rules to be added, "
            "potentially exposing internal services to the WAN."
        ),
        "entry_point": "upnp:1900/udp",
        "steps": [
            "Discover device via SSDP (port 1900 UDP multicast)",
            "Query IGD profile via SOAP",
            "Add port forwarding rules or exploit known UPnP implementation CVEs",
        ],
        "evidence": ["protocols.txt: UPnP/SSDP references found"],
    }


def _ap_snmp(protocols: dict, **_) -> AttackPath | None:
    if not protocols.get("snmp", {}).get("present"):
        return None
    return {
        "id":          "ap-snmp",
        "title":       "SNMP Community String Enumeration and Write Access",
        "severity":    "medium",
        "description": (
            "SNMP with predictable community strings allows full device enumeration. "
            "SNMPv2c write access enables configuration modification."
        ),
        "entry_point": "snmp:161/udp",
        "steps": [
            "Send SNMP GET to port 161 with community 'public' or 'private'",
            "Walk MIB tree to enumerate device configuration",
            "Use SNMP SET (if write community known) to modify running config",
        ],
        "evidence": [
            "protocols.txt: SNMP community string references",
        ] + protocols["snmp"]["evidence"][:2],
    }


def _ap_setuid(privesc: dict, **_) -> AttackPath | None:
    if not privesc["setuid_binaries"]:
        return None
    return {
        "id":          "ap-setuid",
        "title":       "Local Privilege Escalation via SetUID Binary",
        "severity":    "medium",
        "description": (
            "SetUID binaries execute as root regardless of the calling user. "
            "A vulnerability in any of these binaries allows escalation from web/daemon user to root."
        ),
        "entry_point": "local — requires initial code execution",
        "steps": [
            "Gain low-privilege code execution (e.g., RCE as www-data via web handler)",
            f"Target SetUID binary: {privesc['setuid_binaries'][0]}",
            "Exploit buffer overflow, path traversal, or argument injection",
            "Obtain root shell",
        ],
        "evidence": [f"setuid_binaries.txt: {len(privesc['setuid_binaries'])} SetUID binaries found"],
    }


def _ap_world_writable(privesc: dict, **_) -> AttackPath | None:
    ww = privesc.get("world_writable", {})
    ww_total = len(ww.get("files", [])) + len(ww.get("dirs", []))
    if not ww_total:
        return None
    return {
        "id":          "ap-world-writable",
        "title":       "Privilege Escalation via World-Writable Path",
        "severity":    "medium",
        "description": (
            "World-writable files or directories allow a low-privilege process to "
            "inject content that a privileged process later reads or executes."
        ),
        "entry_point": "local — requires initial code execution",
        "steps": [
            "Gain low-privilege code execution",
            "Write malicious payload to world-writable file or directory",
            "Wait for privileged daemon to execute or read the modified path",
        ],
        "evidence": [f"world_writable.txt: {ww_total} world-writable files/directories"],
    }


def _ap_cert_extraction(certs: dict, **_) -> AttackPath | None:
    if not (certs["files"] or certs["embedded_in_binaries"]):
        return None
    return {
        "id":          "ap-cert-extraction",
        "title":       "TLS Private Key Extraction for MITM",
        "severity":    "high",
        "description": (
            "SSL/TLS private keys or certificates found in firmware. "
            "Extracted keys enable man-in-the-middle attacks against the device or its cloud connections."
        ),
        "entry_point": "offline — firmware image",
        "steps": [
            "Extract private key from firmware filesystem (.pem, .key files)",
            "Set up MITM proxy presenting the extracted certificate",
            "Decrypt captured TLS traffic or impersonate the device to its cloud backend",
        ],
        "evidence": [
            f"certificates_keys.txt: {len(certs['files'])} cert/key files found",
        ] + (["certificates_keys.txt: private key material embedded in binary"] if certs["embedded_in_binaries"] else []),
    }


def _ap_weak_crypto(weak_crypto: list, **_) -> AttackPath | None:
    if not weak_crypto:
        return None
    return {
        "id":          "ap-weak-crypto",
        "title":       "Cryptographic Weakness (MD5/DES/RC4/ECB)",
        "severity":    "medium",
        "description": (
            "Broken cryptographic algorithms found in firmware. "
            "MD5 is collision-prone, DES/RC4 are broken, ECB mode leaks patterns."
        ),
        "entry_point": "offline or network",
        "steps": [
            "Capture ciphertext or hash from device (via SNMP, config backup, or MITM)",
            "Apply known attack: MD5 collision, RC4 BEAST/RC4 biases, ECB plaintext recovery",
            "Recover plaintext, forge authentication token, or bypass integrity check",
        ],
        "evidence": [f"weak_crypto.txt: {len(weak_crypto)} weak crypto contexts found"],
    }


def _ap_debug(debug: list, **_) -> AttackPath | None:
    debug_items = [item for f in debug for item in f.get("items", [])]
    if not debug_items:
        return None
    return {
        "id":          "ap-debug",
        "title":       "Debug/Factory Interface Access",
        "severity":    "medium",
        "description": (
            "Debug, factory, or diagnostic artifacts found in firmware. "
            "These may expose undocumented commands, reduced authentication, or UART shell access."
        ),
        "entry_point": "local (UART) or network (undocumented endpoint)",
        "steps": [
            "Connect to UART console (physical access) or find debug HTTP parameter",
            "Trigger factory/diagnostic mode to bypass authentication",
            "Access privileged shell or extract runtime secrets via debug output",
        ],
        "evidence": [f"debug_artifacts.txt: {len(debug_items)} debug/factory/test artifacts"],
    }


def _ap_update_mitm(credentials: dict, **_) -> AttackPath | None:
    if not credentials["cloud_endpoints"]:
        return None
    return {
        "id":          "ap-update-mitm",
        "title":       "Malicious Firmware Delivery via Update MITM",
        "severity":    "medium",
        "description": (
            "Hardcoded firmware update URLs found. "
            "If update integrity verification is absent or uses a weak hash, "
            "a MITM attacker can serve malicious firmware."
        ),
        "entry_point": "network — update channel",
        "steps": [
            "Intercept firmware update request via DNS spoofing or MITM on update URL",
            "Serve crafted firmware that passes signature/hash check (or bypasses it)",
            "Device installs attacker-controlled firmware on next update cycle",
        ],
        "evidence": [f"credentials.txt: {len(credentials['cloud_endpoints'])} cloud/update URLs hardcoded"],
    }


def _ap_cert_issues(certificate_issues: list, **_) -> AttackPath | None:
    if not certificate_issues:
        return None

    expired  = [c for c in certificate_issues if "expired"      in c.get("flags", [])]
    weak_key = [c for c in certificate_issues if any("weak-key" in f for f in c.get("flags", []))]
    self_sig = [c for c in certificate_issues if "self-signed"  in c.get("flags", [])]

    if expired or weak_key:
        severity = "high"
        parts = []
        if expired:
            parts.append(f"{len(expired)} expired certificate{'s' if len(expired) != 1 else ''}")
        if weak_key:
            parts.append(f"{len(weak_key)} certificate{'s' if len(weak_key) != 1 else ''} with weak RSA key (≤1024-bit)")
        if self_sig:
            parts.append(f"{len(self_sig)} self-signed")
        description = (
            ", ".join(parts) + " found in firmware. "
            "Expired or cryptographically weak certificates cannot protect TLS sessions "
            "and enable man-in-the-middle attacks."
        )
        title = "Weak or Expired TLS Certificates"
    else:
        severity = "medium"
        title = "Self-Signed TLS Certificates"
        description = (
            f"{len(self_sig)} self-signed certificate{'s' if len(self_sig) != 1 else ''} found. "
            "Without CA chain validation, an attacker can substitute a rogue certificate "
            "and clients may not detect the impersonation."
        )

    evidence = [
        f"certificate_issues.txt: {len(certificate_issues)} certificate(s) with security issues",
    ] + [
        f"  {c['file']}: {', '.join(c.get('flags', []))}" for c in certificate_issues[:_MAX_EVIDENCE]
    ]

    return {
        "id":          "ap-cert-issues",
        "title":       title,
        "severity":    severity,
        "description": description,
        "entry_point": "network — TLS sessions / offline firmware",
        "steps": [
            "Identify certificate files in firmware filesystem (.pem, .crt, .der)",
            "Verify certificates are expired, self-signed, or have weak keys (RSA ≤1024-bit)",
            "Present a forged or substituted certificate to exploit client trust",
            "Decrypt or intercept TLS traffic between device and cloud / update server",
        ],
        "evidence": evidence,
    }


def _ap_memory_unsafe_binaries(
    dangerous_functions: list,
    entry_points: list,
    init: dict,
    **_,
) -> AttackPath | None:
    if not dangerous_functions:
        return None

    # Collect binary basenames that are network-reachable
    reachable: set[str] = set()
    for ep in entry_points:
        if ep.get("binary"):
            reachable.add(ep["binary"].split("/")[-1])
    for svc in init.get("detected_services", []):
        reachable.add(svc)

    exposed = [df for df in dangerous_functions if df["binary"].split("/")[-1] in reachable]

    if exposed:
        funcs = sorted({fn for df in exposed for fn in df["functions"]})
        n = len(exposed)
        return {
            "id":          "ap-memory-unsafe",
            "title":       "Memory-Unsafe Functions in Network-Reachable Binary",
            "severity":    "high",
            "description": (
                f"{n} network-reachable {'binary' if n == 1 else 'binaries'} "
                f"import dangerous libc functions ({', '.join(funcs[:5])}). "
                "Buffer overflows in network-facing code are directly exploitable for RCE."
            ),
            "entry_point": f"network — {', '.join(df['binary'].split('/')[-1] for df in exposed[:3])}",
            "steps": [
                "Send crafted input to the exposed network service",
                "Trigger buffer overflow in unsafe function (gets, strcpy, sprintf, etc.)",
                "Overwrite return address or function pointer to redirect execution",
                "Achieve remote code execution, typically as root on embedded devices",
            ],
            "evidence": [
                f"dangerous_functions.txt: {n} network-reachable "
                f"{'binary' if n == 1 else 'binaries'} with unsafe imports",
            ] + [f"  {df['binary']}: {', '.join(df['functions'])}" for df in exposed[:_MAX_EVIDENCE]],
        }

    n = len(dangerous_functions)
    all_funcs = sorted({fn for df in dangerous_functions for fn in df["functions"]})
    return {
        "id":          "ap-memory-unsafe",
        "title":       "Memory-Unsafe Function Usage (Post-Exploitation Aid)",
        "severity":    "medium",
        "description": (
            f"{n} {'binary' if n == 1 else 'binaries'} "
            f"import dangerous libc functions ({', '.join(all_funcs[:5])}). "
            "Simplifies local privilege escalation — no heap grooming or ROP chains needed."
        ),
        "entry_point": "local — requires initial code execution",
        "steps": [
            "Gain initial code execution (e.g. command injection, CGI, or default credentials)",
            "Identify a SetUID or privileged binary that uses unsafe functions",
            "Craft input to overflow a buffer and hijack control flow",
            "Escalate to root",
        ],
        "evidence": [
            f"dangerous_functions.txt: {n} {'binary' if n == 1 else 'binaries'} with unsafe imports",
        ] + [f"  {df['binary']}: {', '.join(df['functions'])}" for df in dangerous_functions[:_MAX_EVIDENCE]],
    }


def _ap_vendor_backdoor(init: dict, **_) -> AttackPath | None:
    if not init["vendor_services"]:
        return None
    return {
        "id":          "ap-vendor-backdoor",
        "title":       "Vendor-Specific Service Attack Surface (TP-Link)",
        "severity":    "high",
        "description": (
            "TP-Link proprietary services (tdpServer, tddp, omcid, cwmp) found in init scripts. "
            "These vendor daemons have historically contained undocumented commands and authentication bypasses."
        ),
        "entry_point": "network — vendor daemon port",
        "steps": [
            "Identify vendor daemon port via protocol fingerprinting",
            "Send crafted vendor protocol packets (TDDP, TDP, OMCI)",
            "Exploit known CVEs or undocumented command execution paths",
        ],
        "evidence": [f"init_scripts.txt: vendor services — {', '.join(init['vendor_services'][:_MAX_EVIDENCE])}"],
    }


_CRITICAL_TLS_ISSUES = {"SSLv2 enabled"}
_HIGH_TLS_ISSUES     = {"SSLv3 enabled", "RC4 cipher", "NULL cipher", "EXPORT cipher", "anonymous DH cipher"}


def _ap_tls_config(tls_config_issues: list, **_) -> AttackPath | None:
    if not tls_config_issues:
        return None

    issues_found = {f["issue"] for f in tls_config_issues}

    if issues_found & _CRITICAL_TLS_ISSUES:
        severity = "critical"
    elif issues_found & _HIGH_TLS_ISSUES:
        severity = "high"
    else:
        severity = "medium"

    unique_issues = sorted(issues_found)
    affected_files = sorted({f["file"] for f in tls_config_issues})

    description = (
        f"{len(tls_config_issues)} weak TLS/SSL directive(s) found across "
        f"{len(affected_files)} config file(s): {', '.join(unique_issues[:4])}. "
        "Downgrade attacks and cipher exploits allow traffic decryption or MITM."
    )

    evidence = [
        f"tls_config_issues.txt: {len(tls_config_issues)} weak TLS directive(s) "
        f"in {len(affected_files)} file(s)",
    ] + [
        f"  {f['file']}:{f['line']} — {f['issue']}" for f in tls_config_issues[:_MAX_EVIDENCE]
    ]

    return {
        "id":          "ap-tls-config",
        "title":       "Weak SSL/TLS Protocol or Cipher Configuration",
        "severity":    severity,
        "description": description,
        "entry_point": "network — TLS sessions",
        "steps": [
            "Identify TLS endpoint from web or protocol entry points",
            "Initiate TLS handshake advertising only the weak protocol/cipher (SSLv2, SSLv3, RC4, EXPORT)",
            "Server accepts the downgraded session (DROWN / POODLE / FREAK / LOGJAM)",
            "Decrypt session traffic or forge authentication tokens",
        ],
        "evidence": evidence,
    }


def _ap_inetd(inetd: dict, **_) -> AttackPath | None:
    findings = inetd.get("findings", [])
    if not findings:
        return None
    critical = [f for f in findings if f["severity"] == "critical"]
    high     = [f for f in findings if f["severity"] == "high"]
    if not (critical or high):
        return None
    severity = "critical" if critical else "high"
    worst    = critical if critical else high
    services = sorted({f["service"] for f in findings})
    evidence = [
        f"inetd.txt: {len(findings)} dangerous service(s) in inetd/xinetd config",
    ] + [
        f"  {f['file']}: {f['service']} ({f['severity']}) — {f['note']}"
        for f in findings[:_MAX_EVIDENCE]
    ]
    return {
        "id":          "ap-inetd",
        "title":       f"Dangerous Network Service via inetd/xinetd ({', '.join(services[:3])})",
        "severity":    severity,
        "description": (
            f"inetd/xinetd registers {len(findings)} dangerous network service(s) "
            f"({', '.join(services)}). "
            "These legacy services are unencrypted, have no rate limiting, "
            "and often grant direct shell access."
        ),
        "entry_point": f"network — inetd ({worst[0]['service']})",
        "steps": [
            "Identify active inetd/xinetd service ports (telnet:23, ftp:21, rsh:514, etc.)",
            "Connect to the service port on the LAN interface",
            "Attempt login with default or hardcoded credentials",
            "Gain direct shell or file access (legacy services typically run as root on embedded devices)",
        ],
        "evidence": evidence,
    }


def _ap_sshd_config(sshd_config: dict, **_) -> AttackPath | None:
    findings = sshd_config.get("findings", [])
    if not findings:
        return None
    critical = [f for f in findings if f["severity"] == "critical"]
    high     = [f for f in findings if f["severity"] == "high"]
    if not (critical or high):
        return None
    severity = "critical" if critical else "high"
    worst    = critical if critical else high
    directives = [f"{f['directive']} = {f['value']}" for f in worst[:3]]
    evidence = [
        f"sshd_config.txt: {len(findings)} dangerous SSH directive(s)",
    ] + [
        f"  {f['file']}:{f['line']} — {f['directive']} = {f['value']} ({f['note']})"
        for f in findings[:_MAX_EVIDENCE]
    ]
    return {
        "id":          "ap-sshd-config",
        "title":       "Weak SSH Server Configuration",
        "severity":    severity,
        "description": (
            f"SSH server has {len(findings)} dangerous configuration directive(s): "
            f"{', '.join(directives[:3])}. "
            "Insecure settings enable brute-force attacks, direct root login, "
            "or credential interception."
        ),
        "entry_point": "ssh:22",
        "steps": [
            "Connect to SSH service on port 22",
            "Exploit dangerous directive (e.g., PermitRootLogin yes → brute-force root password)",
            "If PasswordAuthentication yes, perform credential stuffing or dictionary attack",
            "Gain SSH shell access, typically as root",
        ],
        "evidence": evidence,
    }


def _ap_sensitive_permissions(sensitive_permissions: dict, **_) -> AttackPath | None:
    findings = sensitive_permissions.get("findings", [])
    if not findings:
        return None
    critical = [f for f in findings if f["severity"] == "critical"]
    high     = [f for f in findings if f["severity"] == "high"]
    if not (critical or high):
        return None
    severity = "critical" if critical else "high"
    worst    = critical if critical else high
    files    = [f["file"] for f in worst[:2]]
    evidence = [
        f"sensitive_permissions.txt: {len(findings)} permission issue(s) on sensitive files",
    ] + [
        f"  {f['file']} ({f.get('mode', '?')}) — {f['note']}"
        for f in findings[:_MAX_EVIDENCE]
    ]
    return {
        "id":          "ap-sensitive-permissions",
        "title":       "Sensitive File Readable by Unprivileged User",
        "severity":    severity,
        "description": (
            f"{len(worst)} sensitive file(s) have overly permissive modes "
            f"({', '.join(files)}). "
            "World-readable credential or key files allow any local process to "
            "extract secrets without privilege escalation."
        ),
        "entry_point": "local — requires initial code execution",
        "steps": [
            "Gain low-privilege code execution (e.g., command injection via CGI)",
            f"Read sensitive file directly: {worst[0]['file']}",
            "Extract password hashes, SSH private keys, or API credentials",
            "Use extracted material for lateral movement or authentication bypass",
        ],
        "evidence": evidence,
    }


def _ap_rpath(rpath: dict, **_) -> AttackPath | None:
    unsafe = rpath.get("unsafe", [])
    if not unsafe:
        return None
    example  = unsafe[0]
    bin_name = example.get("binary", "").split("/")[-1]
    evidence = [
        f"rpath.json: {len(unsafe)} binary(s) with unsafe RPATH/RUNPATH",
    ] + [
        f"  {e['binary']}: unsafe paths — {', '.join(e.get('unsafe_paths', []))}"
        for e in unsafe[:_MAX_EVIDENCE]
    ]
    return {
        "id":          "ap-rpath",
        "title":       "Library Hijacking via Unsafe RPATH/RUNPATH",
        "severity":    "medium",
        "description": (
            f"{len(unsafe)} binary(s) have relative or world-writable RPATH/RUNPATH entries. "
            "A low-privilege attacker can plant a malicious shared library in the search path "
            "to hijack execution when the binary runs."
        ),
        "entry_point": "local — requires write access to RPATH directory",
        "steps": [
            f"Identify binary with unsafe RPATH: {bin_name}",
            "Plant a malicious shared library in the relative or world-writable RPATH directory",
            "Wait for the binary to be invoked (daemon restart, scheduled task, or user action)",
            "Library is loaded and executes attacker code with the binary's privileges",
        ],
        "evidence": evidence,
    }


def _ap_sysctl(sysctl: dict, **_) -> AttackPath | None:
    findings = sysctl.get("findings", [])
    if not findings:
        return None
    critical = [f for f in findings if f["severity"] == "critical"]
    high     = [f for f in findings if f["severity"] == "high"]
    if not (critical or high):
        return None
    severity = "high" if critical else "medium"
    worst    = critical if critical else high
    params   = [f["parameter"] for f in worst[:3]]
    absent   = [f for f in findings if f.get("type") == "absent"]
    explicit = [f for f in findings if f.get("type") == "explicit"]
    evidence = [
        f"sysctl.txt: {len(findings)} hardening issue(s) "
        f"({len(explicit)} explicit insecure, {len(absent)} absent)",
    ] + [
        f"  {f.get('file', '[not configured]')}: {f['parameter']} — {f['note']}"
        for f in findings[:_MAX_EVIDENCE]
    ]
    return {
        "id":          "ap-sysctl",
        "title":       "Missing Kernel Hardening Reduces Exploit Mitigation",
        "severity":    severity,
        "description": (
            f"Kernel hardening parameters are missing or set to insecure values "
            f"({', '.join(params[:3])}). "
            "Absent mitigations (ASLR, stack protection, etc.) simplify reliable "
            "exploitation of memory corruption vulnerabilities."
        ),
        "entry_point": "local — amplifies memory corruption attack paths",
        "steps": [
            "Exploit a memory corruption vulnerability in a network-facing or privileged binary",
            f"Absence of {params[0]} removes a mitigation that would otherwise require bypassing",
            "Develop a reliable exploit without needing ASLR bypass, ROP chains, or heap hardening",
            "Achieve arbitrary code execution or privilege escalation",
        ],
        "evidence": evidence,
    }


_ATTACK_PATH_INFERRERS = [
    _ap_telnet,
    _ap_http_admin,
    _ap_cgi_injection,
    _ap_default_creds,
    _ap_static_creds,
    _ap_tr069,
    _ap_upnp,
    _ap_snmp,
    _ap_setuid,
    _ap_world_writable,
    _ap_cert_extraction,
    _ap_cert_issues,
    _ap_tls_config,
    _ap_weak_crypto,
    _ap_debug,
    _ap_update_mitm,
    _ap_vendor_backdoor,
    _ap_memory_unsafe_binaries,
    _ap_inetd,
    _ap_sshd_config,
    _ap_sensitive_permissions,
    _ap_rpath,
    _ap_sysctl,
]


def infer_attack_paths(
    entry_points: list,
    init: dict,
    web: dict,
    users: list,
    credentials: dict,
    privesc: dict,
    protocols: dict,
    weak_crypto: list,
    debug: list,
    certs: dict,
    dangerous_functions: list | None = None,
    certificate_issues: list | None = None,
    tls_config_issues: list | None = None,
    inetd: dict | None = None,
    sysctl: dict | None = None,
    sshd_config: dict | None = None,
    sensitive_permissions: dict | None = None,
    rpath: dict | None = None,
) -> list[AttackPath]:
    ctx = dict(
        entry_points=entry_points, init=init, web=web, users=users,
        credentials=credentials, privesc=privesc, protocols=protocols,
        weak_crypto=weak_crypto, debug=debug, certs=certs,
        dangerous_functions=dangerous_functions or [],
        certificate_issues=certificate_issues or [],
        tls_config_issues=tls_config_issues or [],
        inetd=inetd or {"config_files": [], "services": [], "findings": [], "summary": {}},
        sysctl=sysctl or {"config_files": [], "findings": [], "summary": {}},
        sshd_config=sshd_config or {"config_files": [], "findings": [], "summary": {}},
        sensitive_permissions=sensitive_permissions or {"findings": [], "summary": {}},
        rpath=rpath or {"total_with_rpath": 0, "unsafe_count": 0, "unsafe": [], "all": []},
    )
    return [p for fn in _ATTACK_PATH_INFERRERS if (p := fn(**ctx)) is not None]
