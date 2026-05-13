import json

from .context import AnalysisContext, multi_section_file

_MAX_EVIDENCE = 5


def analyze_protocols(ctx: AnalysisContext):
    json_file = ctx.out_dir / "protocols.json"
    captured = multi_section_file([
        ("SNMP Community Strings",
         ["grep", "-Ei", "community|snmpd|public|private"] + ctx.configs),
        ("UPnP / SSDP",
         ["grep", "-Ei", "upnp|ssdp|igd"] + ctx.configs),
        ("TR-069 / CWMP",
         ["grep", "-Ei", "cwmp|tr069|acs.url|inform|tr_069"] + ctx.configs),
        ("MQTT",
         ["grep", "-Ei", "mqtt|broker"] + ctx.configs),
    ], ctx.out_dir / "protocols.txt", "protocols.txt")

    proto_map = {
        "snmp":  "SNMP Community Strings",
        "upnp":  "UPnP / SSDP",
        "tr069": "TR-069 / CWMP",
        "mqtt":  "MQTT",
    }
    result = {}
    for proto, title in proto_map.items():
        lines = captured.get(title, [])
        result[proto] = {"present": bool(lines), "evidence": lines[:_MAX_EVIDENCE]}
    json_file.write_text(json.dumps(result, indent=2))


def analyze_interface_binding(ctx: AnalysisContext):
    multi_section_file([
        ("Interface References (LAN/WAN)",
         ["grep", "-Ei", "br-lan|eth0|eth1|wan|pppoe|interface"] + ctx.configs),
        ("Any-Interface Bindings (0.0.0.0)",
         ["grep", "-E", r"0\.0\.0\.0"] + ctx.configs),
        ("Loopback Only (127.0.0.1)",
         ["grep", "-E", r"127\.0\.0\.1"] + ctx.configs),
    ], ctx.out_dir / "interface_binding.txt", "interface_binding.txt")
