# -*- coding: utf-8 -*-
"""
Blue Team Threat Analysis, Incident Forensics & Hardening Advisory Engine.

Provides deep technical root-cause analysis, passive transport and socket-level flow profiling,
immediate containment enforcement commands, and production-grade kernel/firewall
hardening playbooks for all 13 canonical DDoS/DoS attack vectors.

Strictly authoritative, professional cybersecurity terminology without marketing buzzwords.
"""
from typing import Dict, Any, Optional, List


def infer_host_fingerprint(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform passive transport and socket-level flow profiling.

    NOTE ON OS FINGERPRINTING:
    Raw packet IP TTL is NOT present in the 77-feature CICFlowMeter flow representation.
    Therefore, specific operating system claims (e.g. Windows vs Linux) are omitted
    to prevent speculative forensic claims. Analysis is strictly grounded in genuine
    captured transport metrics: Initial Window Size, packet directional ratio,
    segment sizing, and TCP flag distribution.
    """
    fwd_init_win = float(features.get("Init Fwd Win Byts") or features.get("Init_Win_bytes_forward") or 0.0)
    bwd_init_win = float(features.get("Init Bwd Win Byts") or features.get("Init_Win_bytes_backward") or 0.0)
    bwd_pkts_s = float(features.get("Bwd Pkts/s") or features.get("Bwd Packets/s") or 0.0)
    fwd_pkts_s = float(features.get("Fwd Pkts/s") or features.get("Fwd Packets/s") or 0.0)
    pkt_len_mean = float(features.get("Pkt Len Mean") or features.get("Average Packet Size") or 0.0)
    syn_flag_count = float(features.get("SYN Flag Cnt") or features.get("SYN Flag Count") or 0.0)
    ack_flag_count = float(features.get("ACK Flag Cnt") or features.get("ACK Flag Count") or 0.0)

    # Transport Socket Profiling
    if fwd_init_win == 0 and syn_flag_count > 0:
        socket_profile = "Raw Socket Frame Injection (Unbuffered / Tool-Generated)"
        stack_desc = (
            "Custom raw socket packet synthesizer (e.g. hping3, scapy, raw C AF_INET socket). "
            "Zero TCP socket receive buffer allocated by client kernel."
        )
    elif fwd_init_win > 0:
        socket_profile = f"Standard Kernel Buffered TCP Socket (Init Window: {int(fwd_init_win)} bytes)"
        stack_desc = "Standard client socket with operating system kernel receive window buffering."
    else:
        socket_profile = "Connectionless UDP / Non-Windowed Protocol"
        stack_desc = "Datagram transport layer without connection window negotiation."

    # Empirical transport-layer anomalies
    anomalies = []
    if fwd_pkts_s > 1000 and bwd_pkts_s == 0:
        anomalies.append("Strictly unidirectional traffic: 100% forward packet surge with 0 backward completions.")
    if syn_flag_count > 0 and ack_flag_count == 0:
        anomalies.append("Pure SYN handshake flood: No ACK/RST packets observed; client refuses to complete handshake.")
    if pkt_len_mean <= 6.0 and syn_flag_count > 0:
        anomalies.append("Minimal header footprint: Synthetic 0-byte or 6-byte TCP payload designed solely for socket starvation.")
    elif pkt_len_mean > 1000:
        anomalies.append(f"Oversized datagram volume: Average packet size {pkt_len_mean:.1f} bytes indicating volumetric pipe exhaustion.")

    return {
        "socket_profile": socket_profile,
        "stack_description": stack_desc,
        "initial_window_bytes": int(fwd_init_win),
        "anomalies": anomalies,
    }


def get_attack_profile(vector: str, attacker_ip: str = "192.168.1.100", victim_ip: str = "10.0.0.1") -> Dict[str, Any]:
    """
    Return comprehensive Blue Team threat intelligence, attack mechanics,
    immediate containment actions, and production-grade hardening playbooks
    for the specified canonical attack vector.
    """
    normalized_vec = vector.strip().replace(" ", "").replace("-", "_").lower()

    # Default profile for unknown/generic
    profile = {
        "name": f"{vector} Attack",
        "category": "Volumetric / Protocol Denial-of-Service",
        "severity": "HIGH",
        "incident_narrative": (
            f"Anomalous traffic flood originating from host {attacker_ip} targeting victim {victim_ip}. "
            "Flow characteristics exhibit severe packet rate asymmetry and statistical deviation from normal baseline."
        ),
        "attack_mechanics": (
            "Attacker transmits high-rate request datagrams to saturate host socket buffers or link bandwidth, "
            "causing legitimate inbound client connections to time out."
        ),
        "blast_radius": "Service degradation, potential line-rate saturation, and elevated host packet processing latency.",
        "containment": {
            "firewall_rule": f"iptables -I INPUT -s {attacker_ip} -j DROP",
            "sdn_flowmod": f"OFPFC_ADD priority=65535 match(ipv4_src={attacker_ip}) instructions=[] (DROP)",
            "docker_isolation": f"docker network disconnect bridge {victim_ip} || iptables -A OUTPUT -d {victim_ip} -j DROP",
        },
        "hardening_advisory": {
            "kernel_parameters": [
                "sysctl -w net.core.netdev_max_backlog=10000",
                "sysctl -w net.core.rmem_max=16777216",
            ],
            "firewall_rules": [
                f"iptables -A INPUT -s {attacker_ip} -j DROP",
                "iptables -A INPUT -m limit --limit 500/s --limit-burst 1000 -j ACCEPT",
            ],
            "network_measures": [
                "Deploy upstream BGP FlowSpec filtering rules.",
                "Verify Unicast Reverse Path Forwarding (uRPF / BCP 38) on upstream edge interfaces.",
            ],
        },
    }

    if "syn" in normalized_vec:
        profile = {
            "name": "TCP SYN Flood (Connection State Exhaustion)",
            "category": "Transport-Layer Protocol Exhaustion",
            "severity": "CRITICAL",
            "incident_narrative": (
                f"Host {attacker_ip} is transmitting an unacknowledged TCP SYN packet storm targeting {victim_ip}. "
                "The source sends SYN connection requests without completing the 3-way handshake (0 ACK response). "
                "This forces the victim operating system to maintain half-open socket states in the kernel `SYN_RECV` backlog queue, "
                "rapidly exhausting connection tables until legitimate client handshakes are dropped."
            ),
            "attack_mechanics": (
                "Each TCP SYN allocates a Transmission Control Block (TCB) in kernel memory (~280 bytes) and binds an entry in the "
                "`listen()` connection backlog. Because the attacker never sends the final ACK, half-open sockets linger until "
                "the `tcp_synack_retries` timer expires (often 30-120 seconds), blocking all new inbound connections."
            ),
            "blast_radius": "Complete outage for web and application servers listening on target TCP ports (e.g. 80, 443, 8080).",
            "containment": {
                "firewall_rule": f"iptables -I INPUT -s {attacker_ip} -p tcp --syn -j DROP",
                "sdn_flowmod": f"OFPFC_ADD priority=65535 match(eth_type=0x0800, ip_proto=6, ipv4_src={attacker_ip}) instructions=[] (DROP)",
                "docker_isolation": f"docker exec <container> iptables -I INPUT -s {attacker_ip} -p tcp --syn -j DROP",
            },
            "hardening_advisory": {
                "kernel_parameters": [
                    "sysctl -w net.ipv4.tcp_syncookies=1  # Cryptographically encodes handshake in sequence number; eliminates backlog memory exhaustion",
                    "sysctl -w net.ipv4.tcp_max_syn_backlog=8192  # Expands half-open connection table capacity from default 1024 to 8192",
                    "sysctl -w net.ipv4.tcp_synack_retries=2  # Drops dead half-open connections after 2 retries (~7s) instead of default 5 (~63s)",
                    "sysctl -w net.ipv4.tcp_fin_timeout=15  # Reclaims sockets in FIN-WAIT-2 state faster",
                ],
                "firewall_rules": [
                    "iptables -N SYN_FLOOD_PROTECT",
                    "iptables -A INPUT -p tcp --syn -j SYN_FLOOD_PROTECT",
                    "iptables -A SYN_FLOOD_PROTECT -m limit --limit 50/s --limit-burst 100 -j RETURN",
                    "iptables -A SYN_FLOOD_PROTECT -j DROP  # Drop excess SYN requests exceeding burst threshold",
                ],
                "network_measures": [
                    "Enforce Unicast Reverse Path Forwarding (uRPF / BCP 38) at border routers (`sysctl -w net.ipv4.conf.all.rp_filter=1`) to drop spoofed IP sources.",
                    "Deploy SYN Proxying on perimeter load balancers / reverse proxies (e.g. HAProxy, Cloudflare, F5 Big-IP) to validate handshakes before forwarding to origin.",
                ],
            },
        }

    elif "ntp" in normalized_vec:
        profile = {
            "name": "NTP Monlist Reflection-Amplification Flood",
            "category": "UDP Reflection & Volumetric Amplification",
            "severity": "CRITICAL",
            "incident_narrative": (
                f"Attacker is exploiting open Network Time Protocol (NTP) servers to bounce amplified UDP traffic onto {victim_ip}. "
                f"Source {attacker_ip} or reflection relays are transmitting high-volume UDP port 123 datagrams. "
                "The `monlist` administrative query causes vulnerable NTP daemons to return up to 600 past client IP addresses, "
                "achieving a massive ~556x bandwidth multiplication."
            ),
            "attack_mechanics": (
                "A single 234-byte `monlist` UDP request query spoofed with victim's source IP generates multiple 468-byte response datagrams "
                "totaling up to 130,000 bytes. This floods ingress transit pipes without requiring significant attacker outbound bandwidth."
            ),
            "blast_radius": "Ingress link saturation, network interface card (NIC) ring buffer overflow, and severe line-rate packet drops.",
            "containment": {
                "firewall_rule": f"iptables -I INPUT -s {attacker_ip} -p udp --sport 123 -j DROP",
                "sdn_flowmod": f"OFPFC_ADD priority=65535 match(eth_type=0x0800, ip_proto=17, udp_src=123) instructions=[] (DROP)",
                "docker_isolation": f"iptables -A FORWARD -p udp --sport 123 -d {victim_ip} -j DROP",
            },
            "hardening_advisory": {
                "kernel_parameters": [
                    "sysctl -w net.core.netdev_max_backlog=10000  # Prevents packet drops at kernel driver layer during volumetric bursts",
                    "sysctl -w net.core.rmem_max=16777216  # Allocates 16MB receive buffers for UDP sockets",
                ],
                "firewall_rules": [
                    "iptables -A INPUT -p udp --sport 123 -m length --length 400:65535 -j DROP  # Drop oversized NTP monlist response packets",
                    "iptables -A INPUT -p udp --dport 123 -m limit --limit 20/s -j ACCEPT  # Strict rate limit on NTP time synchronization",
                ],
                "network_measures": [
                    "Add `disable monitor` in `/etc/ntp.conf` and upgrade to Chrony or NTP 4.2.8p7+ where monlist is removed.",
                    "Request upstream ISP BGP FlowSpec rule: `match protocol udp port 123 rate-limit 100k` to drop reflected traffic at upstream transit peering.",
                ],
            },
        }

    elif "dns" in normalized_vec:
        profile = {
            "name": "DNS Open Resolver Reflection-Amplification",
            "category": "UDP Reflection & Volumetric Amplification",
            "severity": "CRITICAL",
            "incident_narrative": (
                f"Attacker is weaponizing misconfigured public recursive DNS resolvers against {victim_ip}. "
                "High-frequency UDP port 53 responses (such as DNSSEC-signed `ANY` or `TXT` queries) are flooding the network, "
                "achieving a 50x-70x bandwidth amplification factor against the target."
            ),
            "attack_mechanics": (
                "Attacker generates small 60-byte DNS requests with EDNS0 extensions specifying `ANY` or large root zones, with the victim's "
                "IP spoofed as the query source. Open resolvers reply with 3,000+ byte answers, saturating customer edge transit bandwidth."
            ),
            "blast_radius": "Boundary firewall state exhaustion, upstream bandwidth saturation, and loss of local DNS resolution availability.",
            "containment": {
                "firewall_rule": f"iptables -I INPUT -s {attacker_ip} -p udp --sport 53 -j DROP",
                "sdn_flowmod": f"OFPFC_ADD priority=65535 match(eth_type=0x0800, ip_proto=17, udp_src=53) instructions=[] (DROP)",
                "docker_isolation": f"iptables -A FORWARD -p udp --sport 53 -d {victim_ip} -j DROP",
            },
            "hardening_advisory": {
                "kernel_parameters": [
                    "sysctl -w net.ipv4.udp_rmem_min=16384",
                    "sysctl -w net.core.rmem_default=262144",
                ],
                "firewall_rules": [
                    "iptables -A INPUT -p udp --sport 53 -m length --length 1500:65535 -j DROP  # Drop fragmented/oversized reflection answers",
                    "iptables -A INPUT -p udp --dport 53 -m string --hex-string '|0000ff0001|' --algo bm -j DROP  # Filter ANY queries",
                ],
                "network_measures": [
                    "Enforce Response Rate Limiting (RRL) across all internal authoritative nameservers (`rate-limit { responses-per-second 5; };`).",
                    "Disable open recursive lookup on public DNS servers (`recursion no;` in BIND `named.conf`).",
                ],
            },
        }

    elif "ldap" in normalized_vec:
        profile = {
            "name": "CLDAP Connectionless Reflection Flood",
            "category": "Directory Services Protocol Abuse",
            "severity": "CRITICAL",
            "incident_narrative": (
                f"Connectionless LDAP (CLDAP on UDP port 389) reflection attack targeting {victim_ip}. "
                "Attacker sends `searchRequest` queries with spoofed source IPs to publicly accessible Active Directory Domain Controllers, "
                "generating ~55x amplified rootDSE directory responses."
            ),
            "attack_mechanics": (
                "A single 50-byte CLDAP search request induces vulnerable Windows Domain Controllers to transmit 3,000+ bytes of domain and "
                "forest schema metadata, overloading the victim's ingress pipes."
            ),
            "blast_radius": "Ingress saturation and degradation of enterprise Active Directory domain authentication infrastructure.",
            "containment": {
                "firewall_rule": f"iptables -I INPUT -s {attacker_ip} -p udp --sport 389 -j DROP",
                "sdn_flowmod": f"OFPFC_ADD priority=65535 match(eth_type=0x0800, ip_proto=17, udp_src=389) instructions=[] (DROP)",
                "docker_isolation": f"iptables -A FORWARD -p udp --sport 389 -d {victim_ip} -j DROP",
            },
            "hardening_advisory": {
                "kernel_parameters": [
                    "sysctl -w net.core.netdev_max_backlog=8192",
                ],
                "firewall_rules": [
                    "iptables -A INPUT -p udp --sport 389 -j DROP  # Block internet CLDAP responses",
                    "iptables -A INPUT -p udp --dport 389 -j DROP  # Do not expose LDAP over UDP to public internet",
                ],
                "network_measures": [
                    "Restrict LDAP/CLDAP services exclusively to internal RFC 1918 subnets or IPSec VPN tunnels.",
                    "Ensure Windows Domain Controllers have public internet ingress blocked for ports 389, 636, and 3268.",
                ],
            },
        }

    elif "mssql" in normalized_vec:
        profile = {
            "name": "Microsoft SQL Resolution Service (MC-SQLR) Amplification",
            "category": "Database Discovery Protocol Abuse",
            "severity": "HIGH",
            "incident_narrative": (
                f"Microsoft SQL Server Resolution Service (UDP port 1434) amplification flood targeting {victim_ip}. "
                "Attacker queries public SQL Browser instances to bounce instance metadata responses onto the victim."
            ),
            "attack_mechanics": (
                "Sending an unauthenticated 1-byte 0x02 or 0x03 query to UDP 1434 causes SQL Browser to reply with details of all "
                "installed SQL Server instances, dynamic TCP ports, and named pipes, achieving ~25x amplification."
            ),
            "blast_radius": "Database tier disruption and local edge congestion.",
            "containment": {
                "firewall_rule": f"iptables -I INPUT -s {attacker_ip} -p udp --sport 1434 -j DROP",
                "sdn_flowmod": f"OFPFC_ADD priority=65535 match(eth_type=0x0800, ip_proto=17, udp_src=1434) instructions=[] (DROP)",
                "docker_isolation": f"iptables -A FORWARD -p udp --sport 1434 -d {victim_ip} -j DROP",
            },
            "hardening_advisory": {
                "kernel_parameters": [],
                "firewall_rules": [
                    "iptables -A INPUT -p udp --dport 1434 -j DROP  # Deny all external access to SQL Browser",
                    "iptables -A INPUT -p udp --sport 1434 -j DROP",
                ],
                "network_measures": [
                    "Disable the `SQL Server Browser` service on all database servers if instances use static ports.",
                    "Bind SQL Server to static TCP port (e.g. 1433) behind strict internal network ACLs.",
                ],
            },
        }

    elif "udp" in normalized_vec:
        profile = {
            "name": "UDP Volumetric Flood & Socket Exhaustion",
            "category": "High-Bandwidth Volumetric Flood",
            "severity": "HIGH",
            "incident_narrative": (
                f"Volumetric UDP datagram flood originating from {attacker_ip} targeting {victim_ip}. "
                "Attacker is bombarding victim ports with high-rate UDP packets to overwhelm network interfaces and CPU interrupt handling."
            ),
            "attack_mechanics": (
                "Because UDP is connectionless, sockets require zero handshake state. High-rate packet floods force the victim operating "
                "system's network stack to verify port bindings and emit ICMP Port Unreachable packets, saturating CPU softirq routines (`ksoftirqd`)."
            ),
            "blast_radius": "High CPU utilization on victim network stack, line-rate link saturation, and packet drops for all co-hosted services.",
            "containment": {
                "firewall_rule": f"iptables -I INPUT -s {attacker_ip} -p udp -j DROP",
                "sdn_flowmod": f"OFPFC_ADD priority=65535 match(eth_type=0x0800, ip_proto=17, ipv4_src={attacker_ip}) instructions=[] (DROP)",
                "docker_isolation": f"iptables -A FORWARD -s {attacker_ip} -d {victim_ip} -p udp -j DROP",
            },
            "hardening_advisory": {
                "kernel_parameters": [
                    "sysctl -w net.ipv4.icmp_ratelimit=100  # Limits ICMP unreachable error generation rate",
                    "sysctl -w net.core.netdev_max_backlog=10000",
                    "sysctl -w net.core.rmem_max=16777216",
                ],
                "firewall_rules": [
                    "iptables -A INPUT -p udp -m conntrack --ctstate NEW -m limit --limit 100/s --limit-burst 200 -j ACCEPT",
                    "iptables -A INPUT -p udp -m conntrack --ctstate NEW -j DROP",
                ],
                "network_measures": [
                    "Implement upstream BGP FlowSpec discard for high-volume UDP traffic matching non-whitelisted destination ports.",
                    "Configure scrubbing center diversion when traffic exceeds 80% of interface capacity.",
                ],
            },
        }

    elif "web" in normalized_vec:
        profile = {
            "name": "Layer 7 HTTP/HTTPS Application Request Flood",
            "category": "Application-Layer Resource Starvation",
            "severity": "HIGH",
            "incident_narrative": (
                f"Application-layer HTTP request flood directed at web services on {victim_ip}. "
                "Attacker is transmitting rapid GET/POST queries to expensive endpoints (e.g. database search, authentication, reports) "
                "to exhaust backend worker processes, database connection pools, and memory."
            ),
            "attack_mechanics": (
                "Unlike volumetric Layer 3/4 attacks, L7 floods use fully formed TCP handshakes and valid HTTP requests. "
                "Each query triggers substantial database transactions or CPU rendering, allowing small request volumes (500-2,000 req/s) "
                "to crash application servers without triggering bandwidth alarms."
            ),
            "blast_radius": "Web server thread pool starvation (HTTP 502/504 errors), database connection exhaustion, and complete web app unresponsiveness.",
            "containment": {
                "firewall_rule": f"iptables -I INPUT -s {attacker_ip} -p tcp -m multiport --dports 80,443 -j DROP",
                "sdn_flowmod": f"OFPFC_ADD priority=65535 match(eth_type=0x0800, ip_proto=6, ipv4_src={attacker_ip}) instructions=[] (DROP)",
                "docker_isolation": f"docker exec <web_container> iptables -I INPUT -s {attacker_ip} -j DROP",
            },
            "hardening_advisory": {
                "kernel_parameters": [
                    "sysctl -w net.ipv4.tcp_tw_reuse=1  # Reuses TIME-WAIT sockets for new client connections",
                    "sysctl -w net.core.somaxconn=4096  # Increases application listen() queue size",
                ],
                "firewall_rules": [
                    "iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j DROP  # Max 50 concurrent connections per IP",
                    "iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 50 -j DROP",
                ],
                "network_measures": [
                    "Deploy reverse proxy rate limiting (e.g. Nginx `limit_req_zone $binary_remote_addr zone=api:10m rate=15r/s;`).",
                    "Enforce Web Application Firewall (WAF) challenges: Managed JavaScript challenges, TLS JA3 fingerprinting, and CAPTCHA.",
                ],
            },
        }

    elif "tftp" in normalized_vec:
        profile = {
            "name": "TFTP Protocol Abuse & UDP Ingestion Flood",
            "category": "UDP Protocol Abuse",
            "severity": "MEDIUM",
            "incident_narrative": (
                f"High-frequency TFTP (UDP 69) flood targeting {victim_ip}. Attacker sends unauthenticated read/write requests "
                "to exhaust network socket queues."
            ),
            "attack_mechanics": "TFTP has zero cryptographic authentication. Flood packets saturate provisioning subnets.",
            "blast_radius": "Exhausts local TFTP server process buffers and causes provisioning timeouts.",
            "containment": {
                "firewall_rule": f"iptables -I INPUT -s {attacker_ip} -p udp --dport 69 -j DROP",
                "sdn_flowmod": f"OFPFC_ADD priority=65535 match(eth_type=0x0800, ip_proto=17, udp_dst=69) instructions=[] (DROP)",
                "docker_isolation": f"iptables -A FORWARD -p udp --dport 69 -d {victim_ip} -j DROP",
            },
            "hardening_advisory": {
                "kernel_parameters": [],
                "firewall_rules": [
                    "iptables -A INPUT -p udp --dport 69 -s 10.0.0.0/8 -j ACCEPT  # Only allow internal provisioning subnet",
                    "iptables -A INPUT -p udp --dport 69 -j DROP  # Block all other ingress",
                ],
                "network_measures": [
                    "Isolate TFTP services exclusively to out-of-band management VLANs.",
                ],
            },
        }

    return profile


def generate_incident_dossier(
    features: Dict[str, Any],
    label: str,
    confidence: float,
    breakdown: Optional[Dict[str, Any]] = None,
    attacker_ip: str = "192.168.1.100",
    victim_ip: str = "10.0.0.1",
) -> Dict[str, Any]:
    """
    Generate the complete Blue Team Incident Dossier:
      1. What happened (Incident summary, attack profile & mechanics)
      2. Forensic evidence & Transport Fingerprint (Socket profile, window anomalies, model consensus)
      3. Immediate containment (Gated firewall DROP & OpenFlow rule)
      4. Hardening advisory (Kernel sysctl, iptables, and upstream network rules to prevent recurrence)
    """
    profile = get_attack_profile(label, attacker_ip=attacker_ip, victim_ip=victim_ip)
    fingerprint = infer_host_fingerprint(features)

    # Format model breakdown consensus
    breakdown = breakdown or {}
    consensus_mode = breakdown.get("mode", "ENSEMBLE_CONSENSUS")
    rf_entry = breakdown.get("random_forest") or {}
    xgb_entry = breakdown.get("xgboost") or {}
    lstm_entry = breakdown.get("sequence_classifier") or {}

    model_evidence = []
    if xgb_entry:
        model_evidence.append(f"XGBoost: {xgb_entry.get('label')} (Confidence: {xgb_entry.get('confidence', 0.0):.2f})")
    if rf_entry:
        model_evidence.append(f"Random Forest: {rf_entry.get('label')} (Confidence: {rf_entry.get('confidence', 0.0):.2f})")
    if lstm_entry and lstm_entry.get("active"):
        model_evidence.append(f"BiLSTM Sequence: {lstm_entry.get('label')} (Confidence: {lstm_entry.get('confidence', 0.0):.2f})")

    # Combine all elements into an enterprise Blue Team Incident Dossier
    return {
        "incident_title": f"INCIDENT-{label.upper()}: {profile['name']}",
        "attack_vector": label,
        "severity": profile["severity"],
        "confidence": float(confidence),
        "target": {
            "attacker_ip": attacker_ip,
            "victim_ip": victim_ip,
        },
        "incident_summary": profile["incident_narrative"],
        "attack_mechanics": profile["attack_mechanics"],
        "blast_radius": profile["blast_radius"],
        "forensics": {
            "socket_profile": fingerprint["socket_profile"],
            "stack_details": fingerprint["stack_description"],
            "initial_window": fingerprint["initial_window_bytes"],
            "observed_anomalies": fingerprint["anomalies"],
            "model_consensus_tier": consensus_mode,
            "model_evidence": model_evidence,
        },
        "containment": profile["containment"],
        "hardening_advisory": profile["hardening_advisory"],
    }


def generate_campaign_dossier(
    campaign_id: str,
    victim_ip: str,
    attack_family: str,
    bot_count: int,
    flow_count: int,
    aggregate_pps: float,
    aggregate_mbps: float,
    participating_ips: List[str],
    h6_result: Optional[Dict[str, Any]] = None,
    h9_result: Optional[Dict[str, Any]] = None,
    analyst_notes: Optional[Dict[str, Any]] = None,
    confidence: float = 0.95,
) -> Dict[str, Any]:
    """
    Generate a Blue Team Campaign Incident Dossier specifically tailored for
    multi-source / distributed campaigns (e.g. thousands of rotating source IPs
    or botnet clusters targeting a single victim).

    Distinct from single-flow dossiers:
      1. Aggregates botnet pool, unique IPs, aggregate PPS/Mbps, and flow count.
      2. Multi-layer corroboration: Layer 1 H6 Rate Surge + Layer 1/2 H9 Statistical Anomaly + Layer 3 H8 Campaign Correlator.
      3. Containment playbook focuses on target-port rate-limiting, SYN cookies, and subnet BGP FlowSpec, rather than single-IP drops.
    """
    is_syn = "syn" in attack_family.lower()

    if is_syn:
        title = f"CAMPAIGN-DISTRIBUTED-SYN-FLOOD: Coordinated Botnet Queue Saturation ({campaign_id})"
        narrative = (
            f"Distributed TCP SYN flood detected targeting victim host {victim_ip}. "
            f"Traffic is coordinated across {bot_count:,} distinct source endpoints ({flow_count:,} flows) "
            f"generating {aggregate_pps:.1f} PPS ({aggregate_mbps:.2f} Mbps). "
            f"Attacker employs rotating source ports to bypass stateless per-flow filters and exhaust the host listen() backlog queue."
        )
        mechanics = (
            "Attacker initiates thousands of half-open TCP handshakes across rotating ephemeral ports. "
            "Because each connection attempt is a distinct micro-flow (1-2 packets), per-flow ML models see normal handshake behavior. "
            "However, the aggregate arrival rate saturates the kernel SYN queue (tcp_max_syn_backlog), causing legitimate client connection drops."
        )
        containment = {
            "firewall_rule": f"iptables -I INPUT -p tcp --dport 80 --syn -m limit --limit 50/s --limit-burst 100 -j ACCEPT && iptables -A INPUT -p tcp --dport 80 --syn -j DROP",
            "sdn_flowmod": f"OFPFC_ADD priority=65500 match(eth_type=0x0800, ip_proto=6, tcp_dst=80) meter=1 instructions=[meter:1, OUTPUT:NORMAL]",
            "docker_isolation": f"docker exec <web_container> sysctl -w net.ipv4.tcp_syncookies=1",
        }
        hardening = {
            "kernel_parameters": [
                "sysctl -w net.ipv4.tcp_syncookies=1  # Mitigate SYN queue exhaustion with cryptographic cookies",
                "sysctl -w net.ipv4.tcp_max_syn_backlog=8192  # Expand half-open connection backlog table",
                "sysctl -w net.ipv4.tcp_synack_retries=2  # Drop stale half-open connections rapidly (default: 5)",
                "sysctl -w net.core.somaxconn=4096  # Expand listen() accept queue for web sockets",
            ],
            "firewall_rules": [
                "iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -m limit --limit 100/s --limit-burst 200 -j ACCEPT",
                "iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j DROP",
            ],
            "network_measures": [
                "Activate upstream SYN Proxy scrubbing on perimeter edge router.",
                f"Advertise BGP FlowSpec rate-limit for tcp-flags=SYN to {victim_ip}.",
            ],
        }
    else:
        title = f"CAMPAIGN-DISTRIBUTED-ANOMALY: Multi-Source Coordinated Vector ({campaign_id})"
        narrative = (
            f"Multi-source anomalous traffic surge targeting {victim_ip}. "
            f"Coordinated across {bot_count:,} distinct endpoints generating {aggregate_pps:.1f} PPS ({aggregate_mbps:.2f} Mbps). "
            f"Detected via multi-layer corroboration across rate thresholds (H6) and statistical anomaly baselines (H9)."
        )
        mechanics = (
            f"High-frequency traffic surge deviating statistically from historical baseline. "
            f"Multi-endpoint coordination indicates command-and-control synchronization."
        )
        containment = {
            "firewall_rule": f"iptables -I INPUT -d {victim_ip} -m limit --limit 100/s --limit-burst 200 -j ACCEPT && iptables -A INPUT -d {victim_ip} -j DROP",
            "sdn_flowmod": f"OFPFC_ADD priority=65500 match(eth_type=0x0800, ipv4_dst={victim_ip}) meter=1 instructions=[meter:1, OUTPUT:NORMAL]",
            "docker_isolation": f"iptables -A FORWARD -d {victim_ip} -j DROP",
        }
        hardening = {
            "kernel_parameters": [
                "sysctl -w net.core.netdev_max_backlog=10000",
                "sysctl -w net.core.rmem_max=16777216",
            ],
            "firewall_rules": [
                f"iptables -A INPUT -d {victim_ip} -m limit --limit 500/s --limit-burst 1000 -j ACCEPT",
            ],
            "network_measures": [
                "Implement upstream BGP FlowSpec traffic redirection to scrubbing center.",
            ],
        }

    evidence = []
    if h6_result:
        evidence.append(f"Layer 1 Rate Detector (H6): {h6_result.get('status')} ({h6_result.get('current_pps', 0):.1f} PPS, {h6_result.get('current_syn_rate', 0):.1f} SYN/s)")
    if h9_result:
        evidence.append(f"Layer 1/2 Anomaly Detector (H9): {h9_result.get('severity')} (Score: {h9_result.get('anomaly_score', 0):.1f}/100, Z_pps: +{h9_result.get('z_scores', {}).get('z_pps', 0):.1f}σ)")
    evidence.append(f"Layer 3 Campaign Correlator (H8): {bot_count:,} unique endpoints across {flow_count:,} correlated flows")

    sample_ips = participating_ips[:10]
    more_count = len(participating_ips) - len(sample_ips)
    ip_display = ", ".join(sample_ips) + (f" ... (+{more_count} more)" if more_count > 0 else "")

    return {
        "incident_title": title,
        "attack_vector": attack_family,
        "severity": "CRITICAL" if aggregate_pps > 500 or bot_count >= 10 else "HIGH",
        "confidence": round(confidence, 3),
        "confidence_type": "MULTI_LAYER_CORROBORATION_HEURISTIC",
        "is_campaign": True,
        "campaign_id": campaign_id,
        "target": {
            "attacker_ip": f"Distributed Pool ({bot_count:,} endpoints)",
            "victim_ip": victim_ip,
            "participating_ips_sample": ip_display,
        },
        "incident_summary": narrative,
        "attack_mechanics": mechanics,
        "blast_radius": f"Denial of service for victim host {victim_ip}, potential backlog overflow across {bot_count:,} attacking nodes.",
        "forensics": {
            "socket_profile": "Distributed Multi-Host Raw Sockets / Spoofed Ephemeral Handshakes",
            "stack_details": f"Multi-source coordinated attack pool. {bot_count:,} endpoints transmitting {flow_count:,} flows.",
            "initial_window": "N/A (Multi-Host Aggregate)",
            "observed_anomalies": [
                f"Multi-flow coordination across {bot_count:,} source endpoints.",
                f"Aggregate throughput: {aggregate_pps:.1f} PPS ({aggregate_mbps:.3f} Mbps).",
            ],
            "model_consensus_tier": "MULTI_LAYER_CAMPAIGN_CORROBORATION",
            "model_evidence": evidence,
            "ai_threat_analyst_notes": analyst_notes,
        },
        "containment": containment,
        "hardening_advisory": hardening,
    }

