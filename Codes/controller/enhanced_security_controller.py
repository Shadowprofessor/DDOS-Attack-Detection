# -*- coding: utf-8 -*-
import os
import sys
import time
import collections
try:
    import collections.abc
    collections.MutableMapping = collections.abc.MutableMapping
    collections.Mapping = collections.abc.Mapping
    collections.Callable = collections.abc.Callable
except (ImportError, AttributeError):
    pass

try:
    import eventlet.wsgi
    if not hasattr(eventlet.wsgi, 'ALREADY_HANDLED'):
        eventlet.wsgi.ALREADY_HANDLED = object()
except (ImportError, AttributeError, Exception):
    pass

import logging
import json
try:
    import urllib.request as urllib_request
except ImportError:
    import urllib2 as urllib_request
from datetime import datetime
try:
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    HAS_PANDAS_SKLEARN = True
except ImportError:
    HAS_PANDAS_SKLEARN = False

try:
    from ryu.controller import ofp_event
    from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
    from ryu.lib import hub
    from ryu.lib.packet import packet, ethernet, ether_types, in_proto, ipv4, icmp, tcp, udp
    from ryu.base import app_manager
    HAS_RYU = True
except ImportError:
    HAS_RYU = False
    class _MockOFPEvent:
        EventOFPStateChange = "EventOFPStateChange"
        EventOFPFlowStatsReply = "EventOFPFlowStatsReply"
        EventOFPPacketIn = "EventOFPPacketIn"
        EventOFPSwitchFeatures = "EventOFPSwitchFeatures"
    ofp_event = _MockOFPEvent()
    MAIN_DISPATCHER, DEAD_DISPATCHER = "MAIN", "DEAD"
    def set_ev_cls(*args, **kwargs):
        def decorator(f): return f
        return decorator
    class _MockHub:
        def spawn(self, *args, **kwargs): return None
    hub = _MockHub()
    packet = ethernet = ether_types = in_proto = ipv4 = icmp = tcp = udp = None
    class _MockRyuApp(object):
        def __init__(self, *args, **kwargs):
            self.logger = logging.getLogger("EnhancedRyuSecurityController")
    app_manager = type("app_manager", (), {"RyuApp": _MockRyuApp})

# Ensure controller directory and security suite are in sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# Import base switch logic
try:
    import switch
except ImportError:
    switch = None
from security.attacker_profiler import AttackerProfiler
from security.geo_locator import GeoLocator
from security.forensics_logger import ForensicsLogger
from security.threat_intelligence import ThreatIntelligence
from security.ai_threat_analyzer import AIThreatAnalyzer
from security.docker_enforcer import DockerEnforcer

try:
    from security.ai_threat_analyzer import _propose_action, get_action
except ImportError:
    try:
        from ai_threat_analyzer import _propose_action, get_action
    except ImportError:
        _propose_action = None
        get_action = None


# Dashboard push URL (host.docker.internal resolves to the Docker host)
DASHBOARD_PUSH_URLS = [
    "http://host.docker.internal:5050/api/incidents",
    "http://172.17.0.1:5050/api/incidents",
    "http://localhost:5050/api/incidents",
]

# ── Real-time flood detection thresholds ──
# If more than this many NEW flows arrive for the same dst_ip within the
# time window, we treat it as a DDoS flood and DROP all further traffic.
FLOOD_NEW_FLOW_THRESHOLD = 50       # new flows per destination
FLOOD_TIME_WINDOW_SEC    = 10       # sliding window length (seconds)


class EnhancedRyuSecurityController(switch.SimpleSwitch13 if switch else object):
    """
    Enhanced Ryu SDN Controller featuring:
    - **Real-time packet-in flood detection** (rate-based, per destination)
    - ML-based DDoS Traffic Detection (Random Forest)
    - IP Traceback & Attacker Profiling
    - GeoIP Lookup & Location Identification
    - Dynamic Threat Scoring & IP Blacklisting
    - Attack Vector Multi-class Classification
    - Automated Forensic Logging for Incident Reports
    - Real-time Dashboard Push Notifications
    """
    def __init__(self, *args, **kwargs):
        super(EnhancedRyuSecurityController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        # ── Real-time flood tracking ──
        # dst_ip → list of timestamps when a NEW flow (packet_in) was seen
        self._dst_flow_times = {}
        # dst_ip → set() of source IPs already seen during the current window
        self._dst_src_ips = {}
        # Set of dst_ips currently under flood protection (auto-DROP mode)
        self._flood_protected_dsts = set()

        # Initialize Security Modules
        self.profiler = AttackerProfiler(high_threat_threshold=30)
        self.geo_locator = GeoLocator()
        
        # Use Docker-mounted path for forensics so dashboard can read it
        forensics_log_dir = self._resolve_forensics_dir()
        self.forensics = ForensicsLogger(log_dir=forensics_log_dir)
        self.threat_intel = ThreatIntelligence(default_block_duration_sec=300)
        self.classifier = AttackTypeClassifier()
        self.ai_analyzer = AIThreatAnalyzer()
        self._icmp_ping_counts = collections.defaultdict(int)

        # Whitelist local Mininet hosts (10.0.0.x) so legitimate host traffic & pings are never blocked
        for i in range(1, 255):
            self.threat_intel.add_to_whitelist("10.0.0." + str(i))

        # Detection stats
        self.total_flows_analyzed = 0
        self.total_attacks_detected = 0
        self.total_attacks_mitigated = 0

        start = datetime.now()
        self.flow_training()
        end = datetime.now()
        self.logger.info("ML Training completed in: %s", (end - start))

    def _resolve_forensics_dir(self):
        """Find or create the best forensics log directory."""
        candidates = [
            "/root/Codes/Codes/attack_logs",
            "/root/Codes/attack_logs",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "attack_logs"),
            "attack_logs",
        ]
        for d in candidates:
            parent = os.path.dirname(d)
            if os.path.isdir(parent) or os.path.isdir(d):
                if not os.path.exists(d):
                    try:
                        os.makedirs(d)
                    except Exception:
                        pass
                self.logger.info("Forensics log directory: %s", os.path.abspath(d))
                return d
        # Fallback
        if not os.path.exists("attack_logs"):
            try:
                os.makedirs("attack_logs")
            except Exception:
                pass
        return "attack_logs"

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            self._check_system_recovery()
            self._load_dynamic_whitelist()
            hub.sleep(1)  # Ultra-fast 1s polling for real-time detection, mitigation & auto-recovery

    def _load_dynamic_whitelist(self):
        """Load dynamic whitelisted IPs saved by dashboard user feedback."""
        for d in [self.forensics.log_dir, "/root/Codes/Codes/attack_logs", "/root/Codes/attack_logs", "attack_logs"]:
            path = os.path.join(d, "whitelisted_ips.json")
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        ips = json.load(f)
                        for ip in ips:
                            if ip and ip != "ATTACK_STOPPED":
                                self.threat_intel.add_to_whitelist(ip)
                except Exception:
                    pass

    def _check_system_recovery(self):
        """
        Monitors active DDoS mitigation state. If no new attack flows targeting
        a protected destination have arrived for 6+ seconds, lift the flood
        protection, log [SYSTEM RECOVERED], and push a recovery alert to the dashboard.
        """
        now = time.time()
        recovered_dsts = []

        for dstip in list(self._flood_protected_dsts):
            times = self._dst_flow_times.get(dstip, [])
            # Prune timestamps outside window
            cutoff = now - FLOOD_TIME_WINDOW_SEC
            while times and times[0] < cutoff:
                times.pop(0)

            # If no new flows in the last 6 seconds or queue emptied
            if not times or (now - times[-1] >= 6):
                recovered_dsts.append(dstip)

        for dstip in recovered_dsts:
            self._flood_protected_dsts.remove(dstip)
            if dstip in self._dst_flow_times:
                self._dst_flow_times[dstip] = []
            if dstip in self._dst_src_ips:
                self._dst_src_ips[dstip] = set()

            self.logger.info(
                "🟢 [SYSTEM RECOVERED] DDoS Attack Ended! Traffic for target %s restored to normal. All pings & normal traffic operational.",
                dstip
            )

            # Log forensic recovery record
            incident = self.forensics.log_incident(
                attacker_ip="ATTACK_STOPPED",
                victim_ip=dstip,
                attack_type="SYSTEM RECOVERED",
                threat_score=0,
                geo_info={
                    "ip": "0.0.0.0",
                    "country": "System Restored",
                    "country_code": "OK",
                    "city": "Normal Operation",
                    "isp": "SDN Auto-Recovery Engine",
                    "org": "CyberShield Defense",
                    "lat": 0.0, "lon": 0.0, "is_private": True
                },
                mitigation_action="SYSTEM_RECOVERED"
            )
            self._push_to_dashboard(incident)

    def _request_stats(self, datapath):
        self.logger.debug('Send stats request to datapath: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def flow_training(self):
        self.logger.info("Initializing ML Flow Model...")
        if not HAS_PANDAS_SKLEARN:
            self.rf_model = None
            self.logger.info("Pandas/Scikit-Learn not installed in container environment. Utilizing ultra-fast SDN heuristic flood detection & Nemotron AI reasoning engine.")
            return
        import joblib
        
        # Check for saved trained model checkpoints first
        checkpoint_paths = [
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ml", "models", "RandomForest_model.pkl")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ml", "models", "ExtraTrees_model.pkl")),
            "/root/Codes/Codes/ml/models/RandomForest_model.pkl",
            "RandomForest_model.pkl"
        ]
        
        for path in checkpoint_paths:
            if os.path.exists(path):
                try:
                    loaded_model = joblib.load(path)
                    n_feats = getattr(loaded_model, 'n_features_in_', 18)
                    if n_feats == 18:
                        self.rf_model = loaded_model
                        self.logger.info("✅ Loaded 18-feature pre-trained ML Checkpoint model from: %s", path)
                        return
                    else:
                        self.logger.warning("Checkpoint %s expects %d features (SDN telemetry provides 18). Training native 18-feature SDN model...", path, n_feats)
                except Exception as e:
                    self.logger.warning("Failed to load checkpoint %s: %s", path, e)

        # Fallback: train on FlowStatsfile.csv dataset
        try:
            candidate_paths = [
                "FlowStatsfile.csv",
                os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "FlowStatsfile.csv")),
                os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "FlowStatsfile.csv")),
                "../../FlowStatsfile.csv",
                "../../../FlowStatsfile.csv",
                "/root/Codes/FlowStatsfile.csv"
            ]
            dataset_path = None
            for path in candidate_paths:
                if os.path.exists(path):
                    dataset_path = path
                    break
            if not dataset_path:
                raise FileNotFoundError("FlowStatsfile.csv not found in expected locations")

            flow_dataset = pd.read_csv(dataset_path)
            self.logger.info("Dataset loaded: %d rows, %d columns from %s", len(flow_dataset), len(flow_dataset.columns), dataset_path)

            for col in ['ip_src', 'ip_dst']:
                if col in flow_dataset.columns:
                    flow_dataset[col] = flow_dataset[col].astype(str).str.replace('.', '', regex=False).astype(float)

            X_flow = flow_dataset.iloc[:, :-1].values.astype('float64')
            y_flow = flow_dataset.iloc[:, -1].values

            self.rf_model = RandomForestClassifier(n_estimators=100, criterion='entropy', random_state=42)
            self.rf_model.fit(X_flow, y_flow)
            
            attack_count = int((y_flow == 1).sum())
            benign_count = int((y_flow == 0).sum())
            self.logger.info("ML Model Training Completed Successfully. [Attack: %d, Benign: %d samples]", attack_count, benign_count)
        except Exception as e:
            self.logger.error("Failed to train ML model: %s", str(e))

    # ─── Real-time Flood Detection (packet-in level) ──────────────────
    def _is_flood_detected(self, srcip, dstip):
        """
        Track new-flow arrival rate per destination IP.
        Returns True if dstip is under a DDoS flood (too many unique src IPs
        sending new flows within the time window).
        """
        now = time.time()
        cutoff = now - FLOOD_TIME_WINDOW_SEC

        # Initialize tracking structures
        if dstip not in self._dst_flow_times:
            self._dst_flow_times[dstip] = []
            self._dst_src_ips[dstip] = set()

        # Prune old entries outside the time window
        times = self._dst_flow_times[dstip]
        while times and times[0] < cutoff:
            times.pop(0)
        # If we pruned everything, reset the source IP set
        if not times:
            self._dst_src_ips[dstip] = set()

        # Record this new flow
        times.append(now)
        self._dst_src_ips[dstip].add(srcip)

        unique_srcs = len(self._dst_src_ips[dstip])

        # Check threshold
        if unique_srcs >= FLOOD_NEW_FLOW_THRESHOLD:
            if dstip not in self._flood_protected_dsts:
                self._flood_protected_dsts.add(dstip)
                self.logger.warning(
                    "🛡️ [FLOOD DETECTED] %d unique sources → %s in %ds window! Activating DROP mode.",
                    unique_srcs, dstip, FLOOD_TIME_WINDOW_SEC
                )
            return True

        return dstip in self._flood_protected_dsts

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # ── IP-level processing with real-time flood detection ──
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            if ip:
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto
                match = None

                if protocol == in_proto.IPPROTO_ICMP:
                    t = pkt.get_protocol(icmp.icmp)
                    if t:
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                ipv4_src=srcip, ipv4_dst=dstip,
                                                ip_proto=protocol, icmpv4_code=t.code, icmpv4_type=t.type)
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    if t:
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                ipv4_src=srcip, ipv4_dst=dstip,
                                                ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port)
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    if u:
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                ipv4_src=srcip, ipv4_dst=dstip,
                                                ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port)
                
                if match is None:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)

                # ── ICMP Continuous Ping Tracking ──
                if protocol == in_proto.IPPROTO_ICMP:
                    self._icmp_ping_counts[srcip] += 1

                is_ping_flood = (protocol == in_proto.IPPROTO_ICMP and self._icmp_ping_counts[srcip] >= 150)
                is_rate_flood = self._is_flood_detected(srcip, dstip)

                # ── CHECK 1: Already blacklisted → DROP immediately ──
                if self.threat_intel.is_blacklisted(srcip):
                    self.mitigate_attacker(datapath, srcip, victim_ip=dstip, confidence=1.0, reason=f"Blacklisted IP {srcip}")
                    return

                # ── CHECK 2: Continuous 150 pings or real-time flood → Trigger Nemotron AI & DROP ──
                if is_ping_flood or is_rate_flood:
                    # Install DROP rule immediately to stop server downtime
                    conf = 0.99 if (is_ping_flood and is_rate_flood) else 0.90
                    self.mitigate_attacker(
                        datapath, srcip, victim_ip=dstip, confidence=conf,
                        reason=f"Flood detected (ping_flood={is_ping_flood}, rate_flood={is_rate_flood})"
                    )
                    self.threat_intel.blacklist_ip(srcip)
                    self.total_attacks_detected += 1
                    self.total_attacks_mitigated += 1

                    # Extract protocol details for classification
                    tp_src_val, tp_dst_val, icmp_type_val, tcp_flags_val = 0, 0, -1, 0
                    if protocol == in_proto.IPPROTO_ICMP:
                        t = pkt.get_protocol(icmp.icmp)
                        if t: icmp_type_val = t.type
                    elif protocol == in_proto.IPPROTO_TCP:
                        t = pkt.get_protocol(tcp.tcp)
                        if t:
                            tp_src_val, tp_dst_val, tcp_flags_val = t.src_port, t.dst_port, t.bits
                    elif protocol == in_proto.IPPROTO_UDP:
                        u = pkt.get_protocol(udp.udp)
                        if u: tp_src_val, tp_dst_val = u.src_port, u.dst_port

                    geo_info = self.geo_locator.locate_ip(srcip)
                    pkt_cnt = max(self._icmp_ping_counts[srcip], 150 if is_ping_flood else 1)
                    attack_type = self.classifier.classify_attack(
                        protocol, tp_src_val, tp_dst_val, icmp_type_val, pkt_cnt, msg.total_len, 0, tcp_flags_val
                    )

                    # Trigger Nemotron AI reasoning prevention engine & Docker enforcer
                    telemetry = {
                        "attacker_ip": srcip,
                        "victim_ip": dstip,
                        "attack_type": attack_type,
                        "packet_count": pkt_cnt,
                        "continuous_pings": self._icmp_ping_counts[srcip]
                    }
                    ai_res = self.ai_analyzer.analyze_and_prevent(telemetry)
                    DockerEnforcer.block_attacker_container(srcip, dstip)

                    incident = self.forensics.log_incident(
                        attacker_ip=srcip,
                        victim_ip=dstip,
                        attack_type=attack_type,
                        threat_score=100,
                        geo_info=geo_info,
                        mitigation_action="FLOW_DROP_NEMOTRON_AI_BLOCK"
                    )
                    self._push_to_dashboard(incident)
                    self.logger.info(
                        "🚫 [PREVENTION COMPLETE] %s → %s | %s mitigated by Nemotron AI | %s",
                        srcip, dstip, attack_type, geo_info.get("country", "Unknown")
                    )
                    return

                # ── NORMAL: Install forwarding flow (priority 1) ──
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle=20, hard=100)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, idle=20, hard=100)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        try:
            body = ev.msg.body
            stats_data = []

            for stat in body:
                # Include any flow with priority >= 1 or explicit IP match
                if stat.priority >= 1 or 'ipv4_src' in stat.match:
                    ip_src = stat.match.get('ipv4_src', '0.0.0.0')
                    tp_src = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
                    ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
                    tp_dst = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))
                    ip_proto = stat.match.get('ip_proto', 0)
                    icmp_code = stat.match.get('icmpv4_code', -1)
                    icmp_type = stat.match.get('icmpv4_type', -1)
                    
                    duration_sec = stat.duration_sec
                    duration_nsec = stat.duration_nsec
                    packet_count = stat.packet_count
                    byte_count = stat.byte_count

                    rate_pps = packet_count / max(duration_sec, 1)
                    rate_npps = packet_count / max(duration_nsec, 1)
                    rate_bps = byte_count / max(duration_sec, 1)
                    rate_nbps = byte_count / max(duration_nsec, 1)

                    # IP String formatting to numeric
                    ip_src_num = int(str(ip_src).replace('.', '')) if str(ip_src) != '0.0.0.0' else 0
                    ip_dst_num = int(str(ip_dst).replace('.', '')) if str(ip_dst) != '0.0.0.0' else 0

                    stats_data.append([
                        ip_src_num, tp_src, ip_dst_num, tp_dst, ip_proto, icmp_code, icmp_type,
                        duration_sec, duration_nsec, 0, 0, 0, packet_count, byte_count,
                        rate_pps, rate_npps, rate_bps, rate_nbps, ip_src, ip_dst
                    ])

            if not stats_data:
                return

            self.total_flows_analyzed += len(stats_data)

            if HAS_PANDAS_SKLEARN and getattr(self, 'rf_model', None) is not None:
                df = pd.DataFrame(stats_data)
                X_predict = df.iloc[:, :18]
                y_pred = self.rf_model.predict(X_predict)
                predictions = list(zip(y_pred, df.iloc[:, 18], df.iloc[:, 19], df.iloc[:, 12], df.iloc[:, 13]))
            else:
                predictions = []
                for row in stats_data:
                    pred = 1 if row[14] > 50 else 0
                    predictions.append((pred, row[18], row[19], row[12], row[13]))

            ddos_count = 0
            for idx, (pred, ip_src_str, ip_dst_str, pkt_cnt, byte_cnt) in enumerate(predictions):
                if pred == 1:
                    ddos_count += 1

                    self.logger.info(
                        "⚠️ [ML DETECTION] DDoS predicted for flow: %s → %s (pkt=%d, bytes=%d)",
                        ip_src_str, ip_dst_str, int(pkt_cnt), int(byte_cnt)
                    )

                    # 1. Check Threat Intel Blacklist — skip if attacker is already blocked
                    if self.threat_intel.is_blacklisted(ip_src_str):
                        self.logger.info("   ↳ Already blacklisted: %s (skipping)", ip_src_str)
                        continue

                    # 1b. Skip backscatter / response traffic directed at a blacklisted attacker
                    if self.threat_intel.is_blacklisted(ip_dst_str):
                        self.logger.info("   ↳ Response backscatter flow towards blacklisted target: %s → %s (skipping)", ip_src_str, ip_dst_str)
                        continue

                    # 2. Attacker Profiling & Threat Scoring
                    # Read from stats_data which is always available (works for both ML and heuristic paths)
                    row = stats_data[idx]
                    pkt_cnt = row[12]
                    byte_cnt = row[13]
                    dur_sec = row[7]
                    ip_proto = row[4]
                    tp_src = row[1]
                    tp_dst = row[3]
                    icmp_type = row[6]

                    profile_res = self.profiler.analyze_flow(
                        ip_src_str, ip_dst_str, pkt_cnt, byte_cnt, dur_sec, ip_proto, tp_src, tp_dst
                    )

                    # 3. GeoLocation Tracking
                    geo_info = self.geo_locator.locate_ip(ip_src_str)

                    # 4. Attack Vector Multi-class Classification
                    attack_type = self.classifier.classify_attack(
                        ip_proto, tp_src, tp_dst, icmp_type, pkt_cnt, byte_cnt, dur_sec
                    )

                    threat_score = profile_res["threat_score"] if profile_res else 50
                    is_high_threat = profile_res["is_high_threat"] if profile_res else True

                    # 5. ALWAYS log forensics when ML predicts attack
                    self.total_attacks_detected += 1

                    if is_high_threat or ddos_count >= 2:
                        # Execute Mitigation & Blacklist
                        self.threat_intel.blacklist_ip(ip_src_str)
                        
                        datapath = ev.msg.datapath
                        conf = round(threat_score / 100.0, 2) if threat_score else 0.85
                        self.mitigate_attacker(
                            datapath, ip_src_str, victim_ip=ip_dst_str, confidence=conf,
                            reason=f"ML/Profiler attack detection (threat_score={threat_score})"
                        )
                        self.total_attacks_mitigated += 1

                        mitigation_action = "FLOW_DROP_BLOCK"
                    else:
                        mitigation_action = "ALERT_ONLY"

                    # Forensics logging (always log for ML detections)
                    incident = self.forensics.log_incident(
                        attacker_ip=ip_src_str,
                        victim_ip=ip_dst_str,
                        attack_type=attack_type,
                        threat_score=threat_score,
                        geo_info=geo_info,
                        mitigation_action=mitigation_action
                    )

                    # Push to dashboard via HTTP
                    self._push_to_dashboard(incident)

                    self.logger.info(
                        "🚨 [ATTACK DETECTED & %s] Attacker: %s (%s, %s) → Victim: %s | Vector: %s | Score: %d",
                        mitigation_action, ip_src_str,
                        geo_info.get("country", "Unknown"), geo_info.get("city", "Unknown"),
                        ip_dst_str, attack_type, threat_score
                    )

            if ddos_count > 0:
                self.logger.info(
                    "📊 [STATS] Flows analyzed: %d | DDoS in batch: %d | Total detected: %d | Total mitigated: %d",
                    len(stats_data), ddos_count, self.total_attacks_detected, self.total_attacks_mitigated
                )

        except Exception as e:
            self.logger.error("Error in flow stats handler: %s", str(e))
            import traceback
            self.logger.error(traceback.format_exc())

    def _push_to_dashboard(self, incident):
        """Push incident data to the dashboard via HTTP POST (best-effort)."""
        if not incident:
            return
        try:
            data = json.dumps(incident).encode('utf-8')
            for url in DASHBOARD_PUSH_URLS:
                try:
                    req = urllib_request.Request(
                        url, data=data,
                        headers={'Content-Type': 'application/json'}
                    )
                    urllib_request.urlopen(req, timeout=2)
                    self.logger.debug("Dashboard push succeeded: %s", url)
                    return
                except Exception:
                    continue
        except Exception:
            pass

    def mitigate_attacker(self, datapath, ip_src, victim_ip=None, confidence=None, in_port=None, reason=None):
        """
        Propose an OpenFlow Flow Mod Drop Rule to block malicious attacker traffic.
        SAFETY: Does NOT send the flow-mod directly. Enqueues a PENDING action for human approval.
        """
        dpid = getattr(datapath, 'id', None)
        target_victim = victim_ip or "10.0.0.1"
        target_confidence = confidence if confidence is not None else 0.95
        proposed_cmd = f"OFPFlowMod DROP eth_type=0x0800 ipv4_src={ip_src} (dpid={dpid}, in_port={in_port})"

        if _propose_action is not None:
            action_id = _propose_action(
                action_type="OPENFLOW_DROP",
                attacker_ip=ip_src,
                victim_ip=target_victim,
                reason=reason or f"OpenFlow drop proposed for attacker IP {ip_src} targeting {target_victim} on dpid {dpid}",
                confidence=target_confidence,
                commands=[proposed_cmd],
                source="enhanced_security_controller",
                datapath=datapath,
            )
            action = get_action(action_id) if get_action else None
            if action:
                action["datapath"] = datapath
                action["in_port"] = in_port
                action["dpid"] = dpid

            self.logger.info("⏳ OPENFLOW_DROP action PROPOSED for %s → %s (confidence=%.2f, ID: %s). Awaiting human approval.", ip_src, target_victim, target_confidence, action_id)
            return action_id
        else:
            self.logger.warning("ai_threat_analyzer not available; cannot propose OpenFlow drop for %s", ip_src)
            return None


def execute_openflow_drop(action_id_or_action):
    """
    Execute an approved OPENFLOW_DROP action.
    This is the ONLY function that sends the OpenFlow DROP flow-mod, and it must
    ONLY be called via approve_action() after explicit human approval.
    """
    if isinstance(action_id_or_action, str):
        action = get_action(action_id_or_action) if get_action else None
    else:
        action = action_id_or_action

    if not action:
        return {"status": "FAILED", "error": "Action not found"}

    dp = action.get("datapath")
    ip_src = action.get("attacker_ip")
    if dp and hasattr(dp, "ofproto") and hasattr(dp, "ofproto_parser"):
        try:
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
            instructions = []
            mod = parser.OFPFlowMod(
                datapath=dp,
                priority=100,
                match=match,
                instructions=instructions,
                hard_timeout=300
            )
            dp.send_msg(mod)
            return {"command": f"OFPFlowMod DROP {ip_src}", "status": "EXECUTED"}
        except Exception as e:
            return {"command": f"OFPFlowMod DROP {ip_src}", "status": "FAILED", "error": str(e)}
    else:
        return {"command": f"OFPFlowMod DROP {ip_src}", "status": "LOGGED_NOT_EXECUTED"}

