class AttackTypeClassifier:
    """
    Classifies DDoS attack types based on network header features and flow stats.
    Categorizes attacks into: SYN Flood, ICMP Ping Flood, UDP Flood, LAND Attack, or Generic DDoS.
    """
    @staticmethod
    def classify_attack(ip_proto, tp_src, tp_dst, icmp_type, packet_count, byte_count, flow_duration_sec, flags=0):
        """
        Determine the specific DDoS vector type.
        """
        # LAND Attack detection (Same source and destination port/IP)
        if tp_src == tp_dst and tp_src != 0 and tp_src is not None:
            return "LAND Attack"

        # Protocol based classification
        # ICMP (Protocol 1)
        if ip_proto == 1 or icmp_type != -1:
            if packet_count >= 150:
                return "150 ICMP Continuous Ping Flood"
            return "ICMP Echo Flood"

        # UDP (Protocol 17)
        if ip_proto == 17:
            if tp_dst in [137, 138, 139] or tp_src in [137, 138, 139]:
                return "NetBIOS Reflection & Amplification Attack (UDP 137/138)"
            elif tp_dst in [53, 123, 1900] or tp_src in [53, 123, 1900]:
                return "UDP Amplification Attack (DNS/NTP/SSDP)"
            elif tp_dst in [389, 11211] or tp_src in [389, 11211]:
                return "UDP Amplification Attack (CLDAP/Memcached)"
            return "UDP Flood Attack"

        # TCP (Protocol 6)
        if ip_proto == 6:
            # Flags check: 2 = SYN flag
            if flags == 2 or flags == 0x02:
                return "TCP SYN Flood"
            elif flags == 16 or flags == 0x10:
                return "TCP ACK Flood"
            else:
                return "TCP Flood"

        # General high packet rate heuristic fallback
        avg_pkt_size = byte_count / max(packet_count, 1)
        if avg_pkt_size < 100:
            return "Small Packet Volumetric DDoS"

        return "Generic Volumetric DDoS"
