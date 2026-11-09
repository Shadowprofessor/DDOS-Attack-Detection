import time
import logging

class ThreatIntelligence:
    """
    Manages IP blacklist/whitelist dynamic entries, IP reputation scoring,
    and automatic expiration for mitigated attacker IPs.
    """
    def __init__(self, default_block_duration_sec=300):
        self.default_block_duration = default_block_duration_sec
        # ip -> expire timestamp
        self.blacklist = {}
        # ip set
        self.whitelist = set()
        # ip -> reputation score (0 = clean, 100 = malicious)
        self.ip_reputation = {}

    def add_to_whitelist(self, ip_address):
        self.whitelist.add(ip_address)
        if ip_address in self.blacklist:
            del self.blacklist[ip_address]
        self.ip_reputation[ip_address] = 0

    def blacklist_ip(self, ip_address, duration_sec=None):
        if ip_address in self.whitelist:
            return False  # Whitelisted IP cannot be blocked

        duration = duration_sec if duration_sec is not None else self.default_block_duration
        expire_time = time.time() + duration
        self.blacklist[ip_address] = expire_time
        self.ip_reputation[ip_address] = 100
        return True

    def is_blacklisted(self, ip_address):
        if ip_address in self.whitelist:
            return False

        if ip_address in self.blacklist:
            expire_time = self.blacklist[ip_address]
            if time.time() < expire_time:
                return True
            else:
                # Expired blacklist entry
                del self.blacklist[ip_address]
                self.ip_reputation[ip_address] = 30  # Reduced score after expiration
                return False
        return False

    def get_reputation(self, ip_address):
        if ip_address in self.whitelist:
            return 0
        return self.ip_reputation.get(ip_address, 0)

    def get_active_blacklist(self):
        current_time = time.time()
        active = {}
        expired = []
        for ip, exp in self.blacklist.items():
            if current_time < exp:
                active[ip] = {
                    "expires_in_sec": int(exp - current_time),
                    "reputation": self.ip_reputation.get(ip, 100)
                }
            else:
                expired.append(ip)

        for ip in expired:
            del self.blacklist[ip]

        return active
