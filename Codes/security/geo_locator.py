# -*- coding: utf-8 -*-
import json
import socket
import logging
import time
try:
    import urllib.request as urllib_request
except ImportError:
    import urllib2 as urllib_request

logger = logging.getLogger("GeoLocator")

class GeoLocator:
    """
    Resolves IP addresses to geographical location, ISP, Autonomous System (ASN),
    and country details using public IP APIs with local private network handling
    and a non-blocking circuit breaker to prevent SDN controller backlogs.
    """
    def __init__(self, cache_enabled=True):
        self.cache_enabled = cache_enabled
        self.geo_cache = {}
        self._circuit_breaker_until = 0

    def is_private_ip(self, ip_address):
        """Check if IP is local/private/Mininet virtual IP."""
        try:
            parts = [int(p) for p in ip_address.split(".")]
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127 or parts[0] == 0:
                return True
        except Exception:
            pass
        return False

    def locate_ip(self, ip_address):
        """
        Locate IP address and return dictionary of geographical info.
        """
        if not ip_address or ip_address == "0.0.0.0":
            return self._unknown_location(ip_address, "Invalid IP")

        if self.cache_enabled and ip_address in self.geo_cache:
            return self.geo_cache[ip_address]

        if self.is_private_ip(ip_address):
            res = {
                "ip": ip_address,
                "country": "Local / Private Network",
                "country_code": "LAN",
                "city": "Internal Mininet / Private Subnet",
                "isp": "Local Virtual Environment (Mininet)",
                "org": "Internal Network Host",
                "lat": 0.0,
                "lon": 0.0,
                "is_private": True
            }
            self.geo_cache[ip_address] = res
            return res

        # Non-blocking circuit breaker: if previous HTTP lookup timed out/failed,
        # skip remote HTTP for 30s so controller event loop never stalls.
        now = time.time()
        if now < self._circuit_breaker_until:
            res = self._unknown_location(ip_address, "Fast Offline Resolution")
            self.geo_cache[ip_address] = res
            return res

        # Public IP lookup via free API with 0.5s fast timeout
        try:
            url = "http://ip-api.com/json/" + str(ip_address) + "?fields=status,message,country,countryCode,city,isp,org,as,lat,lon,query"
            req = urllib_request.Request(url, headers={'User-Agent': 'DDoS-Detection-Tool/1.0'})
            resp = urllib_request.urlopen(req, timeout=0.5)
            data = json.loads(resp.read().decode('utf-8'))
            if data.get("status") == "success":
                    res = {
                        "ip": ip_address,
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "XX"),
                        "city": data.get("city", "Unknown"),
                        "isp": data.get("isp", "Unknown"),
                        "org": data.get("org", "Unknown"),
                        "asn": data.get("as", "Unknown"),
                        "lat": data.get("lat", 0.0),
                        "lon": data.get("lon", 0.0),
                        "is_private": False
                    }
                    self.geo_cache[ip_address] = res
                    return res
        except Exception as e:
            # Activate 30-second circuit breaker on failure/timeout
            self._circuit_breaker_until = now + 30
            logger.warning("GeoIP API timeout/failed for %s. Activated fast non-blocking mode for 30s. Reason: %s", ip_address, e)

        res = self._unknown_location(ip_address, "Lookup Failed")
        self.geo_cache[ip_address] = res
        return res

    def _unknown_location(self, ip_address, reason):
        return {
            "ip": ip_address,
            "country": "Unknown Location",
            "country_code": "UN",
            "city": reason,
            "isp": "Unknown ISP",
            "org": "Unknown Organization",
            "lat": 0.0,
            "lon": 0.0,
            "is_private": False
        }
