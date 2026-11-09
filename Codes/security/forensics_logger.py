# -*- coding: utf-8 -*-
import os
import json
import logging
import time
from datetime import datetime

class ForensicsLogger:
    """
    Detailed DDoS attack forensics logger and forensic report generator.
    Logs attacker profiles, victim targets, mitigation actions, and timestamps.
    """
    def __init__(self, log_dir="attack_logs", report_file="attack_forensics_report.json"):
        self.log_dir = log_dir
        self.report_file = report_file
        self.incidents = []

        if not os.path.exists(self.log_dir):
            try:
                os.makedirs(self.log_dir)
            except Exception:
                pass

    def log_incident(self, attacker_ip, victim_ip, attack_type, threat_score, geo_info, mitigation_action):
        """
        Record an attack incident entry with timestamp and telemetry.
        """
        now_dt = datetime.now()
        ts = int(time.time())
        incident = {
            "incident_id": "INC-" + str(ts),
            "timestamp": now_dt.isoformat(),
            "attacker_ip": attacker_ip,
            "victim_ip": victim_ip,
            "attack_type": attack_type,
            "threat_score": threat_score,
            "geolocation": geo_info,
            "mitigation_action": mitigation_action,
            "status": "MITIGATED"
        }
        self.incidents.append(incident)
        self._write_to_file(incident)
        return incident

    def _write_to_file(self, incident):
        # Write individual incident log file
        filename = os.path.join(self.log_dir, "incident_" + str(incident['incident_id']) + ".json")
        try:
            with open(filename, "w") as f:
                json.dump(incident, f, indent=4)
        except Exception as e:
            logging.error("Failed to write forensic log: %s", e)

        # Update master report file
        master_path = os.path.join(self.log_dir, self.report_file)
        try:
            with open(master_path, "w") as f:
                json.dump(self.incidents, f, indent=4)
        except Exception as e:
            logging.error("Failed to update master forensic report: %s", e)

    def generate_summary(self):
        """Generate high-level forensic summary of all recorded attack incidents."""
        total_incidents = len(self.incidents)
        unique_attackers = len(set(i["attacker_ip"] for i in self.incidents))
        unique_victims = len(set(i["victim_ip"] for i in self.incidents))
        attack_types = {}
        countries = {}

        for inc in self.incidents:
            atype = inc["attack_type"]
            attack_types[atype] = attack_types.get(atype, 0) + 1

            country = inc.get("geolocation", {}).get("country", "Unknown")
            countries[country] = countries.get(country, 0) + 1

        return {
            "total_incidents": total_incidents,
            "unique_attackers": unique_attackers,
            "unique_victims": unique_victims,
            "attack_type_breakdown": attack_types,
            "attacker_country_breakdown": countries,
            "last_incident_time": self.incidents[-1]["timestamp"] if self.incidents else None
        }
