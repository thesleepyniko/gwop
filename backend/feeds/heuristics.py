import httpx
from urllib.parse import urlparse
import tldextract
import resources.definitions as definitions
import datetime
"""Domain age
Domain entropy (random-looking subdomains)
Phishing keywords in subdomain/path
Suspicious TLDs
Excessive path length"""

def check_heuristic(url: str, is_ip = False):
    #first, check tlds
    detections = {"score": 0, "whois": "", "entropy": "", "length": ""}
    if not is_ip:
        try:
            domain=tldextract.extract(url)
            if not domain.suffix:
                detections["whois"] = definitions.UrlCheckResponse(
                        result=definitions.Result.error,
                        is_threat=False,
                        via=definitions.Via.api,
                        source="heuristics", 
                        threat_type=None,
                        attributes=None,
                        error={"details": "Invalid URL"}
                    )
                detections["score"] = 0
                return detections
            rdap_response = httpx.get(f"https://www.rdap.net/domain/{domain.domain}.{domain.suffix}")
            if rdap_response.status_code == 200:
                response=rdap_response.json()
                domain_events = response.get("events", "")
                if domain_events:
                    for event in domain_events:
                        if event.get("eventAction", "") == "registration":
                            now = datetime.datetime.now()
                            reg_date: datetime.datetime = event.get("eventDate", now).fromisoformat()
                            if (now - reg_date).days <= 7:
                                detections["whois"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.hit,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="heuristics", 
                                    threat_type=None,
                                    attributes={"detail": "within 7 days", "score_add": 2},
                                    error=None
                                )
                                detections["score"] += 2
                            elif (now - reg_date).days <= 30:
                                detections["whois"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.hit,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="heuristics", 
                                    threat_type=None,
                                    attributes={"detail": "within 30 days", "score_add": 1},
                                    error=None
                                )
                                detections["score"] += 1
                            else:
                                detections["whois"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.miss,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="heuristics", 
                                    threat_type=None,
                                    attributes={"detail": "older than 30 days", "score_add": 0},
                                    error=None
                                )
        except Exception as e:
            detections["whois"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.error,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="heuristics", 
                                    threat_type=None,
                                    attributes={"detail": e},
                                    error=None
                                )

    elif is_ip:
        pass
    pass