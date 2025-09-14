import httpx
from urllib.parse import urlparse
import tldextract
import resources.definitions as definitions
from resources.shannon_entropy import entropy
import datetime
from datetime import timezone
from dateutil import parser

def check_heuristic(url: str, is_ip = False):
    #first, check tlds
    detections = {"score": 0, "age": None, "entropy": None, "length": None, "cidr": None}
    # whois is the domain age check
    # entropy checks for randomness
    # length is just a simple length check
    domain_obj=tldextract.extract(url)
    domain = f"{domain_obj.domain}.{domain_obj.suffix}"
    print(domain)
    print(domain_obj)
    print(is_ip)
    if not is_ip:
        try:
            # domain age detection
            if not domain_obj.suffix:
                detections["age"] = definitions.UrlCheckResponse(
                        result=definitions.Result.error,
                        is_threat=False,
                        via=definitions.Via.api,
                        source="heuristics", 
                        threat_type=None,
                        attributes=None,
                        confidence=definitions.Confidence.notapplicable,
                        error={"details": "Invalid URL"}
                    )
                detections["score"] = 0
                return detections
            try:
                rdap_response = httpx.get(f"https://www.rdap.net/domain/{domain}", follow_redirects=True, timeout=5)
            except httpx.RequestError as e:
                return {
                    "score": 0,
                    "age": None,
                    "entropy": None,
                    "length": None,
                    "cidr": None,
                }
            print("RDAP status:", rdap_response.status_code)
            print("RDAP body:", rdap_response.text)
            if rdap_response.status_code == 200:
                response=rdap_response.json()
                domain_events = response.get("events", [])
                if domain_events:
                    for event in domain_events:
                        if event.get("eventAction", "") == "registration":
                            now = datetime.datetime.now(timezone.utc)
                            raw_date = event.get("eventDate")
                            reg_date = parser.parse(raw_date).astimezone(timezone.utc)
                            if reg_date is None:
                                detections["age"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.error,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="rdap.net",
                                    threat_type=None,
                                    attributes=None,
                                    confidence=definitions.Confidence.notapplicable,
                                    error={"details": "no registration date"}
                                )
                                break
                            age_days = (now - reg_date).days
                            if age_days <= 7:
                                detections["age"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.hit,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="rdap.net", 
                                    threat_type=None,
                                    attributes={"detail": "within 7 days", "score_add": 2},
                                    confidence=definitions.Confidence.low,
                                    error=None
                                )
                                detections["score"] += 2
                            elif age_days <= 30:
                                detections["age"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.hit,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="rdap.net", 
                                    threat_type=None,
                                    attributes={"detail": "within 30 days", "score_add": 1},
                                    confidence=definitions.Confidence.low,
                                    error=None
                                )
                                detections["score"] += 1
                            else:
                                detections["age"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.miss,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="rdap.net", 
                                    threat_type=None,
                                    attributes={"detail": "older than 30 days", "score_add": 0},
                                    confidence=definitions.Confidence.low,
                                    error=None
                                )
        except Exception as e:
            detections["age"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.error,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="rdap.net", 
                                    threat_type=None,
                                    attributes=None,
                                    confidence=definitions.Confidence.notapplicable,
                                    error={"details": str(e)}
                                )
        
        # entropy detection
        ent = entropy(domain)
        try:
            if len(domain) >= 6:
                
                if ent >= 4:
                    detections["entropy"] = definitions.UrlCheckResponse(
                                            result=definitions.Result.hit,
                                            is_threat=False,
                                            via=definitions.Via.heuristic,
                                            source="entropy", 
                                            threat_type=None,
                                            attributes={"detail": "entropy >= 4", "score_add": 2},
                                            confidence=definitions.Confidence.low,
                                            error=None
                                        )
                    detections["score"] += 2
                elif ent >= 3.5:
                    detections["entropy"] = definitions.UrlCheckResponse(
                                            result=definitions.Result.hit,
                                            is_threat=False,
                                            via=definitions.Via.heuristic,
                                            source="entropy", 
                                            threat_type=None,
                                            attributes={"detail": "4 > entropy >= 3.5", "score_add": 1},
                                            confidence=definitions.Confidence.low,
                                            error=None
                                        )
                    detections["score"] += 1
                else:
                    detections["entropy"] = definitions.UrlCheckResponse(
                                            result=definitions.Result.miss,
                                            is_threat=False,
                                            via=definitions.Via.heuristic,
                                            source="entropy", 
                                            threat_type=None,
                                            attributes={"detail": "3.5 > entropy", "score_add": 0},
                                            confidence=definitions.Confidence.low,
                                            error=None
                                        )
            else:
                detections["entropy"] = definitions.UrlCheckResponse(
                                            result=definitions.Result.miss,
                                            is_threat=False,
                                            via=definitions.Via.heuristic,
                                            source="entropy", 
                                            threat_type=None,
                                            attributes={"detail": "too short", "score_add": 0},
                                            confidence=definitions.Confidence.low,
                                            error=None
                                        )
        except Exception as e:
            detections["entropy"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.error,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="entropy", 
                                    threat_type=None,
                                    attributes={"detail": str(e)},
                                    confidence=definitions.Confidence.notapplicable,
                                    error=None
                                )
        # length check
        if len(domain) >= 20:
            detections["length"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.hit,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="domain_length", 
                                    threat_type=None,
                                    attributes={"detail": "length of domain >= 20", "score_add": 2},
                                    confidence=definitions.Confidence.low,
                                    error=None
                                )
            detections["score"]+=2
        elif len(domain) >= 12 and ent >= 3.8:
            detections["length"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.hit,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="domain_length", 
                                    threat_type=None,
                                    attributes={"detail": "length of domain >= 12 and ent >= 3.8", "score_add": 1},
                                    confidence=definitions.Confidence.low,
                                    error=None
                                )
            detections["score"]+=1
        else:
            detections["length"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.miss,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="domain_length", 
                                    threat_type=None,
                                    attributes={"detail": "12 > domain length", "score_add": 0},
                                    confidence=definitions.Confidence.low,
                                    error=None
                                )
        return detections
    elif is_ip:
        # date check
        ip = urlparse(url).hostname if urlparse(url).hostname else url
        try:
            rdap_response = httpx.get(f"https://www.rdap.net/ip/{ip}", follow_redirects=True)
        except httpx.RequestError as e:
                return {
                    "score": 0,
                    "age": None,
                    "entropy": None,
                    "length": None,
                    "cidr": None,
                }
        if rdap_response.status_code == 200:
            response=rdap_response.json()
            domain_events = response.get("events", [])
            try:
                if domain_events:
                    for event in domain_events:
                        if event.get("eventAction", "") == "registration":
                            now = datetime.datetime.now(timezone.utc)
                            raw_date = event.get("eventDate")
                            reg_date = parser.parse(raw_date).astimezone(timezone.utc)
                            if reg_date is None:
                                detections["age"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.error,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="rdap.net",
                                    threat_type=None,
                                    attributes=None,
                                    confidence=definitions.Confidence.notapplicable,
                                    error={"details": "no registration date"}
                                )
                                break  
                            age_days = (now - reg_date).days
                            if age_days <= 7:
                                detections["age"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.hit,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="rdap.net", 
                                    threat_type=None,
                                    attributes={"detail": "within 7 days", "score_add": 2},
                                    confidence=definitions.Confidence.low,
                                    error=None
                                )
                                detections["score"] += 2
                            elif age_days <= 30:
                                detections["age"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.hit,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="rdap.net", 
                                    threat_type=None,
                                    attributes={"detail": "within 30 days", "score_add": 1},
                                    confidence=definitions.Confidence.low,
                                    error=None
                                )
                                detections["score"] += 1
                            else:
                                detections["age"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.miss,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="rdap.net", 
                                    threat_type=None,
                                    attributes={"detail": "older than 30 days", "score_add": 0},
                                    confidence=definitions.Confidence.low,
                                    error=None
                                )
            except Exception as e:
                detections["age"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.error,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="rdap.net", 
                                    threat_type=None,
                                    attributes=None,
                                    confidence=definitions.Confidence.notapplicable,
                                    error={"details": str(e)}
                                )
            # cidr check
            try:
                if response.get("cidr0_cidrs", []):
                    for cidr_info in response.get("cidr0_cidrs"):
                        if cidr_info.get("length", 24) >= 29:
                            detections["cidr"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.hit,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="rdap.net", 
                                    threat_type=None,
                                    attributes={"detail": "smaller than cidr 29", "score_add": 2},
                                    confidence=definitions.Confidence.low,
                                    error=None
                                )
                            detections["score"] += 2
                        elif cidr_info.get("length", 24) >= 24:
                            detections["cidr"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.hit,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="rdap.net", 
                                    threat_type=None,
                                    attributes={"detail": "smaller than cidr 24", "score_add": 1},
                                    confidence=definitions.Confidence.low,
                                    error=None
                                )
                            detections["score"] += 1
                        else:
                            detections["cidr"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.miss,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="rdap.net", 
                                    threat_type=None,
                                    attributes={"detail": "larger than cidr 24", "score_add": 0},
                                    confidence=definitions.Confidence.low,
                                    error=None
                                )
            except Exception as e:
                detections["cidr"] = definitions.UrlCheckResponse(
                                    result=definitions.Result.error,
                                    is_threat=False,
                                    via=definitions.Via.heuristic,
                                    source="rdap.net", 
                                    threat_type=None,
                                    attributes=None,
                                    confidence=definitions.Confidence.notapplicable,
                                    error={"details": str(e)}
                                )
        return detections
    return detections