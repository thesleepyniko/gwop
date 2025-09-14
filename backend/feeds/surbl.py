# this is a dns checker, so we're going to need dns

import httpx
from pathlib import Path
import datetime
import json
from resources.parse_url import parse_url
import csv
import dotenv
import resources.definitions as definitions
from resources.cache import Cache
import dns.resolver
import dns
import redis

cache = Cache()

SURBL_BITMASK = {
    4: "disposable_mail",
    8: "phishing",
    16: "malware",
    32: "clicktracker",
    64: "abuse",
    128: "cracked"
}

def check_domain_surbl(domain):
    if not domain:
        return definitions.UrlCheckResponse(
                    result=definitions.Result.error,
                    is_threat=False,
                    via=definitions.Via.api,
                    source="surbl", 
                    threat_type=None, 
                    attributes=None,
                    confidence=definitions.Confidence.notapplicable,
                    error={"details": "empty string passed for domain"}
        )
    try:
        response=cache.get(domain)
        if response:
            return definitions.UrlCheckResponse.model_validate_json(response)
    except Exception:
        pass

    lists=[]
    try:
        query = f"{domain}.multi.surbl.org"
        answers = dns.resolver.resolve(query, "A")

        hits = [str(rdata) for rdata in answers]

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        response=definitions.UrlCheckResponse(
                    result=definitions.Result.miss,
                    is_threat=False,
                    via=definitions.Via.api,
                    source="surbl", 
                    threat_type=None,
                    attributes=None,
                    confidence=definitions.Confidence.high,
                    error=None
                 ) # NXDomain, means that this isn't valid
        cache.set(domain, response.model_dump_json())
        return response
    except Exception as e:
        response=response=definitions.UrlCheckResponse(
                    result=definitions.Result.error,
                    is_threat=False,
                    via=definitions.Via.api,
                    source="surbl", 
                    threat_type=None, 
                    attributes=None,
                    confidence=definitions.Confidence.notapplicable,
                    error={"details": str(e)}
        )
        cache.set(domain, response.model_dump_json(), ttl=15)
        return response
    
    
    for hit in hits:
        try:
            last_octet = int(hit.split(".")[-1])
            if last_octet == 1:
                response = definitions.UrlCheckResponse(
                    result=definitions.Result.error,
                    is_threat=False,
                    via=definitions.Via.api,
                    source="surbl",
                    threat_type=None,
                    attributes=None,
                    confidence=definitions.Confidence.notapplicable,
                    error={"details": "surbl blocked resolver (127.0.0.1 response)"}
                )
                cache.set(domain, response.model_dump_json(), ttl=3600)
                return response
            
            for bit, name in SURBL_BITMASK.items():
                if last_octet & bit:
                    lists.append(name)
        except ValueError:
            continue
    
    if lists:
        if "malware" in lists:
            threat_type = definitions.ThreatType.malware
        elif "phishing" in lists:
            threat_type = definitions.ThreatType.phishing
        elif len(lists) > 1:
            threat_type = definitions.ThreatType.mixed
        else:
            threat_type = definitions.ThreatType.other
        
        response = definitions.UrlCheckResponse(
            result = definitions.Result.hit,
            is_threat=True,
            via=definitions.Via.api,
            source="surbl",
            threat_type=threat_type,
            attributes={"raw": hits},
            confidence=definitions.Confidence.high,
            error=None
        )
        cache.set(domain, response.model_dump_json(), ttl=60)
        return response
    
    else:
        return definitions.UrlCheckResponse(
                    result=definitions.Result.miss,
                    is_threat=False,
                    via=definitions.Via.api,
                    source="surbl", 
                    threat_type=None, 
                    attributes={"raw": hits},
                    confidence=definitions.Confidence.high,
                    error=None
        )

