from enum import Enum

from pydantic import BaseModel

from typing import Union, Optional, List, Dict, Any

# enums that we want to use for each model
class Verdict(str, Enum):
    invalid = "invalid"
    clean = "clean"
    suspicious = "suspicious"
    malicious = "malicious"
    error = "error"

class Result(str, Enum):
    hit = "hit"
    miss = "miss"
    error = "error"

class Via(str, Enum):
    cache = "cache"
    api = "api"
    multi = "multi"
    none = "none"

class ThreatType(str, Enum):
    phishing = "phishing"
    malware = "malware"
    unknown = "unclassified"

class UrlCheckResponse(BaseModel):
    source: str
    result: Result
    via: Via
    is_threat: bool
    threat_type: Optional[ThreatType]
    attributes: Optional[Dict[str, Any]]
    error: Optional[dict]

class ClientResponse(BaseModel):
    verdict: Verdict
    is_threat: bool
    threat_type: Optional[ThreatType]
    confirmed_via: Via
    evidence: List[UrlCheckResponse]
    