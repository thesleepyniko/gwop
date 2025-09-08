from enum import Enum

from pydantic import BaseModel, model_validator, HttpUrl

from typing import Union, Optional, List, Dict, Any

class Weights(str, Enum):
    gsb = 1.0
    AbuseCh = 0.9
    SinkingYahts=0.9
    PhishObserver=0.8
    PhishReport=0.8
    IpQuality=0.5
    Walshy=0.5
    VirusTotal=0.5

# enums that we want to use for each response, just for easier returns persay
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
    other = "other"
    mixed = "mixed"
    unknown = "unclassified"

class UrlCheckRequest(BaseModel):
    link: HttpUrl

class UrlCheckResponse(BaseModel):
    source: str
    result: Result
    via: Via
    is_threat: bool
    threat_type: Optional[ThreatType]
    attributes: Optional[Dict[str, Any]]
    error: Optional[dict]
    @model_validator(mode="after")
    def enforce_consistency(self) -> "UrlCheckResponse":
        if self.result == Result.error and self.error is None: # if there are no error details we need to make sure there are for logging
            raise ValueError("Response with result=error must include details of error!")
        
        if self.result == Result.miss: # not a threat so we unset threat_type and set is_threat to false
            self.is_threat = False
            self.threat_type = None
        
        if self.is_threat is False: # if threat type was set to False or None but self.result not Result.miss, we unset threat_type
            self.result = Result.miss
            self.threat_type = None
        
        if self.is_threat and self.threat_type is None: # if there is a threat but we do not know the type, then set it to ThreatType.unknown
            self.threat_type = ThreatType.unknown
        
        return self


class ClientResponse(BaseModel):
    verdict: Verdict
    is_threat: bool
    threat_type: Optional[ThreatType]
    confirmed_via: Via
    # the following three are to allow the front page to figure out what to display for each provider
    flagged_by: List[str]
    cleared_by: List[str]
    errored_by: List[str]
    error: Optional[str]
    evidence: List[UrlCheckResponse]

    @model_validator(mode="after")
    def enforce_threat_consistency(self) -> "ClientResponse":
        if self.verdict in {Verdict.malicious, Verdict.suspicious}: # if it is malicious or suspcious, mark as threat
            self.is_threat = True

        elif self.verdict in {Verdict.clean}: # otherwise we just mark it as not a threat
            self.is_threat = False
            self.threat_type = None

        return self