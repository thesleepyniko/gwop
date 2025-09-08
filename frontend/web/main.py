from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from reactpy import component, html, run, use_state
from reactpy.backend.fastapi import configure, Options
from reactpy.html import head, link, script, title, span, meta
from reactpy_router import browser_router, route
import httpx
from pydantic import BaseModel

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

head_content = head(
        meta({"charset": "UTF-8"}),
        link({"rel": "stylesheet", "href": "/resources/main.css"}),
        link({"rel": "preconnect", "href": "https://fonts.googleapis.com"}),
        link({"rel": "preconnect", "href": "https://fonts.gstatic.com", "crossorigin": ""}),
        link({"rel": "stylesheet","href": "https://fonts.googleapis.com/css2?family=Inter:ital,opsz,wght@0,14..32,100..900;1,14..32,100..900&display=swap"}),
        link({"rel": "stylsheet", "href": "https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,100..800;1,100..800&display=swap"}),
        html.title("gwop")
    )

@component
def main(theme, set_theme):

    def change_theme(event):
        print("changing event")
        print(theme)
        if theme == "dark":
            set_theme("light")
        else:
            set_theme("dark")

    return html.div(
        {"class": "flex items-center justify-center h-screen transition-colors duration-500 ease-in-out" + (" bg-zinc-900" if theme == "dark" else " bg-white")},
        html.div(
            {"class": "w-[40%] text-left overflow-auto no-scrollbar transition-colors duration-500 ease-in-out" + (" text-zinc-100" if theme == "dark" else " text-black")},
            html.button(
                {"class": "absolute top-3 right-3 px-3 py-1 rounded bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-200",
                 "id": "theme-toggle",
                 "on_click": change_theme},
                 "🌙" if theme == "light" else "☀️"
            ),
            html.h1(
                {"class": "font-['JetBrains_Mono',monospace] text-[clamp(1rem,2vw,2rem)] text-3xl"},
                "gwop (great wall of phish)",
                span(
                    {"class": "blinking-cursor", "aria-hidden": "true", "role": "presentation"},
                    "_"
                )
            ),
            html.p(
                {"class": "font['Inter', font-sans] text-[clamp(1rem,1.3vw,1.6rem)] text-1xl"},
                "gwop is a frontend that aggregates multiple threat intelligence APIs to check for phishing and malicious sites. free to use and ",
                html.a(
                    {"href": "https://github.com/thesleepyniko/gwop"},
                    "open source"
                ),
                " on GitHub. learn a little more about what gwop does ",
                html.a(
                    {"href": "about"},
                    "here."
                )
            ),
            html.hr(
                {"class": "my-8 border-t border-gray-300", "aria-hidden": "true"}
            ),
            html.h1(
                {"class": "font['Inter', font-sans] text-[clamp(1rem,2vw,2rem)] text-3xl"},
                "ways to use gwop:"
            ),
            html.p(
                {"class": "font['Inter', font-sans] text-[clamp(1rem,1.3vw,1.6rem)] text-1xl"},
                html.a(
                    {"href": "/scan"},
                    "web"
                ),
                html.br(),
                html.a(
                    {"href": "#"},
                    "cli"
                )
            )
        )
    )

@component
def about():
    return html.div(
        {"class": "flex items-center justify-center h-screen"},
        html.div(
            {"class": "w-[40%] text-left overflow-auto no-scrollbar"},
            html.h1(
                {"class": "font-['JetBrains_Mono',monospace] text-[clamp(1rem,2vw,2rem)] text-3xl"},
                "about gwop",
                span(
                    {"class": "blinking-cursor", "aria-hidden": "true", "role": "presentation"},
                    "_"
                )
            ),
            html.p(
                {"class": "font['Inter', font-sans] text-[clamp(1rem,1.3vw,1.6rem)] text-1xl"},
                "gwop primarily pulls from ",
                html.a(
                    {"href": "https://github.com/phishdirectory/api"},
                    "phish.directory"
                ),
                " as it's main api. for availability, gwop will also attempt to contact upstream providers that phish.directory uses in the event it is down, such as URLHaus. finally, gwop uses some of it's own heuristics for maliciousness."
            ),
            html.hr(
                {"class": "my-8 border-t border-gray-300", "aria-hidden": "true"}
            ),
            html.p(
                {"class": "font['Inter', font-sans] text-[clamp(1rem,1.3vw,1.6rem)] text-1xl"},
                html.a(
                    {"href": "/"},
                    "return home"
                ),
            )
        )
    )

def create_result_overview():
    pass
    

@component
def scan_link():
    
    SERVER_LINK = "http://127.0.0.1:5500"
    text, set_text = use_state("")
    error, set_error_message = use_state("")
    is_error, set_is_error = use_state(False)

    def handle_change(event):
        set_text(event["target"]["value"])
    
    def send_link_to_server(event):
        if not text.strip():
            set_error_message("URL cannot be empty!")
            set_is_error(True)
            return
        elif not (text.startswith("http://") or text.startswith("https://")):
            set_error_message("URL must start with http:// or https://!")
            set_is_error(True)
            return
        else:
            response = httpx.post(
                f"{SERVER_LINK}/check-url",
                json={"link": text.strip()})
            if response.status_code != 200:
                set_is_error(True)
                set_error_message(response.text)
            set_is_error(True)
            set_error_message(response.text)

    return html.div(
        {"class": "flex items-center justify-center h-screen"},
        html.div(
            {"class": "w-[40%] text-left overflow-auto no-scrollbar"},
            html.h1(
                {"class": "font-['JetBrains_Mono',monospace] text-[clamp(1rem,2vw,2rem)] text-3xl"},
                "gwop web",
                span(
                    {"class": "blinking-cursor", "aria-hidden": "true", "role": "presentation"},
                    "_"
                )
            ),
            html.p(
                {"class": "font['Inter', font-sans] text-[clamp(1rem,1.3vw,1.6rem)] text-1xl"},
                "scan a link by inputting below"
            ),
            html.input(
                {"class": "shadow appearance-none border border-gray-500 rounded w-[70%] py-2 px-3 text-gray-700 mb-3 leading-tight focus:outline-none focus:shadow-outline h-8",
                 "id": "link",
                 "type": "link",
                 "placeholder": "example.com",
                 "on_change": handle_change}
            ),
            html.p(
                {"class": "font['Inter', font-sans] text-[clamp(.6rem,.8vw,1rem)] text-1xl" + 
                 (" text-red-600" if is_error else "")},
                error
            ),
            html.button(
                {"class": "bg-gray-500 hover:bg-gray-400 text-white font-bold py-2 px-4 border-gray-700 hover:border-gray-500 rounded",
                 "id":"submit_link",
                 "on_click": send_link_to_server
                },
                "scan link"
            ),
            html.p(
                {"class": "font['Inter', font-sans] text-[clamp(1rem,1.3vw,1.6rem)] text-1xl"},
                html.a(
                    {"href": "/"},
                    "return home"
                )
            )

        )
    )

@component
def page_not_found():
    return html.div(
        {"class": "flex items-center justify-center h-screen"},
        html.div(
            {"class": "w-[40%] text-left overflow-auto no-scrollbar"},
            html.h1(
                {"class": "font-['JetBrains_Mono',monospace] text-[clamp(1rem,2vw,2rem)] text-3xl"},
                "404",
                span(
                    {"class": "blinking-cursor", "aria-hidden": "true", "role": "presentation"},
                    "_"
                )
            ),
            html.p(
                {"class": "font['Inter', font-sans] text-[clamp(1rem,1.3vw,1.6rem)] text-1xl"},
                "the link you tried to access could not be found."
            ),
            html.p(
                {"class": "font['Inter', font-sans] text-[clamp(.6rem,.8vw,1rem)] text-1xl"},
                "Here we are, at the eleventh hour.",
            ),
            html.hr(
                {"class": "my-8 border-t border-gray-300", "aria-hidden": "true"}
            ),
            html.p(
                {"class": "font['Inter', font-sans] text-[clamp(1rem,1.3vw,1.6rem)] text-1xl"},
                html.a(
                    {"href": "/"},
                    "return home"
                ),
            )
        )
    )

@component
def app_router():
    theme, set_theme = use_state("light")
    return browser_router(
        route("/", main(theme, set_theme)),
        route("/about", about()),
        route("/scan", scan_link()),
        route("{404:any}", page_not_found()),
    )

app = FastAPI()
app.mount("/resources", StaticFiles(directory="resources"), name="resources")
configure(app, app_router, Options(head=head_content))

