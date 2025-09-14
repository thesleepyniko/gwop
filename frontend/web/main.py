from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from reactpy import component, html, run, use_state, use_effect
from reactpy.backend.fastapi import configure, Options
from reactpy.html import head, link, script, title, span, meta
from reactpy_router import browser_router, route
from urllib.parse import urlparse
import httpx
from pydantic import BaseModel
import datetime
from definitions import ClientResponse, ThreatType, Via, Verdict, UrlCheckResponse, Result
import asyncio
import json
import yaml
import base64

head_content = head(
        meta({"charset": "UTF-8"}),
        link({"rel": "stylesheet", "href": "/resources/main.css"}),
        link({"rel": "preconnect", "href": "https://fonts.googleapis.com"}),
        link({"rel": "preconnect", "href": "https://fonts.gstatic.com", "crossorigin": ""}),
        link({"rel": "stylesheet","href": "https://fonts.googleapis.com/css2?family=Inter:ital,opsz,wght@0,14..32,100..900;1,14..32,100..900&display=swap"}),
        link({"rel": "stylesheet", "href": "https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,100..800;1,100..800&display=swap"}),
        html.title("gwop")
    )

@component
def main():

    return html.div(
        {"class": "flex items-center justify-center min-h-screen transition-colors duration-500 ease-in-out bg-zinc-900"},
        html.div(
            {"class": "w-[40%] text-left overflow-auto no-scrollbar transition-colors duration-500 ease-in-out text-zinc-100"},
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
        {"class": "flex items-center justify-center min-h-screen transition-colors duration-500 ease-in-out bg-zinc-900"},
        html.div(
            {"class": "w-[40%] text-left overflow-auto no-scrollbar transition-colors duration-500 ease-in-out text-zinc-100"},
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
                """ as it's main api. for availability, gwop will also attempt to contact upstream
                providers that phish.directory uses in the event it is down, such as URLHaus. finally,  
                gwop uses some of it's own heuristics for maliciousness.
                if one provider flags, gwop flags as malicious (as a false positive is better than a false negative.)"""
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

def is_valid_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme in ["http", "https"] and bool(parsed.netloc)
    except Exception:
        return False

def create_evidence_list(resp: ClientResponse):
    items=[]
    for i in resp.evidence:
        items.append(create_individual_tag(i))
    items.append(create_heuristics_tag(resp))
    if len(items) % 2 == 1:
        items[-1] = html.div(
            {"class": "col-span-full"},
            items[-1]
        )

    return items
def create_result_overview(result: ClientResponse, scanned_at):
    threat_type_labels = {
        ThreatType.phishing: "phishing",
        ThreatType.malware: "malware",
        ThreatType.other: "other threat",
        ThreatType.mixed: "mixed/multiple",
        ThreatType.unknown: "unclassified",
    }
    verdict_map = {
        Verdict.invalid: "invalid",
        Verdict.clean: "clean",
        Verdict.suspicious: "suspicious",
        Verdict.malicious: "malicious",
        Verdict.error: "error",
    }

    if result.threat_type:
        label = threat_type_labels.get(result.threat_type, ThreatType.unknown)
    else:
        label = "unclassified"
    
    if any(source.is_threat for source in result.evidence):
        mapped = Verdict.malicious

    else:
        score = result.heuristics.get("score")
        if isinstance(score, int):
            if score >= 5:
                mapped = Verdict.malicious
            elif score >= 3:
                mapped = Verdict.suspicious
            else:
                mapped = Verdict.clean
        else:
            mapped = Verdict.clean

    verdict = verdict_map.get(mapped, Verdict.error)

    class_name = "font['Inter', font-sans] text-[clamp(.6rem,.8vw,1rem)] text-1xl"
    return html.div(
        {"class": "rounded-xl border border-gray-400 p-6 shadow-md bg-zinc-800 text-zinc-100 mt-6 mb-4"},
        html.p(
            {"class": "font['Inter', font-sans] text-[clamp(.8rem,1.5vw,2rem)] text-1xl"},
            f"verdict: {verdict}"
        ),
        html.p(
            {"class": class_name},
            f"threat type: {label}"
        ),
        html.p(
            {"class": class_name},
            f"scanned at: {scanned_at}"
        ),
        html.p(
            {"class": class_name},
            f"{len(result.flagged_by)}/{len(result.cleared_by) + len(result.flagged_by) + len(result.errored_by)} flagged"
        ),
        html.p(
            {"class": class_name},
            f"encountered {len(result.errored_by)} errors while scanning"
        ),
        html.p(
            {"class": class_name},
            f"our heuristics ranked this a {result.heuristics.get("score")}/{6 if not result.heuristics.get("cidr", None) else 4}"
        )      
    )

def create_heuristics_tag(result: ClientResponse):
    via_map = {
        Via.cache: "local cache",
        Via.api:   "api",
        Via.multi: "combined",
        Via.none:  "n/a",
    }
    heuristics = result.heuristics

    error_span=span(
        {"class": "px-3 py-1 text-xs rounded bg-orange-100 text-orange-700"},
        "Error"
    )
    clean_span=span(
        {"class": "px-3 py-1 text-xs rounded bg-green-100 text-green-700"},
        "Clean"
    )
    flag_span=span(
        {"class": "px-3 py-1 text-xs rounded bg-red-100 text-red-700"},
        "Flagged"
    )
    if result.error:
        badge = error_span
    elif result.heuristics_is_threat:
        badge = flag_span
    else:
        badge = clean_span
    heuristics_info = []
    for key, value in heuristics.items():
        if key == "score":
            continue

        if isinstance(value, UrlCheckResponse):
            score_add = 0
            if value.attributes and isinstance(value.attributes, dict):
                score_add = value.attributes.get("score_add", 0)
            detail = value.attributes.get("detail") if value.attributes else "n/a"

            heuristics_info.append(html.p(f"{key} threat score: {score_add}/2 ({detail})"))

        else:
            heuristics_info.append(html.p(f"{key} threat score: not available"))

    return html.details(
        {"class": "rounded-xl border border-gray-400 p-4 shadow-md bg-zinc-700"},
        html.summary(
            {"class": "cursor-pointer font-bold text-lg flex items-center gap-2"},
            html.span("heuristics"),
            badge,
        ),
        html.div(
            {"class": "mt-2 space-y-1 text-sm"},
            html.p(
                "flagged: " + ("yes" if badge == flag_span else "no")
            ),
            html.p(
                "recieved score of " + str(heuristics.get("score"))
            ),
            html.p(
                f"confirmed via: mixed"
            ),
            html.p(
                f"error: {result.error}" if result.error else ""
            ),
            *heuristics_info
        )
    )

def create_individual_tag(result: UrlCheckResponse):
    via_map = {
        Via.cache: "local cache",
        Via.api:   "api",
        Via.multi: "combined",
        Via.none:  "n/a",
    }
    via_label = via_map.get(result.via, str(result.via))

    error_span=span(
        {"class": "px-2 py-1 text-xs rounded bg-orange-100 text-orange-700"},
        "Error"
    )
    clean_span=span(
        {"class": "px-2 py-1 text-xs rounded bg-green-100 text-green-700"},
        "Clean"
    )
    flag_span=span(
        {"class": "px-2 py-1 text-xs rounded bg-red-100 text-red-700"},
        "Flagged"
    )
    if result.result == Result.error:
        badge = error_span
    elif result.is_threat:
        badge = flag_span
    else:
        badge = clean_span
    return html.details(
        {"class": "rounded-xl border border-gray-400 p-4 shadow-md bg-zinc-700"},
        html.summary(
            {"class": "cursor-pointer font-bold text-lg flex items-center gap-2"},
            html.span(result.source),
            badge,
        ),
        html.div(
            {"class": "mt-2 space-y-1 text-sm"},
            html.p(
                "flagged: " + ("yes" if badge == flag_span else "no")
            ),
            html.p(
                f"confirmed via: {via_label}"
            ),
            html.p(
                f"error: {result.error}" if result.error and result.error.get("details", {}).get("query_status") != "ok" else ""
            )
        )
    )



@component
def scan_link():
    
    SERVER_LINK = "http://127.0.0.1:8000"
    text, set_text = use_state("")
    error, set_error_message = use_state("")
    is_error, set_is_error = use_state(False)
    result, set_result = use_state(None)
    scan_time, set_scan_time = use_state("")
    yaml_link, set_yaml_link = use_state("")
    json_link, set_json_link = use_state("")

    def handle_change(event):
        set_text(event["target"]["value"])
    
    
    def send_link_to_server(event):
        # show loading state first
        set_is_error(True)
        set_error_message("scanning, please wait...")

        async def do_request():
            if not text.strip():
                set_error_message("url cannot be empty")
                set_is_error(True)
                return
            elif not is_valid_url(text.strip()):
                set_error_message("start your url with http or https! (if it is an ip, prepend http://)")
                set_is_error(True)
                return
            try:
                response = await httpx.AsyncClient().post(
                    f"{SERVER_LINK}/check-url",
                    json={"link": text.strip()},
                    timeout=20.0
                )
                if response.status_code != 200:
                    set_is_error(True)
                    set_error_message(response.text)
                    return

                data = response.json()
                parsed = ClientResponse.model_validate(data)
                set_result(parsed)  # type: ignore
                set_scan_time(datetime.datetime.now(tz=datetime.timezone.utc).isoformat())
                json_str = json.dumps(data, indent=2)
                yaml_str = yaml.dump(data)
                json_b64 = base64.b64encode(json_str.encode("utf-8")).decode("utf-8")
                yaml_b64 = base64.b64encode(yaml_str.encode("utf-8")).decode("utf-8")
                json_href = f"data:application/json;base64,{json_b64}"
                yaml_href = f"data:text/yaml;base64,{yaml_b64}"
                set_json_link(json_href)
                set_yaml_link(yaml_href)
                set_is_error(False)
                set_error_message("")
            except httpx.ConnectError:
                set_is_error(True)
                set_error_message("server refused connection, try again in a few minutes")
            except httpx.ConnectTimeout:
                set_is_error(True)
                set_error_message("timed out trying to connect, try again in a few minutes")
            except Exception as e:
                set_is_error(True)
                set_error_message(str(e))

        # schedule async work without blocking the event loop
        asyncio.create_task(do_request())

            

    return html.div(
        {"class": "flex items-center justify-center min-h-screen transition-colors duration-500 ease-in-out bg-zinc-900"},
        html.div(
            {"class": "w-[40%] text-left overflow-auto no-scrollbar transition-colors duration-500 ease-in-out text-zinc-100"},
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
                {"class": "placeholder-zinc-400 text-zinc-100 shadow appearance-none border border-gray-500 rounded w-[70%] py-2 px-3 text-gray-700 mb-3 leading-tight focus:outline-none focus:shadow-outline h-8",
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
            yaml_link and html.button(
                {"class": "bg-gray-500 hover:bg-gray-400 text-white font-bold py-2 px-4 border-gray-700 hover:border-gray-500 rounded",
                },
                html.a(
                    {"href": yaml_link,
                     "download": f"gwop{datetime.date.today().isoformat()}.yaml"},
                    "Download YAML"
                )
            ),
            json_link and html.button(
                {"class": "bg-gray-500 hover:bg-gray-400 text-white font-bold py-2 px-4 border-gray-700 hover:border-gray-500 rounded",
                },
                html.a(
                    {"href": json_link,
                     "download": f"gwop{datetime.date.today().isoformat()}.json"},
                    "Download JSON"
                )
            ),
            result and html.div(
                {"class": "grid grid-cols-1 gap-6 mt-6"},
                create_result_overview(result, scan_time),
                html.div(
                    {"class": "grid grid-cols-1 md:grid-cols-2 gap-4"},
                    *create_evidence_list(result) 
                ),
            ),


            html.p(
                {"class": "font['Inter', font-sans] text-[clamp(1rem,1.3vw,1.6rem)] text-1xl"},
                "note that not all providers will flag a malicious link. only one needs to flag to be potentially malicious."
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
        {"class": "flex items-center justify-center min-h-screen transition-colors duration-500 ease-in-out bg-zinc-900"},
        html.div(
            {"class": "w-[40%] text-left overflow-auto no-scrollbar transition-colors duration-500 ease-in-out text-zinc-100"},
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
def App():
    return browser_router(
        route("/", main()),
        route("/about", about()),
        route("/scan", scan_link()),
        route("{404:any}", page_not_found()),
    )


app = FastAPI()
app.mount("/resources", StaticFiles(directory="resources"), name="resources")
configure(app, App, Options(head=head_content))

