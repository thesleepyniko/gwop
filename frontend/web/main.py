from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from reactpy import component, html, run

from reactpy.backend.fastapi import configure, Options
from reactpy.html import head, link, script, title, span, meta
from reactpy_router import browser_router, route

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
def main():
    return html.div(
        {"class": "flex items-center justify-center h-screen"},
        html.div(
            {"class": "w-[40%] text-left overflow-auto no-scrollbar"},
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
                    {"href": "#"},
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
                {"class": "my-8 border-t border-gray-300", "aria_hidden": "true"}
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
def scan_link():
    

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
                {"class": "my-8 border-t border-gray-300", "aria_hidden": "true"}
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
    return browser_router(
        route("/", main()),
        route("/about", about()),
        route("{404:any}", page_not_found()),
    )

app = FastAPI()
app.mount("/resources", StaticFiles(directory="resources"), name="resources")
configure(app, app_router, Options(head=head_content))

