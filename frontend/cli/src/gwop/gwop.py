import click
import httpx
import asyncio
import datetime
from .definitions import ThreatType, Verdict, ClientResponse
import yaml

SERVER_LINK = "https://api.gwop.nikoo.dev"

@click.command()
@click.option('--url', help='The url to scan.', nargs=1)
@click.option('--format', 'fmt', type=click.Choice(['text', 'json', 'yaml']), default='text')
@click.option('--output', "-o", type=click.File('w'), default='-',
              help="File to write results to (default is stdout)")

def gwop(url: str, fmt: str, output):
    """CLI frontend application for great wall of phish."""
    asyncio.run(run_gwop(url, fmt, output))

async def run_gwop(url: str, fmt: str, output):
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

    if not url:
        exit_and_help()
    elif not (url.startswith("http://") or url.startswith("https://")):
        exit_and_help("Invalid URL. If you are passing in an IP, try 'http://'.")
    elif not url.strip():
        exit_and_help("Link cannot be empty.")
    else:
        try:
            scan_time = datetime.datetime.isoformat(datetime.datetime.now())
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{SERVER_LINK}/check-url",
                    json={"link": url.strip()},
                    timeout=20.0
                )
            if response.status_code != 200:
                exit_and_help("Non 200 response code, try again later.")
            data = response.json()
            result = ClientResponse.model_validate(data)
            if fmt == "text":
                if result.threat_type:
                    label = threat_type_labels.get(result.threat_type, ThreatType.unknown)
                else:
                    if result.is_threat:
                        label = "unclassified"
                    else:
                        label = None
                
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

                click.echo(f"Verdict: {verdict}", file=output)
                if label:
                    click.echo(f"threat type: {label}", file=output)
                click.echo(f"Scanned at: {scan_time}", file=output)
                click.echo(f"{len(result.flagged_by)} out of {len(result.cleared_by) + len(result.errored_by)} services flagged", file=output)
                click.echo(f"Our heuristics scored this a {result.heuristics.get("score", 0)}/{"6" if not result.heuristics.get("cidr", None) else "4"}", file=output)
                click.echo(f"{len(result.errored_by)} errors while scanning", file=output)
                click.echo(file=output)
                click.echo("details:", file=output)

                for ev in result.evidence:
                    click.echo(f"service: {ev.source}", file=output)
                    click.echo(f"flagged: {"yes" if ev.is_threat else "no"}", file=output)
                    click.echo(file=output)

                click.echo(f"heuristics", file=output)
                click.echo(f"recieved score of {result.heuristics.get("score", 0)}", file=output)
                click.echo(f"flagged: {"yes" if int(result.heuristics.get("score", 0)) > 3 else "no"}", file=output) # type: ignore
                click.echo()

                click.echo("finished writing output, goodbye")
            elif fmt == "json":
                click.echo(result.model_dump_json(indent=2), file=output)
                click.echo("finished writing output, goodbye")
            elif fmt == "yaml":
                click.echo(yaml.dump(result.model_dump(), sort_keys=False), file=output)
                click.echo("finished writing output, goodbye")
            else:
                exit_and_help("invalid option recieved for format")
        except click.exceptions.Exit:
            raise
        except Exception as e:
            exit_and_help(f"Unhandled exception: {e}")


def exit_and_help(msg=None):
    ctx = click.get_current_context()
    if msg:
        click.echo(msg)
    click.echo(ctx.get_help())
    ctx.exit()

if __name__ == "__main__":
    gwop()
