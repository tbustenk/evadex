"""evadex bridge — start the HTTP bridge server for siphon-c2 and friends.

Installed as an optional extra: ``pip install evadex[bridge]``.
"""
from __future__ import annotations

import os
import sys

import click


@click.command("bridge")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Interface to bind. Use 0.0.0.0 for LAN access.")
@click.option("--port", default=8081, show_default=True, type=int,
              help="TCP port.")
@click.option("--api-key", default=None, metavar="KEY",
              help=("Require this key in the x-api-key header on every "
                    "request. Can also be set via EVADEX_BRIDGE_KEY."))
@click.option("--cors", default=None, metavar="ORIGINS",
              help=("Comma-separated CORS allow-list. Default '*' allows "
                    "any origin. Can also be set via "
                    "EVADEX_BRIDGE_CORS_ORIGINS."))
@click.option("--reload", is_flag=True, default=False,
              help="Auto-reload on code changes (development only).")
@click.option("--root", default=None, type=click.Path(),
              help=("Directory evadex scans against (defaults to the "
                    "current working directory). Mirrors "
                    "EVADEX_BRIDGE_ROOT."))
def bridge(host: str, port: int, api_key: str | None, cors: str | None,
           reload: bool, root: str | None) -> None:
    """Start the evadex HTTP bridge.

    Exposes three endpoints the siphon-c2 dashboard calls:

    \b
      POST /v1/evadex/run       trigger a scan (background, returns run_id)
      GET  /v1/evadex/metrics   detection / FP / coverage from audit log
      POST /v1/evadex/generate  emit a synthetic test file and stream it back

    Install the extra first: ``pip install evadex[bridge]``.
    """
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        click.echo(
            "evadex bridge requires the [bridge] extra.\n"
            "Install with:  pip install evadex[bridge]",
            err=True,
        )
        sys.exit(2)

    # Surface the flags via env so the FastAPI factory picks them up —
    # uvicorn with reload=True re-imports the app, so command-line state
    # must travel through the environment.
    if api_key:
        os.environ["EVADEX_BRIDGE_KEY"] = api_key
    if cors:
        os.environ["EVADEX_BRIDGE_CORS_ORIGINS"] = cors
    if root:
        os.environ["EVADEX_BRIDGE_ROOT"] = str(root)

    click.echo(f"evadex bridge listening on http://{host}:{port}")
    click.echo(
        "auth: " + ("x-api-key required" if os.environ.get("EVADEX_BRIDGE_KEY")
                    else "open (no API key set)")
    )

    import uvicorn
    uvicorn.run(
        "evadex.bridge.server:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )
