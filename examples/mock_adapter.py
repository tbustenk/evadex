"""
Minimal example adapter — shows how to integrate any DLP scanner into Evadex.

To use a real scanner:
  1. Replace the submit() body with your scanner's API/CLI call.
  2. Set detected = True if the scanner flagged the variant, False otherwise.
  3. Register the adapter with a unique name via @register_adapter("your-name").
  4. Run: evadex scan --tool your-name

This file is intentionally simple. See src/evadex/adapters/dlpscan_cli/adapter.py
for a full subprocess-based example, or src/evadex/adapters/dlpscan/adapter.py
for an HTTP-based example.
"""
from evadex.adapters.base import BaseAdapter
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, Variant, ScanResult


@register_adapter("mock")
class MockAdapter(BaseAdapter):
    """Always-detected mock adapter — useful for verifying Evadex itself works."""

    name = "mock"

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        # ── Replace this block with your scanner call ──────────────────────────
        #
        # HTTP example:
        #   import httpx
        #   async with httpx.AsyncClient() as client:
        #       resp = await client.post(
        #           f"{self.config.base_url}/scan",
        #           json={"text": variant.value},
        #           timeout=self.config.timeout,
        #       )
        #       detected = resp.json().get("detected", False)
        #
        # CLI example:
        #   import subprocess
        #   result = subprocess.run(["my-scanner", variant.value], capture_output=True)
        #   detected = result.returncode == 0
        #
        # ──────────────────────────────────────────────────────────────────────
        detected = True  # mock: pretend the scanner always catches it

        return ScanResult(
            payload=payload,
            variant=variant,
            detected=detected,
            raw_response={"mock": True},
        )

    async def health_check(self) -> bool:
        return True  # mock: always healthy
