# ── Stage 1: Build ──────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# gcc is needed for the few wheels that still build from source on
# python:3.11-slim (e.g. py7zr's cffi extension). rm'ing the apt
# lists keeps the builder layer slim even though we throw it away.
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

# pyproject first so dep-install caches when only source changes.
# README is referenced by [project].readme so it has to be present at
# install time or pip fails the PEP 517 metadata step.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Install with extras used by the bridge + realistic file generation.
# --prefix=/install stages everything under a copyable root so the
# runtime layer can grab site-packages + scripts in one COPY.
RUN pip install --no-cache-dir --prefix=/install ".[bridge,barcodes,data-formats,archives]"

# ── Stage 2: Runtime ───────────────────────────────────────────
FROM python:3.11-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Non-root user + stable uid 1000 so the k8s manifest's
# securityContext.runAsUser matches without extra ID remapping.
RUN groupadd -r evadex --gid 1000 && \
    useradd -r -g evadex -u 1000 -s /bin/false evadex

COPY --from=builder /install /usr/local
COPY src/ /app/src/

WORKDIR /app

USER evadex

ENTRYPOINT ["python", "-m", "evadex"]
CMD ["--help"]

# Bridge server listens on 8081. Non-bridge runs (one-shot `scan`,
# `generate`, etc) will fail this probe fast and exit — that's fine
# for k8s Jobs/CronJobs, which don't pay attention to HEALTHCHECK.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8081/healthz || exit 1

LABEL org.opencontainers.image.title="evadex" \
      org.opencontainers.image.description="DLP evasion test suite — adversarial testing for Siphon" \
      org.opencontainers.image.version="3.17.1"
