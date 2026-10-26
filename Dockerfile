# syntax=docker/dockerfile:1.7
# aegisx9 gateway image: LiteLLM proxy + the aegisx9 guard package.

# Node.js runs the Prisma CLI that LiteLLM uses to migrate its database. Taken from the
# official image pinned by digest (no unverified download); only the node binary reaches
# the runtime image, npm stays in the build stage.
FROM node:24.22.1-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea AS node

FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY requirements/runtime.txt requirements/runtime.txt
RUN pip install -r requirements/runtime.txt
COPY pyproject.toml README.md LICENSE VERSION ./
COPY src ./src
RUN pip install --no-deps .

# Prisma (database client + CLI) baked at build time, so the gateway never downloads
# anything at runtime: it has no internet egress and a read-only root filesystem.
# Everything lives under /opt/prisma (root-owned, world-readable); the same variables are
# set in the runtime stage, so the generated client points at these exact paths.
#   PRISMA_BINARY_CACHE_DIR  Prisma CLI (npm package) and its engines
#   PRISMA_NODEENV_CACHE_DIR never created: node is on PATH, and if prisma-client-py ever
#                            fell back to installing a private Node it would fail on the
#                            read-only /opt instead of downloading one
#   PRISMA_QUERY_ENGINE_BINARY the query engine for this platform, chosen once here
ENV PRISMA_BINARY_CACHE_DIR=/opt/prisma/binaries \
    PRISMA_NODEENV_CACHE_DIR=/opt/prisma/nodeenv \
    PRISMA_CLI_QUERY_ENGINE_TYPE=binary \
    PRISMA_HIDE_UPDATE_MESSAGE=1 \
    PRISMA_USE_NODEJS_BIN=false \
    CHECKPOINT_DISABLE=1 \
    PATH=/opt/prisma/node/bin:/opt/venv/bin:$PATH
COPY scripts/image/bake_prisma.py /src/scripts/image/bake_prisma.py
COPY --from=node /usr/local/bin/node /opt/prisma/node/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && SCHEMA="$(python -c 'import litellm.proxy, pathlib; print(pathlib.Path(litellm.proxy.__file__).parent / "schema.prisma")')" \
 && prisma generate --schema "${SCHEMA}" \
 && python scripts/image/bake_prisma.py
RUN chmod -R a+rX /opt/prisma

FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
ARG VERSION=0.0.0
LABEL org.opencontainers.image.title="aegisx9" \
      org.opencontainers.image.description="Secure AI gateway with governance" \
      org.opencontainers.image.source="https://github.com/mchasse73/aegisx9" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
RUN groupadd --system --gid 10001 aegisx9 \
 && useradd --system --uid 10001 --gid aegisx9 --no-create-home --shell /usr/sbin/nologin aegisx9
COPY --from=build /opt/venv /opt/venv
COPY --from=build /opt/prisma /opt/prisma
# Prisma: same paths as the build stage, CLI run directly (LiteLLM's offline mode), no
# download of any kind. LITELLM_MIGRATION_DIR copies LiteLLM's migrations to a writable
# directory before `prisma migrate deploy`, as LiteLLM documents for read-only roots.
ENV PATH=/opt/venv/bin:/opt/prisma/node/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PRISMA_BINARY_CACHE_DIR=/opt/prisma/binaries \
    PRISMA_NODEENV_CACHE_DIR=/opt/prisma/nodeenv \
    PRISMA_QUERY_ENGINE_BINARY=/opt/prisma/query-engine \
    PRISMA_CLI_PATH=/opt/prisma/binaries/node_modules/.bin/prisma \
    PRISMA_OFFLINE_MODE=true \
    PRISMA_CLI_QUERY_ENGINE_TYPE=binary \
    PRISMA_HIDE_UPDATE_MESSAGE=1 \
    PRISMA_SKIP_POSTINSTALL_GENERATE=1 \
    PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING=1 \
    PRISMA_USE_NODEJS_BIN=false \
    CHECKPOINT_DISABLE=1 \
    LITELLM_MIGRATION_DIR=/tmp/litellm-migrations
# Fail the build if the runtime image cannot run the baked toolchain (openssl is what
# Prisma uses to pick its engine build).
RUN command -v openssl >/dev/null \
 && node --version >/dev/null \
 && test -x "${PRISMA_CLI_PATH}" \
 && /opt/prisma/query-engine --version >/dev/null \
 && python -c "import prisma; from prisma import Prisma"
USER 10001:10001
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:4000/health/liveliness', timeout=4).status == 200 else 1)"]
ENTRYPOINT ["litellm"]
CMD ["--config", "/etc/aegisx9/config.yaml", "--port", "4000"]
