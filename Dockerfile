# syntax=docker/dockerfile:1.7
# aegisx9 gateway image: LiteLLM proxy + the aegisx9 guard package.
FROM python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2 AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY requirements/runtime.txt requirements/runtime.txt
RUN pip install -r requirements/runtime.txt
COPY pyproject.toml README.md LICENSE VERSION ./
COPY src ./src
RUN pip install --no-deps .

FROM python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2
ARG VERSION=0.0.0
LABEL org.opencontainers.image.title="aegisx9" \
      org.opencontainers.image.description="Secure AI gateway with governance" \
      org.opencontainers.image.source="https://github.com/mchasse73/aegisx9" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
RUN groupadd --system --gid 10001 aegisx9 \
 && useradd --system --uid 10001 --gid aegisx9 --no-create-home --shell /usr/sbin/nologin aegisx9
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:4000/health/liveliness', timeout=4).status == 200 else 1)"]
ENTRYPOINT ["litellm"]
CMD ["--config", "/etc/aegisx9/config.yaml", "--port", "4000"]
