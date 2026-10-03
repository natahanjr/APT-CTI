FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY deploy/requirements.txt /app/deploy/requirements.txt
RUN pip install -r deploy/requirements.txt

COPY src/ /app/src/
COPY deploy/ /app/deploy/
COPY model/ /app/model/
COPY config/default.yaml /app/config/default.yaml
COPY data/feed_snapshots/ /app/data/feed_snapshots/
COPY data/threat_actors.json /app/data/threat_actors.json

RUN mkdir -p /app/data/inbox /app/deploy/alerts \
    && useradd -m scorer \
    && chown -R scorer /app/data /app/deploy/alerts
USER scorer

EXPOSE 8099

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import os,sys,urllib.request as u; t=os.environ.get('APT_CTI_TOKEN',''); r=u.Request('http://127.0.0.1:8099/__status', headers={'X-Auth-Token':t} if t else {}); sys.exit(0 if u.urlopen(r, timeout=4).status==200 else 1)"

# Mount a sensor-forwarded file at /app/data/inbox/flows.jsonl, e.g.
#   docker run -d --restart unless-stopped -p 8099:8099 \
#     -v "$PWD/inbox:/app/data/inbox" \
#     -e APT_CTI_TOKEN='<strong-token>' \
#     -e NVIDIA_API_KEY="$NVIDIA_API_KEY" \
#     apt-cti-scorer --config deploy/config.yaml --health-host 0.0.0.0
# Binding to 0.0.0.0 REQUIRES APT_CTI_TOKEN (or auth.token) — the service
# refuses to start otherwise (fail closed).
ENTRYPOINT ["python", "deploy/service.py"]
CMD ["--config", "deploy/config.yaml"]
