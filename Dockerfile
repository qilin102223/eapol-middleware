FROM debian:trixie-slim

ARG DEBIAN_MIRROR=http://mirror.twds.com.tw/debian

RUN sed -i -E "s|^URIs: https?://deb\.debian\.org/debian$|URIs: ${DEBIAN_MIRROR}|g" /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-flask \
        python3-gunicorn \
        python3-cryptography \
        gunicorn \
        eapoltest \
        freeradius-utils \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app.py ./
COPY templates/ templates/
COPY static/ static/

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", \
     "-k", "gthread", \
     "-w", "4", "--threads", "25", \
     "--timeout", "600", \
     "--backlog", "2048", \
     "app:app"]
