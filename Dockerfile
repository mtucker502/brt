FROM python:3.7-alpine as base

# Builder Image

FROM base as builder

WORKDIR /home/brt

RUN apk add --no-cache \
        libressl-dev \
        musl-dev \
        libffi-dev \
        build-base \
        git \
        libxml2-dev \
        libxslt-dev \
        python-dev

COPY requirements.txt requirements.txt

RUN python -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

RUN pip install -r requirements.txt

# Runtime Image

FROM base as runtime

WORKDIR /home/brt

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

COPY worker.py .

RUN chmod +x worker.py

ENTRYPOINT [ "python", "worker.py" ]