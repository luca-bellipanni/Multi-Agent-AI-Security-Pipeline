FROM python:3.12

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Python 3.12 no longer bundles setuptools; opentelemetry (semgrep dep)
# needs pkg_resources at import time — install BEFORE other packages.
RUN pip install --no-cache-dir "setuptools>=70.0"

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && python -c "import semgrep; print('semgrep OK')" \
    && semgrep --version

COPY entrypoint.sh /app/entrypoint.sh
COPY src/ /app/src/

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
