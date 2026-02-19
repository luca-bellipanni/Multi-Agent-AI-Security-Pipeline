FROM python:3.12

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
# opentelemetry-instrumentation 0.46b0 (semgrep dep) uses pkg_resources,
# which was removed in setuptools>=78. Force-install a compatible version
# AFTER requirements (pip resolves to 82.x which lacks pkg_resources).
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && pip install --no-cache-dir "setuptools>=70.0,<78" \
    && semgrep --version

COPY entrypoint.sh /app/entrypoint.sh
COPY src/ /app/src/

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
