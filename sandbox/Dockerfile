# MailShield isolated sandbox — static/controlled analysis of quarantined artefacts.
# Hardened: non-root, no secrets baked in, no volumes, read-only friendly, no shell tools needed at runtime.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install -r requirements.txt \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin sandbox \
 && rm -rf /root/.cache
COPY sandbox_app ./sandbox_app
USER 10001:10001
EXPOSE 8080
# One worker: jobs are isolated in forked children with rlimits (see sandbox_app/isolation.py).
CMD ["sh", "-c", "exec uvicorn sandbox_app.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1 --no-server-header"]
