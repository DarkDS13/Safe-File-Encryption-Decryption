# Secure File Encryption and Decryption System
#
# One image serves both the JSON API and the browser client, so a deployment is
# a single container with a single port.
FROM python:3.12-slim AS base

# Never write .pyc files, never buffer stdout (so logs appear immediately in
# the platform's log viewer).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first: this layer is cached and only rebuilds when the
# requirements file changes, not on every source edit.
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Containers are written here.  Declaring it a volume means a platform can
# mount persistent storage over it; without one, uploads live only as long as
# the container does.
ENV SFE_DATA_DIR=/data
RUN mkdir -p /data

# Run as an unprivileged user.  A process that does not need root should not
# have it, and this one only ever writes to /data.
RUN useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /data /app
USER appuser

EXPOSE 8000

# The platform overrides PORT; 8000 is the fallback for a plain `docker run`.
ENV PORT=8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,os,sys; \
        url=f\"http://127.0.0.1:{os.environ.get('PORT','8000')}/api/health\"; \
        sys.exit(0 if urllib.request.urlopen(url, timeout=4).status == 200 else 1)"

CMD ["python", "backend/run.py"]
