# checktls — Docker image for hosting the MX / Mimecast root-CA checker.
#
# Build:   docker build -t checktls .
# Run:     docker run --rm -p 5000:5000 checktls
# Then open http://localhost:5000

FROM python:3.11-slim

# Keep the image small and non-interactive; install to a dedicated venv path.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CHECKTLS_HOST=0.0.0.0 \
    CHECKTLS_PORT=5000

WORKDIR /app

# Install dependencies first so the layer is cached unless requirements change.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application and its templates.
COPY app.py .
COPY templates/ ./templates/

# Run as an unprivileged user (created by python:slim).
USER 1000

EXPOSE 5000

# gunicorn serves the app. NOTE: keep --workers 1 — batch-check run state is
# kept in process memory, so every request (upload + status polling) must hit
# the same worker. Checks are I/O-bound and already parallelized internally
# via threads (CHECKTLS_BATCH_WORKERS), so one worker is plenty for this app.
CMD ["gunicorn", "--workers", "1", "--bind", "0.0.0.0:5000", "app:app"]
