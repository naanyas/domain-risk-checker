# v8.5: headless-render-capable image.
# Playwright's official Python image ships Chromium + all system libraries
# preinstalled, which is far more reliable on Railway than installing a browser
# under Nixpacks.  Pinned to v1.60.0 — do NOT reinstall playwright via pip, or
# the pinned browser binaries in /ms-playwright would no longer match.
FROM mcr.microsoft.com/playwright/python:v1.60.0-noble

WORKDIR /app

# App Python deps only (playwright is already in the base image at 1.60.0).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Railway injects $PORT at runtime; default for local `docker run`.
ENV PORT=8080
EXPOSE 8080

# Shell form so ${PORT} expands at runtime.
CMD streamlit run app.py \
    --server.port ${PORT} \
    --server.address 0.0.0.0 \
    --server.headless true \
    --browser.gatherUsageStats false
