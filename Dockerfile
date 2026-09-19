# One container = frontend + backend on ONE public URL (Render).
# ---- Stage 1: build the React frontend ----
FROM node:20-alpine AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
ENV VITE_API_BASE_URL=/api/v1
RUN npm run build

# ---- Stage 2: FastAPI backend that also serves the built frontend ----
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONUTF8=1 PIP_NO_CACHE_DIR=1
WORKDIR /app/backend
COPY backend/requirements-prod.txt ./
RUN pip install -r requirements-prod.txt
COPY backend/ ./
COPY --from=frontend /frontend/dist /app/frontend/dist
RUN mkdir -p /tmp/evidence
EXPOSE 8000
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
