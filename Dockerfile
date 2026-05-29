# ============================================================
# Stage 1: Build React Frontend
# ============================================================
FROM node:20-alpine AS frontend-build

WORKDIR /app/frontend

# Copy only package.json first for Docker layer caching
COPY frontend/package.json ./
RUN npm install

# Copy the rest of the source and build
COPY frontend/ ./
RUN npm run build

# ============================================================
# Stage 2: Python Backend with Static Frontend
# ============================================================
FROM python:3.11-slim

WORKDIR /app

# Copy backend code
COPY backend/ ./backend/

# Copy built frontend from Stage 1
COPY --from=frontend-build /app/frontend/dist/ ./frontend/dist/

# Install Python dependencies
RUN pip install --no-cache-dir -r backend/requirements.txt

# Expose the application port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

# Run the FastAPI server with uvicorn
# Note: The main.py references frontend/dist relative to backend/../frontend/dist,
# which translates to /app/frontend/dist in this container layout
# Use shell form so env vars are expanded
# HOST and PORT can be overridden at runtime
CMD uvicorn backend.main:app --host ${HOST:-0.0.0.0} --port ${PORT:-8000}
