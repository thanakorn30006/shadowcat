# ==============================================================================
#  SHADOW CAT — Production Docker Container (Single-Port Architecture)
# ==============================================================================
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system utilities needed for CTF analysis (binutils, file, tshark/tcpdump optional)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    file \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend code & pre-compiled frontend distribution
COPY backend/ /app/backend/
COPY frontend/dist/ /app/frontend/dist/

WORKDIR /app/backend

# Inside the container the server must listen on 0.0.0.0; host exposure is
# controlled by the port mapping in docker-compose.yml (loopback by default).
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
