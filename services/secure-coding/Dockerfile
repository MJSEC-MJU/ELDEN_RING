FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git nodejs npm \
    && npm install -g @openai/codex@0.125.0 @anthropic-ai/claude-code@2.1.121 \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY src /app/src

ENV PYTHONUNBUFFERED=1
EXPOSE 8080

CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
