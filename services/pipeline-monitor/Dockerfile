FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git nodejs npm \
    && npm install -g @openai/codex@0.125.0 @anthropic-ai/claude-code@2.1.121 \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY src/ ./src/

RUN useradd -u 1001 -m mon && chown -R mon:mon /app
USER 1001

ENV MONITOR_CODEX_COMMAND=codex
ENV MONITOR_CLAUDE_COMMAND=claude

EXPOSE 8080

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
