FROM docker:29-cli

RUN apk add --no-cache python3 py3-redis

WORKDIR /repo
COPY deploy_agent.py /agent/deploy_agent.py

CMD ["python3", "/agent/deploy_agent.py"]
