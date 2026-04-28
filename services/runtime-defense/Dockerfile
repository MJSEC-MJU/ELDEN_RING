FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Non-root execution. UID/GID 1000 matches runAsUser in K8s SecurityContext.
# /home/app must exist so K8s can mount writable emptyDir at /home/app/.kube
# under readOnlyRootFilesystem (kubernetes client discovery cache).
RUN groupadd --system --gid 1000 app \
 && useradd --system --uid 1000 --gid 1000 --create-home --home-dir /home/app --shell /sbin/nologin app \
 && chown -R 1000:1000 /app /home/app
USER 1000

EXPOSE 8080

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
