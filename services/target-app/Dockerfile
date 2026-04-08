FROM python:3.11-slim

LABEL maintainer="ELDEN RING Team"
LABEL description="Intentionally vulnerable Flask app for security testing"

WORKDIR /app

RUN mkdir -p /app/data /app/uploads

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY init_db.py .
COPY app.py .
COPY templates/ ./templates/

# Create sample upload files for path traversal demo
RUN echo "This is a sample file." > /app/uploads/sample.txt

# Initialize the database at build time
RUN python init_db.py

EXPOSE 5000

ENV DB_PATH=/app/data/users.db
ENV FLASK_APP=app.py

CMD ["python", "app.py"]
