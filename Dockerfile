FROM python:3.11-slim
ENV PYTHONUNBUFFERED=True
WORKDIR /app

COPY src/security_shield/backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

ENV PYTHONPATH=/app/src
ENV PORT=8080
EXPOSE 8080

CMD exec gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 0 security_shield.backend.main:app
