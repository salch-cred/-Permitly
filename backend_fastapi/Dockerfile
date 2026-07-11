FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend_fastapi/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire repo (needed for apps/web static files)
COPY . .

ENV PYTHONPATH=/app/backend_fastapi:$PYTHONPATH
ENV HOST=0.0.0.0 PORT=7860

CMD ["sh","-c","cd backend_fastapi && uvicorn app.main:app --host ${HOST:-0.0.0.0} --port ${PORT:-7860}"]
