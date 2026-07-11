FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend_fastapi/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY backend_fastapi /app

ENV HOST=0.0.0.0
# Hugging Face sets PORT; default for local runs
ENV PORT=7860

CMD ["sh","-lc","uvicorn app.main:app --host ${HOST:-0.0.0.0} --port ${PORT:-7860}"]
