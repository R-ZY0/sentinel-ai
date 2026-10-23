FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY attack_engine ./attack_engine
COPY judge ./judge

RUN useradd --create-home --uid 10001 sentinel
USER sentinel

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
