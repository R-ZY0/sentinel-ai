FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend/requirements.txt ./requirements.txt
COPY judge/requirements.txt ./judge-requirements.txt
COPY security_validation/requirements.txt ./security-requirements.txt
RUN pip install --no-cache-dir \
    -r requirements.txt \
    -r judge-requirements.txt \
    -r security-requirements.txt

RUN python -m spacy download en_core_web_lg

COPY backend/app ./app
COPY attack_engine ./attack_engine
COPY judge ./judge

COPY security_validation ./security_validation
COPY security ./security

RUN useradd --create-home --uid 10001 sentinel
USER sentinel

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
