FROM python:3.13-slim
ARG TOOL
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app \
    LOCAL_TARGET_MODE=protected OLLAMA_BASE_URL=http://ollama:11434
WORKDIR /app
COPY attack_engine/requirements*.txt ./attack_engine/
RUN test "$TOOL" = garak -o "$TOOL" = pyrit \
    && pip install --no-cache-dir -r attack_engine/requirements-${TOOL}.txt fastapi uvicorn
COPY backend/app ./app
COPY attack_engine ./attack_engine
ENV SENTINEL_TOOL=${TOOL}
RUN useradd --create-home --uid 10001 sentinel
USER sentinel
CMD ["uvicorn", "app.tool_service:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
