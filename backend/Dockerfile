FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# data/ is bind-mounted from the host so the registry survives image rebuilds.
ENV RANGE_DATA_DIR=/app/data \
    RANGE_DB_PATH=/app/data/range.db

EXPOSE 8780
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8780"]
