FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
# The collector needs to read host-owned BunkerWeb logs. The mount stays read-only.
CMD ["python", "main.py"]
