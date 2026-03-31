FROM python:3.12-alpine
WORKDIR /app

RUN apk add --no-cache conntrack-tools docker-cli docker-cli-compose
RUN pip install --no-cache-dir aiohttp

COPY app.py .
COPY templates/ ./templates/

EXPOSE 9090
CMD ["python", "app.py"]
