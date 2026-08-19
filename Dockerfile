FROM python:3.12-slim

WORKDIR /app

# Copy application files
COPY server.py ./
COPY public/ ./public/
COPY data/ ./data/

# SQLite database persistence directory
VOLUME ["/app/data"]

EXPOSE 5001

CMD ["python3", "server.py", "5001"]
