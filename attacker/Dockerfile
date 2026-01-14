FROM python:3.11-slim

WORKDIR /app

COPY attacker.html .
COPY server.py .
COPY static/ ./static/

EXPOSE 8080

CMD ["python", "server.py"]
