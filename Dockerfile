FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install flask mitmproxy requests gunicorn

WORKDIR /app

COPY . .

# Expõe as portas necessárias
EXPOSE 5000
EXPOSE 8080

# Comando para rodar o sistema Tudo-em-Um
CMD ["python", "main.py"]
