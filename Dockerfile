FROM python:3.9-slim

RUN useradd -m -u 999 appuser

WORKDIR /app

COPY requirements.txt ./

RUN python3 -m pip install --no-cache-dir -r requirements.txt

COPY ./app/ ./

USER 999

CMD ["python3", "./main.py"]
