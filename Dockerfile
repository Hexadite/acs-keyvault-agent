FROM python:2.7-slim

RUN useradd -m -u 999 appuser

WORKDIR /app

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY ./app/ ./

USER 999

CMD ["python", "./main.py"]
