FROM python:2.7-slim

WORKDIR /app

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY ./app/ ./

CMD ["python", "./main.py"]
