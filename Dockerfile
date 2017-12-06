FROM python:2.7-slim

RUN apt-get update -y
RUN apt-get install --upgrade -y python-pip python-dev build-essential

COPY ./app/ /app
WORKDIR /app

RUN pip install -r requirements.txt

ENTRYPOINT ["python"]
CMD ["main.py"]
