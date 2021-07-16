FROM python:3.8-slim-buster

# LABEL maintainer="jesus.ramos.atos@gmail.com"

RUN apt-get update -y && \
    apt-get install -y netcat-openbsd

EXPOSE ${VAULT_SECRET_UPLOADER_PORT}

COPY ./requirements.txt /app/requirements.txt

WORKDIR /app

RUN pip3 install -r requirements.txt

COPY ./app.py /app

CMD [ "sh", "-c", "gunicorn -w 2 -b :${VAULT_SECRET_UPLOADER_PORT} app:app" ]