FROM python:3.11-alpine as builder
RUN apk add curl

WORKDIR /sztafeta

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt && rm -rf /root/.cache

COPY . .

# CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]
# CMD ["python", "app.py"]
HEALTHCHECK --interval=1m CMD curl --fail http://localhost:8888/ping || exit 1
CMD gunicorn --bind 0.0.0.0:8888 app:app  
