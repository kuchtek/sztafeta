# FROM python:3.11-alpine as builder

# # This hack is widely applied to avoid python printing issues in docker containers.
# # See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13

# WORKDIR /sztafeta
# RUN python3 -m venv venv
# ENV PATH=/sztafeta/venv/bin/:$PATH
# # RUN echo "**** install Python ****" && \
# #     apk add --no-cache python3 && \
# #     if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi && \
# #     \
# #     echo "**** install pip ****" && \
# #     python -m ensurepip && \
# #     rm -r /usr/lib/python*/ensurepip && \
# #     if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi && \
# #     rm -rf /var/lib/apt/lists/* && \
# #     pip install --no-cache-dir --no-compile --upgrade pip setuptools wheel
# COPY . ./
# RUN pip install --no-cache-dir -r requirements.txt

# FROM gcr.io/distroless/python3
# COPY --from=builder /sztafeta /sztafeta
# WORKDIR /sztafeta
# ENV PYTHONUNBUFFERED=1
# ENV PYTHONDONTWRITEBYTECODE=1
# # ENV PYTHONPATH=/app/venv/lib/python3.11/site-packages
# # ENV PATH=/app/venv/bin/:$PATH
# EXPOSE 5000
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
