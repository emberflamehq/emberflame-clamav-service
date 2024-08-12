
FROM python:3.12.4-alpine3.20

RUN apk add --no-cache tini su-exec

RUN apk --update add --no-cache clamav ca-certificates
RUN apk --update add --no-cache -t .build-deps \
  build-base \
  mercurial \
  musl-dev \
  openssl \
  bash \
  curl \
  curl-dev \
  libffi-dev \
  python3-dev \
  wget \
  git \
  gcc \
  openssl-dev \
  ca-certificates \
  libpq-dev \
  libcurl

#we need the go version installed from apk to bootstrap the custom version built from source
RUN update-ca-certificates 
# Update ClamAV Definitions
RUN mkdir -p /opt/malice \
  && freshclam
RUN touch /opt/malice/UPDATED

RUN mkdir -p /run/clamav \
&& chown clamav:clamav /run/clamav

RUN clamd &

# Add EICAR Test Virus File to malware folder
# ADD https://raw.githubusercontent.com/fire1ce/eicar-standard-antivirus-test-files/master/eicar-test.txt /malware/EICAR

# COPY --from=go_builder /bin/avscan /bin/avscan
RUN mkdir -p /code \
&& mkdir /malware

COPY . /code
WORKDIR /code

RUN pip install -r requirements.txt
# ENTRYPOINT [ "./entrypoint.sh" ]

COPY entrypoint.sh ./entrypoint.sh
CMD ["bash", "entrypoint.sh"]