ARG VERSION=0.6.1

FROM debian:stable as downloader

ARG VERSION

RUN apt-get update && apt-get install -y curl
RUN mkdir -p /app/x86 /app/arm64 /app/armv7 /app/extracted/x86 /app/extracted/arm64 /app/extracted/armv7


RUN curl -L https://github.com/mokeyish/smartdns-rs/releases/download/$VERSION/smartdns-x86_64-unknown-linux-musl.tar.gz -o  /app/x86/smartdns.tar.gz
RUN ls -lisa /app/x86
RUN tar -xvf /app/x86/smartdns.tar.gz -C /app/extracted/x86

RUN curl -L https://github.com/mokeyish/smartdns-rs/releases/download/$VERSION/smartdns-aarch64-unknown-linux-musl.tar.gz -o /app/arm64/smartdns.tar.gz

RUN tar -xvf /app/arm64/smartdns.tar.gz -C /app/extracted/arm64
RUN curl -L https://github.com/mokeyish/smartdns-rs/releases/download/$VERSION/smartdns-arm-unknown-linux-musleabihf.tar.gz -o /app/armv7/smartdns.tar.gz

RUN tar -xvf /app/armv7/smartdns.tar.gz -C /app/extracted/armv7

FROM alpine as base

WORKDIR /app
RUN apk add bash
COPY docker-entrypoint.sh /app/entrypoint.sh
FROM base as amd64

COPY --from=downloader /app/extracted/x86/* /app/

FROM base as armv7

COPY --from=downloader /app/extracted/armv7/* /app/

FROM base as arm64

COPY --from=downloader /app/extracted/arm64/* /app/


FROM ${TARGETARCH}${TARGETVARIANT} as final


EXPOSE 8000
CMD ["bash", "/app/entrypoint.sh"]
