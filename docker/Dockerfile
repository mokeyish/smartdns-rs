FROM debian:stable AS downloader


RUN apt-get update && apt-get install -y curl
RUN mkdir -p /app/x86 /app/arm64 /app/armv7 /app/extracted/x86 /app/extracted/arm64 /app/extracted/armv7


COPY ./smartdns-x86_64-unknown-linux-musl.tar.gz /app/x86/smartdns.tar.gz
COPY ./smartdns-aarch64-unknown-linux-musl.tar.gz /app/arm64/smartdns.tar.gz
COPY ./smartdns-aarch64-unknown-linux-musl.tar.gz /app/armv7/smartdns.tar.gz

RUN tar -xvf /app/x86/smartdns.tar.gz -C /app/extracted/x86
RUN tar -xvf /app/arm64/smartdns.tar.gz -C /app/extracted/arm64
RUN tar -xvf /app/armv7/smartdns.tar.gz -C /app/extracted/armv7


FROM alpine AS base

WORKDIR /app
RUN apk add bash
COPY ./contrib/docker/docker-entrypoint.sh /app/entrypoint.sh
FROM base AS amd64

COPY --from=downloader /app/extracted/x86/* /app/

FROM base AS armv7

COPY --from=downloader /app/extracted/armv7/* /app/

FROM base AS arm64

COPY --from=downloader /app/extracted/arm64/* /app/


FROM ${TARGETARCH}${TARGETVARIANT} AS final


EXPOSE 8000
CMD ["bash", "/app/entrypoint.sh"]
