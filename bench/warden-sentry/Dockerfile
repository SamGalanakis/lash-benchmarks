FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        curl \
        findutils \
        gawk \
        git \
        grep \
        jq \
        python3 \
        ripgrep \
        sed \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /work/repo /work/run/tasks /work/secrets
WORKDIR /work/repo
