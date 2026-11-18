FROM public.ecr.aws/docker/library/ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Образ для Molecule. Собирается локально: Docker Hub на macOS часто
# отвечает 401, а этот базовый слой доступен через public.ecr.aws.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 0755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       systemd \
       systemd-sysv \
       python3 \
       sudo \
       ca-certificates \
       iproute2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /lib/systemd/system/systemd*udev* \
    && rm -f /lib/systemd/system/getty.target

RUN ln -sf python3 /usr/bin/python

VOLUME ["/sys/fs/cgroup", "/tmp", "/run"]
CMD ["/lib/systemd/systemd"]
