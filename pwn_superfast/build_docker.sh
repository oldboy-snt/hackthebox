#!/bin/sh
docker build . -t pwn_superfast && \
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -p1337:1337 -it pwn_superfast
