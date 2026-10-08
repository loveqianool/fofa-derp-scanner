# syntax=docker/dockerfile:1
#
# 构建：
#   gnu (Debian):  docker build --build-arg BASE_IMAGE=debian:bookworm-slim -t derp-scan .
#   musl (Alpine): docker build --build-arg BASE_IMAGE=alpine:3.21 -t derp-scan:musl .
#
# 二进制为纯静态编译（CGO_ENABLED=0），不依赖目标系统的 libc，
# gnu/musl 只是运行时的基础镜像区别。

ARG BASE_IMAGE=debian:bookworm-slim

FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS builder
ARG TARGETOS TARGETARCH
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# 纯静态编译：glibc / musl / scratch 通吃
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /derp-scan .

FROM ${BASE_IMAGE}
COPY --from=builder /derp-scan /usr/local/bin/derp-scan
ENTRYPOINT ["derp-scan"]
CMD ["--help"]
