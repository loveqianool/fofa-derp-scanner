# syntax=docker/dockerfile:1
#
# 构建多架构镜像：
#   docker buildx build --platform linux/amd64,linux/arm64 -t derp-scan .
#
# 二进制为纯静态编译（CGO_ENABLED=0），不依赖目标系统的 libc，
# 运行在 Alpine (musl) 基础镜像上，体积小。

FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS builder
ARG TARGETOS TARGETARCH
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /derp-scan .

FROM alpine:3.21
COPY --from=builder /derp-scan /usr/local/bin/derp-scan
ENTRYPOINT ["derp-scan"]
CMD ["--help"]
