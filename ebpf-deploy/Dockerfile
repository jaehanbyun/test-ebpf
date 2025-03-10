FROM golang:1.24.0 as builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    gcc \
    make \
    pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . . 

RUN go generate ./...

RUN CGO_ENABLED=0 GOOS=linux go build -o ebpf-manager .

FROM alpine:latest

RUN apk add --no-cache libelf ca-certificates

WORKDIR /app

RUN mkdir -p /app

COPY --from=builder /app/ebpf-manager /app/
COPY --from=builder /app/trafficmonitor_bpfeb.o /app/
COPY --from=builder /app/trafficmonitor_bpfel.o /app/

ENV IFACE="eth0"

ENTRYPOINT ["/app/ebpf-manager"]