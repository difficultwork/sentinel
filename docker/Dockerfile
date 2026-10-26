FROM bpf2go-builder:latest AS builder

WORKDIR /app

COPY . .

RUN clang-18 \
    -O2 -g -target bpf \
	-Wall -Werror \
    -I/usr/include/x86_64-linux-gnu \
	-Ibpf/headers \
    -c bpf/sentinel.bpf.c -o internal/loader/sentinel.bpf.o

RUN llvm-objdump-18 -h internal/loader/sentinel.bpf.o

RUN go build -o ./bin/sentinel ./cmd/sentinel && \
    go build -o ./bin/sentinel-cli ./cmd/sentinel-cli && \
    go build -o ./bin/demo-agent ./cmd/demo-agent

FROM ubuntu:24.04 AS final

COPY --from=builder /app/bin/sentinel /usr/local/bin/sentinel
COPY --from=builder /app/bin/sentinel-cli /usr/local/bin/sentinel-cli
COPY --from=builder /app/bin/demo-agent /usr/local/bin/demo-agent

COPY ./docker/sentinel-verify.yaml /etc/sentinel/sentinel-verify.yaml
COPY ./docker/attach-agent.sh /usr/local/bin/attach-agent.sh
RUN chmod +x /usr/local/bin/attach-agent.sh