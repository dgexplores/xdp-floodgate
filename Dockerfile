# Build toolchain + runtime image. Also the way to build on macOS/Windows.
FROM golang:1.25-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev linux-libc-dev \
    && rm -rf /var/lib/apt/lists/* \
    # asm/types.h lives in an arch-specific dir clang -target bpf doesn't search
    && ln -s /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go generate ./... && CGO_ENABLED=0 go build -o /floodgate ./cmd/floodgate

FROM debian:bookworm-slim
COPY --from=build /floodgate /usr/local/bin/floodgate
ENTRYPOINT ["floodgate"]
