IMAGE ?= floodgate:dev

# Native Linux (needs clang, llvm, libbpf-dev, go).
build:
	go generate ./...
	go build -o bin/floodgate ./cmd/floodgate

# BPF_PROG_RUN tests need root; unit tests don't.
test:
	go generate ./...
	sudo -E go test ./...

# Anywhere with Docker (incl. Docker Desktop on macOS/Windows).
docker-build:
	docker build -t $(IMAGE) .

docker-test:
	docker build --target build -t $(IMAGE)-build .
	docker run --rm --privileged $(IMAGE)-build sh -c \
		'mount -t bpf bpf /sys/fs/bpf 2>/dev/null; go test ./...'

.PHONY: build test docker-build docker-test
