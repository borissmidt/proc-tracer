
gen-virtual-linux:
    # https://github.com/libbpf/bpftool/releases/tag/v7.5.0
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h


test:
    golangci-lint ./..

build:
    go generate ./...
    go build .