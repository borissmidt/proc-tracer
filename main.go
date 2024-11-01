package main

import (
	"bytes"
	"encoding/binary"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"log"
	"log/slog"
	"os"
	"os/signal"
)

//go:generate  go run github.com/cilium/ebpf/cmd/bpf2go -type process counter counter.c
func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()
	link.Tracepoint("syscalls", "sys_enter_execve", objs.SysEnterExecve, &link.TracepointOptions{123})

	// Attach count_packets to the network interface.

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	stop := make(chan os.Signal, 5)

	reader, err := ringbuf.NewReader(objs.counterMaps.Events)
	if err != nil {
		slog.Error("failed to get reader", "error", err)
		return
	}

	defer reader.Close()

	go func() {
		<-stop
		_ = reader.Close()
	}()

	signal.Notify(stop, os.Interrupt)

	var event counterProcess
	for {
		record, err := reader.Read()
		if err != nil {
			slog.Error("failed to read event", "error", err)
			os.Exit(1)
		}

		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			slog.Error("failed to parsing event", "error", err)
			os.Exit(1)
		}

		slog.Info("got an event", "filename", unix.ByteSliceToString(event.Filename[:]), "pid", event.Pid, "timestamp", event.Timestamp, "code", event.State)

	}
}
