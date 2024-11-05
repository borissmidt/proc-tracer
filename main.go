package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"time"
)

// https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md

type JsonOutput struct {
	Pid      uint32   `json:"pid"`
	PPid     uint32   `json:"ppid"`
	Command  string   `json:"command"`
	Args     []string `json:"args"`
	Start    uint64   `json:"span-start-ns"`
	End      uint64   `json:"span-end-ns"`
	Duration uint64   `json:"duration-ns"`
	ExitCode uint8    `json:"exit-code"`
}

//go:generate  go run github.com/cilium/ebpf/cmd/bpf2go -type CommandEndEvent -type CommandParameterEvent proctracer proc-tracer.c
func main() {
	logJson := flag.Bool("json", false, "enables the json output of the command")
	flag.Parse()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs proctracerObjects
	if err := loadProctracerObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	l1, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecveEnter, &link.TracepointOptions{Cookie: 122})
	if err != nil {
		log.Fatal(err)
	}
	defer l1.Close()

	l2, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, &link.TracepointOptions{Cookie: 123})
	if err != nil {
		log.Fatal(err)
	}
	defer l2.Close()

	stop := make(chan os.Signal, 5)

	reader, err := ringbuf.NewReader(objs.proctracerMaps.Events)
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

	// avoid confusion by having a single start print.
	slog.Info("starting tracer")

	var commandParamterEvent proctracerCommandParameterEvent
	var commandEndEvent proctracerCommandEndEvent

	// to get the event to arg
	commandParameters := map[uint32][]proctracerCommandParameterEvent{}

	for {
		record, err := reader.Read()
		if err != nil {
			slog.Error("failed to read event", "error", err)
			os.Exit(1)
		}

		switch record.RawSample[0] {
		case 0:
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &commandParamterEvent)
			if err != nil {
				slog.Error("failed to parsing event", "error", err)
				os.Exit(1)
			}
			commandParameters[commandParamterEvent.Pid] = append(commandParameters[commandParamterEvent.Pid], commandParamterEvent)
		case 1:
			// the args already come in ordered.
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &commandEndEvent)
			if err != nil {
				slog.Error("failed to parsing event", "error", err)
				os.Exit(1)
			}

			commandArgEvents := commandParameters[commandEndEvent.Pid]
			args := make([]string, len(commandArgEvents))
			command := unix.ByteSliceToString(commandEndEvent.Comm[:])
			logger := slog.With("command", command)
			for i, c := range commandArgEvents {
				args[i] = unix.ByteSliceToString(c.Arg[:])
			}

			logger.Info("command finished", "parameters", args, "exit-code", commandEndEvent.ExitCode, "start-time", commandEndEvent.StartTimeNs, "end-time", commandEndEvent.EndTimeNs, "duration", time.Duration(commandEndEvent.EndTimeNs-commandEndEvent.StartTimeNs).Seconds())

			if *logJson {
				data, err := json.Marshal(JsonOutput{
					Pid:      commandEndEvent.Pid,
					PPid:     commandEndEvent.Ppid,
					Command:  command,
					Args:     args,
					Start:    commandEndEvent.StartTimeNs,
					End:      commandEndEvent.EndTimeNs,
					Duration: uint64(time.Duration(commandEndEvent.EndTimeNs - commandEndEvent.StartTimeNs).Nanoseconds()),
					ExitCode: commandEndEvent.ExitCode,
				})
				if err != nil {
					slog.Error("failed to marshal json", "error", err)
					os.Exit(1)
				}

				fmt.Println(string(data))
			}

		}
	}
}
