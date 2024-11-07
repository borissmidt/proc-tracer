package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"time"
)

// https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md

type JsonOutput struct {
	uid      uint32   `json:"uid"`
	Pid      uint32   `json:"pid"`
	PPid     uint32   `json:"ppid"`
	Command  string   `json:"name"`
	FileName string   `json:"fileName"`
	Args     []string `json:"args"`
	Start    uint64   `json:"startTimeNs"`
	Duration uint64   `json:"durationNs"`
	ExitCode uint8    `json:"exitCode"`
}

//go:generate  go run github.com/cilium/ebpf/cmd/bpf2go -type CommandEndEvent -type CommandParameterEvent proctracer proc-tracer.c
func main() {
	logJson := flag.String("format", "json", "enables the json output of the command")
	output := flag.String("output", "", "enables the json output of the command")
	flag.Parse()

	if *logJson != "json" {
		log.Fatal("--format only supports [json]")
	}

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

	writer := io.Discard
	if *output != "" {
		file, err := os.Create(*output)
		if err != nil {
			log.Fatal(err)
		}

		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				slog.Warn("failed to close the output file", "error", err, "file", *output)
			}
		}(file)

		writer = file
	}

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

			if *logJson == "json" {
				data, err := json.Marshal(JsonOutput{
					Pid:      commandEndEvent.Pid,
					PPid:     commandEndEvent.Ppid,
					Command:  command,
					Args:     args,
					Start:    commandEndEvent.StartTimeNs,
					Duration: uint64(time.Duration(commandEndEvent.EndTimeNs - commandEndEvent.StartTimeNs).Nanoseconds()),
					ExitCode: commandEndEvent.ExitCode,
				})
				if err != nil {
					slog.Error("failed to marshal json", "error", err)
					os.Exit(1)
				}

				_, err = writer.Write(data)
				if err != nil {
					slog.Error("failed to write json", "error", err)
					os.Exit(1)
				}

				_, err = writer.Write([]byte("\n"))
				if err != nil {
					slog.Error("failed to write json", "error", err)
					os.Exit(1)
				}
			}

		}
	}
}
