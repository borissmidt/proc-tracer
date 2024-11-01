//go:build ignore
#include "vmlinux.h"

#include <asm/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 17);
} events SEC(".maps");

/* to debug use sudo cat /sys/kernel/tracing/trace_pipe  */
// Force emitting struct Event into the ELF.
const struct CommandEndEvent *unused1 __attribute__((unused));
const struct CommandParameterEvent *unused2 __attribute__((unused));


struct Execve {
    __u64 unused;
    __u32 nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};


struct CommandParameterEvent {
    u8 event_type;
    u32 pid;
    u16 index;
    u8 end;
    u8 arg[256];
};

// todo add argv for start of a task.
struct CommandEndEvent {
    u8 event_type;
    u32 pid;
    u32 ppid;
    u64 start_time_ns;
    u64 end_time_ns;
    u8 exit_code;
    u8 comm[TASK_COMM_LEN];
};

enum EventType {
  COMMAND_PARAMETERS,
  COMMAND_END,
};


SEC("tp/syscalls/sys_enter_execve")
int handle_execve_enter(struct Execve *ctx)
{
    u64 id = bpf_get_current_pid_tgid()>> 32;
    pid_t pid = id;
    struct CommandParameterEvent *event;
    int ret;
    u16 i = 0;

    const char * const parameter;
    while(i < 32) {
        bpf_probe_read(&parameter, sizeof(parameter), &ctx->argv[i]);
        if (!parameter){
            break;
        }

        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

        if (!event){
            return 0;
        }

        event->event_type=COMMAND_PARAMETERS;
        event->pid=pid;
        event->index=i;
        int bytesRead = bpf_probe_read_user_str(&event->arg, sizeof(event->arg), parameter);
        bpf_printk("arg length was %d", bytesRead);
        bpf_ringbuf_submit(event, 0);

        i++;
    }

    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx){
    u64 ts = bpf_ktime_get_ns();
    struct task_struct *task;
    struct CommandEndEvent *event;
    pid_t pid, tid;
    u64 id, *start_ts, start_time = 0;


    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    /* ignore thread exits */
    if (pid != tid)
        return 0;

    /* reserve sample from BPF ringbuf */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct *)bpf_get_current_task_btf();
    event->event_type = COMMAND_END;
    event->start_time_ns = task->start_time;
    event->end_time_ns = ts;
    event->pid = pid;
    event->ppid = task->real_parent->pid;
    event->exit_code = (task->exit_code >> 8) & 0xff;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(event, 0);


    return 0;
}