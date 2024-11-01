//go:build ignore

#include <linux/bpf.h>
#include <asm/types.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct execve {
    __u64 unused;
    __u32 pid;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

struct process {
    __u32 pid;
    __u64 timestamp;
    __u8 state;
    // max lenght of ext4
    unsigned char filename[4096];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct process *unused __attribute__((unused));

// count_packets atomically increases a packet counter on every invocation.
//SEC("tp/syscall/sys_enter_execve")
SEC("tp/syscalls/sys_enter_execve")
int sys_enter_execve(struct execve *ctx){
//    for (int i = 0; i < 10; i++) {
//        const char *arg = NULL;
//        bpf_probe_read_user(&arg, sizeof(arg), &ctx->argv[i]);
//        bpf_printk("arg%d: %s ", i, arg);
//    }
//    bpf_printk("\n");

    const char y[] = "hello";
    __u32 pid = bpf_get_current_pid_tgid();
    
    struct process *task_info = bpf_ringbuf_reserve(&events, sizeof(struct process), 0);
    if (!task_info){
        return 0;
    }
    
    task_info->pid = pid;
    task_info->state = 200;
    task_info->timestamp = bpf_ktime_get_ns();
    bpf_probe_read_user(&task_info->filename, 4096, ctx->filename);
    
    // task_info -> argv = ctx->argv;
    // task_info -> envp = ctx->envp;
    if (task_info->filename[0] == '\0') {
        bpf_ringbuf_discard(task_info, 0);
        return 0;
    }

    
    bpf_ringbuf_submit(task_info, 0);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("tp/syscalls/sys_enter_exit")
int syscall_trace_exit_call(void *ctx){
    bpf_printk("exit call\n");
    __u32 pid = bpf_get_current_pid_tgid();

    struct process *task_info = bpf_ringbuf_reserve(&events, sizeof(struct process), 0);
    if (!task_info){
        return 0;
    }
    task_info->pid = pid;
    task_info->state = 200;
    bpf_ringbuf_submit(task_info, 0);
    return 0;
}