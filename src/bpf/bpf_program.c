/* https://github.com/torvalds/linux/tree/master/include/trace/events */

#include <linux/sched.h>
#include "src/bpf/bpf_program.h"

static inline u32 bpf_strlen(char *s)
{
    u32 i;
    for (i = 0; s[i] != '\0' && i < (1 << (32 - 1)); i++);
    return i;
}

static inline int bpf_strncmp(char *s1, char *s2, u32 n)
{
    int mismatch = 0;
    for (int i = 0; i < n && i < sizeof(s1) && i < sizeof(s2); i++)
    {
        if (s1[i] != s2[i])
            return s1[i] - s2[i];

        if (s1[i] == s2[i] == '\0')
            return 0;
    }

    return 0;
}

static inline int bpf_strcmp(char *s1, char *s2)
{
    u32 s1_size = sizeof(s1);
    u32 s2_size = sizeof(s2);

    return bpf_strncmp(s1, s2, s1_size < s2_size ? s1_size : s2_size);
}

RAW_TRACEPOINT_PROBE(sys_enter)
{
    struct task *t = (struct task *)bpf_get_current_task();
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, TASK_COMM_LEN);

    if (bpf_strncmp(comm, EXECUTABLE, TASK_COMM_LEN))
        return 0;

    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];
    unsigned long bp = regs->sp; /* Base pointer */
    unsigned long sp = regs->si; /* Stack frame pointer */
    unsigned long ip = regs->ip; /* Instruction pointer */

    bpf_trace_printk("%x %x %x\n", bp, sp, ip);

    return 0;
}

RAW_TRACEPOINT_PROBE(sys_exit)
{

}
