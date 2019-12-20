/* https://github.com/torvalds/linux/tree/master/include/trace/events */

#include <linux/sched.h>

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

RAW_TRACEPOINT_PROBE(mm_lru_insertion)
{
    struct task *t = (struct task *)bpf_get_current_task();
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, TASK_COMM_LEN);

    struct page *p = (struct page *)ctx->args[0];

    if (bpf_strncmp(comm, EXECUTABLE, TASK_COMM_LEN))
        return 0;

    bpf_trace_printk("%s\n", comm);

    return 0;
}
