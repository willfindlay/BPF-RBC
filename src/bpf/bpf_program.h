#ifndef BPF_PROGRAM_H
#define BPF_PROGRAM_H

#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

struct rbc_task
{
    u32 pid;
    u32 tgid;
    unsigned long stack_start;
    unsigned long stack_end;
    unsigned long heap_start;
    unsigned long heap_end;
    char comm[TASK_COMM_LEN];
};

#endif /* BPF_PROGRAM_H */
