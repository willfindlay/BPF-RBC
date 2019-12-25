/* https://github.com/torvalds/linux/tree/master/include/trace/events */

#include "src/bpf/bpf_program.h"
#include "src/bpf/helpers.h"

/* Initialization arrays for structs */
BPF_ARRAY(__rbc_task_init, struct rbc_task, 1);

/* Hashmaps */
BPF_TABLE("lru_hash", u64, struct rbc_task, rbc_tasks, 10240); /* pid_tgid to rbc_task */

static inline struct rbc_task *update_rbc_task()
{
    int zero = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct rbc_task *rbc_task;
    struct mm_struct *mm;

    /* Attempt to look up directly */
    rbc_task = rbc_tasks.lookup(&pid_tgid);
    if (rbc_task)
        goto update;

    /* Look up or init rbc_task */
    rbc_task = __rbc_task_init.lookup(&zero);
    if (!rbc_task)
    {
#ifdef RBC_DEBUG
        bpf_trace_printk("ERROR: Could not fetch rbc_task from its init array.\n");
#endif
        return NULL;
    }
    rbc_task = rbc_tasks.lookup_or_try_init(&pid_tgid, rbc_task);
    if (!rbc_task)
    {
#ifdef RBC_DEBUG
        bpf_trace_printk("ERROR: Could not lookup or init rbc_task.\n");
#endif
        return NULL;
    }

update:
    /* Get current memory descriptor */
    mm = (struct mm_struct *) t->mm;

    rbc_task->pid = (pid_tgid >> 32);
    rbc_task->tgid = pid_tgid;
    rbc_task->stack_start = mm->start_stack;
    rbc_task->stack_end = mm->start_stack - mm->stack_vm * PAGE_SIZE; /* TODO: change this to + based on STACKGROWSUP */
    rbc_task->heap_start = mm->start_brk;
    rbc_task->heap_end = mm->brk;
    bpf_get_current_comm(rbc_task->comm, TASK_COMM_LEN);

    /* Maybe print debug info */
#ifdef RBC_DEBUG
    bpf_trace_printk("-------------------------------\n");
    bpf_trace_printk("Program:     %s\n", rbc_task->comm);
    bpf_trace_printk("PID:         %u\n", rbc_task->pid);
    bpf_trace_printk("TID:         %u\n", rbc_task->tgid);
    bpf_trace_printk("Stack start: %x\n", rbc_task->stack_start);
    bpf_trace_printk("Stack end:   %x\n", rbc_task->stack_end);
    bpf_trace_printk("Stack size:  %lu bytes\n", rbc_task->stack_start - rbc_task->stack_end);
    bpf_trace_printk("Heap start:  %x\n", rbc_task->heap_start);
    bpf_trace_printk("Heap end:    %x\n", rbc_task->heap_end);
    bpf_trace_printk("-------------------------------\n");
#endif

    return rbc_task;
}

/* BPF programs below this line ---------------------------------- */

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    RBC_FILTER_BY_COMM

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    RBC_FILTER_BY_COMM

    if (args->id == __NR_brk)
    {
#ifdef RBC_DEBUG
    bpf_trace_printk("brk called!\n");
#endif
        struct rbc_task *r = update_rbc_task();
    }

    if (args->id == __NR_mmap)
    {
#ifdef RBC_DEBUG
    bpf_trace_printk("mmap called!\n");
#endif
        struct rbc_task *r = update_rbc_task();
    }

    return 0;
}

int kprobe__expand_stack(struct pt_regs *ctx, struct vm_area_struct *vma, unsigned long addr)
{
    RBC_FILTER_BY_COMM

#ifdef RBC_DEBUG
    bpf_trace_printk("Expanding stack...\n");
#endif

    struct rbc_task *r = update_rbc_task();

    return 0;
}

int kretprobe__expand_stack(struct pt_regs *ctx)
{
    RBC_FILTER_BY_COMM

    /* Check if there was an error expanding the stack */
    if(PT_REGS_RC(ctx))
    {
#ifdef RBC_DEBUG
        bpf_trace_printk("Couldn't expand stack!\n");
#endif
    }
    else
    {
#ifdef RBC_DEBUG
    bpf_trace_printk("Expanded stack!\n");
#endif
    }

    struct rbc_task *r = update_rbc_task();

    return 0;
}
