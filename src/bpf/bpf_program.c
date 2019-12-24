/* https://github.com/torvalds/linux/tree/master/include/trace/events */

#include "src/bpf/bpf_program.h"
#include "src/bpf/helpers.h"

/* Store intermediate values between entry and exit points */
static int store_intermediate_values(void)
{
    return 0;
}

int kprobe__expand_stack(struct pt_regs *ctx, struct vm_area_struct *vma, unsigned long addr)
{
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, TASK_COMM_LEN);

    /* Check if we are in the specified comm */
    if (bpf_strncmp(comm, EXECUTABLE, TASK_COMM_LEN))
        return 0;

    struct mm_struct *mm = (struct mm_struct *) t->mm;

    //struct rbc_task task;
    //__builtin_memset(&task, 0, sizeof(struct rbc_task));
    //task->pid = bpf_get_current_pid_tgid();
    //task->tgid = (bpf_get_current_pid_tgid() >> 32);

    bpf_trace_printk("Expanding stack...\n");
    bpf_trace_printk("stack start: %x\n", mm->start_stack);
    bpf_trace_printk("stack end: %x\n", mm->start_stack + mm->stack_vm);
    bpf_trace_printk("stack size: %lu bytes\n", mm->stack_vm * PAGE_SIZE);
    bpf_trace_printk("--------------------------\n");
    return 0;
}

int kretprobe__expand_stack(struct pt_regs *ctx)
{
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, TASK_COMM_LEN);

    /* Check if we are in the specified comm */
    if (bpf_strncmp(comm, EXECUTABLE, TASK_COMM_LEN))
        return 0;

    struct mm_struct *mm = (struct mm_struct *) t->mm;
    unsigned long start_stack = mm->start_stack;

    if(PT_REGS_RC(ctx))
    {
        bpf_trace_printk("Couldn't expand stack!\n");
        return 0;
    }

    bpf_trace_printk("stack start: %x\n", mm->start_stack);
    bpf_trace_printk("stack end: %x\n", mm->start_stack + mm->stack_vm * PAGE_SIZE);
    bpf_trace_printk("stack size: %lu bytes\n", mm->stack_vm * PAGE_SIZE);
    bpf_trace_printk("Expanded stack!\n");
    bpf_trace_printk("--------------------------\n");


    return 0;
}

int kprobe__vm_brk(struct pt_regs *ctx)
{
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, TASK_COMM_LEN);

    /* Check if we are in the specified comm */
    if (bpf_strncmp(comm, EXECUTABLE, TASK_COMM_LEN))
        return 0;

    struct mm_struct *mm = (struct mm_struct *) t->mm;
    unsigned long start_stack = mm->start_stack;

    //if(PT_REGS_RC(ctx))
    //{
    //    bpf_trace_printk("Couldn't expand heap!\n");
    //    return 0;
    //}

    bpf_trace_printk("heap start: %x\n", mm->start_brk);
    bpf_trace_printk("heap end: %x\n", mm->brk);
    bpf_trace_printk("heap size: %lu bytes\n", mm->brk - mm->start_brk);
    bpf_trace_printk("Expanded heap!\n");


    return 0;
}
