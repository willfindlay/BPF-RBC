/* https://github.com/torvalds/linux/tree/master/include/trace/events */

#include <linux/sched.h>
#include <linux/mm_types.h>
#include "src/bpf/bpf_program.h"

static inline struct pt_regs *bpf_get_current_pt_regs()
{
    struct task_struct* __current = (struct task_struct*)bpf_get_current_task();
    void* __current_stack_page = __current->stack;
    void* __ptr = __current_stack_page + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
    return ((struct pt_regs *)__ptr) - 1;
}

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
