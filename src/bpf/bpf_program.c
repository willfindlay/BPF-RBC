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

//RAW_TRACEPOINT_PROBE(sys_enter)
//{
//    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
//    char comm[TASK_COMM_LEN];
//    bpf_get_current_comm(comm, TASK_COMM_LEN);
//
//    /* Check if we are in the specified comm */
//    if (bpf_strncmp(comm, EXECUTABLE, TASK_COMM_LEN))
//        return 0;
//
//    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
//    unsigned long bp = regs->bp; /* Base pointer */
//    unsigned long sp = regs->sp; /* Stack frame pointer */
//    unsigned long ip = regs->ip; /* Instruction pointer */
//
//    struct mm_struct *mm = (struct mm_struct *) t->mm;
//    unsigned long end_stack = sp;
//    unsigned long start_stack = mm->start_stack;
//
//    //bpf_trace_printk("syscall: %lu rbp: %x rsp: %x\n", ctx->args[1], bp, sp);
//    bpf_trace_printk("syscall: %lu\n", ctx->args[1]);
//    bpf_trace_printk("stack start: %x stack end: %x stack size: %lu\n", start_stack, end_stack, (start_stack - end_stack));
//
//    return 0;
//}
TRACEPOINT_PROBE(kmem, mm_page_alloc)
{
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, TASK_COMM_LEN);

    /* Check if we are in the specified comm */
    if (bpf_strncmp(comm, EXECUTABLE, TASK_COMM_LEN))
        return 0;

    struct pt_regs *regs = bpf_get_current_pt_regs();
    unsigned long bp = regs->bp; /* Base pointer */
    unsigned long sp = regs->sp; /* Stack frame pointer */
    unsigned long ip = regs->ip; /* Instruction pointer */

    struct mm_struct *mm = (struct mm_struct *) t->mm;
    unsigned long end_stack = sp;
    unsigned long start_stack = mm->start_stack;

    //bpf_trace_printk("syscall: %lu rbp: %x rsp: %x\n", ctx->args[1], bp, sp);
    //bpf_trace_printk("syscall: %lu\n", ctx->args[1]);
    bpf_trace_printk("stack start: %x stack end: %x stack size: %lu\n", start_stack, end_stack, (start_stack - end_stack));
    bpf_trace_printk("stack start: %x\n", start_stack);
    return 0;
}
//
// RAW_TRACEPOINT_PROBE(sys_exit)
// {
//     struct task *t = (struct task *)bpf_get_current_task();
//     char comm[TASK_COMM_LEN];
//     bpf_get_current_comm(comm, TASK_COMM_LEN);
//
//     if (bpf_strncmp(comm, EXECUTABLE, TASK_COMM_LEN))
//         return 0;
//
//     struct pt_regs *regs = (struct pt_regs *) ctx->args[0];
//     unsigned long bp = regs->sp; /* Base pointer */
//     unsigned long sp = regs->si; /* Stack frame pointer */
//     unsigned long ip = regs->ip; /* Instruction pointer */
//
//     return 0;
// }
