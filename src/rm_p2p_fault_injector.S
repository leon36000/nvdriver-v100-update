/* SPDX-License-Identifier: MIT */
/*
 * Preserve the ioctl variadic ABI for all requests outside the three RM
 * encodings inspected by the C implementation. In particular, do not read a
 * missing third argument or reinterpret an integer argument as a pointer.
 * On first use, save every integer argument register and RAX/AL while C resolves
 * RTLD_NEXT; restore them before tail-jumping to the real ioctl implementation.
 */
#if !defined(__x86_64__)
#error "The V100 guest A/B runner currently targets Linux x86_64 only"
#endif

    .text
    .globl ioctl
    .type ioctl,@function
ioctl:
    endbr64

    movl    $0xc030462b, %r10d
    cmpq    %r10, %rsi
    je      .Lhybrid_rm_target
    movl    $0xc020462a, %r10d
    cmpq    %r10, %rsi
    je      .Lhybrid_rm_target
    movl    $0xc0104629, %r10d
    cmpq    %r10, %rsi
    je      .Lhybrid_rm_target

    movq    hybrid_rm_next_ioctl_address(%rip), %r11
    testq   %r11, %r11
    jz      .Lhybrid_rm_resolve_forward
    jmp     *%r11

.Lhybrid_rm_resolve_forward:
    pushq   %rax
    pushq   %r9
    pushq   %r8
    pushq   %rcx
    pushq   %rdx
    pushq   %rsi
    pushq   %rdi
    call    hybrid_rm_resolve_next_ioctl
    movq    %rax, %r11
    popq    %rdi
    popq    %rsi
    popq    %rdx
    popq    %rcx
    popq    %r8
    popq    %r9
    popq    %rax
    testq   %r11, %r11
    jz      .Lhybrid_rm_resolve_failed
    jmp     *%r11
.Lhybrid_rm_resolve_failed:
    movl    $-1, %eax
    ret
.Lhybrid_rm_target:
    jmp     hybrid_rm_target_ioctl_dispatch
    .size ioctl, .-ioctl

    .section .note.GNU-stack,"",@progbits
