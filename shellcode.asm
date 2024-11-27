section .text
    global _start

_start:
    ; Appeler write(1, "Infected!", 9)
    mov rax, 1          ; syscall: write
    mov rdi, 1          ; File descriptor: stdout
    lea rsi, [rel msg]  ; Adresse du message
    mov rdx, 9          ; Taille du message
    syscall

    ; Restaurer l'ancienne entry point et y sauter
    lea rax, [rel original_entry]
    jmp qword [rax]

msg db "Infected!", 0
original_entry dq 0x1060