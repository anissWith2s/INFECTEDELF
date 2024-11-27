section .text
    global _start

_start:
    ; Ouvrir le fichier ELF en lecture/écriture
    mov rax, 2              ; syscall: open
    lea rdi, [rel filename] ; Nom du fichier ELF
    mov rsi, 2              ; O_RDWR (lecture-écriture)
    xor rdx, rdx            ; Pas de flags supplémentaires
    syscall
    test rax, rax
    js exit_error
    mov r8, rax             ; Sauvegarde du file descriptor

    ; Lire l'en-tête ELF (64 octets)
    mov rax, 0              ; syscall: read
    mov rdi, r8
    lea rsi, [rel elf_header] ; Tampon pour stocker l'en-tête ELF
    mov rdx, 64             ; Taille de l'en-tête ELF
    syscall
    test rax, rax
    js exit_error

    ; Vérifier le magic number ELF
    mov eax, dword [rel elf_header]
    cmp eax, 0x464c457f     ; Vérifie si c'est 0x7f "ELF"
    jne invalid_elf

    ; Vérifier que le fichier est un ELF 64 bits
    mov al, byte [rel elf_header + 4]
    cmp al, 2               ; ELFCLASS64 (2)
    jne invalid_elf

    ; Positionner le curseur pour lire e_phoff
    mov rax, 8              ; syscall: lseek
    mov rdi, r8             ; file descriptor
    mov rsi, 0x20           ; offset de e_phoff
    xor rdx, rdx            ; SEEK_SET
    syscall

    ; Lire l'offset e_phoff
    mov rax, 0              ; syscall: read
    mov rdi, r8             ; file descriptor
    lea rsi, [rel phdr_offset]
    mov rdx, 8              ; lire 8 octets (valeur 64 bits)
    syscall

    ; Charger l'offset des segments PHDR
    mov rax, 8              ; syscall: lseek
    mov rdi, r8             ; file descriptor
    mov rsi, qword [rel phdr_offset]  ; Offset des segments PHDR
    xor rdx, rdx            ; SEEK_SET
    syscall

;Initialiser le compteur
xor rbx, rbx            ; compteur d'itérations

find_pt_note:
    ; Lire une entrée PHDR
    mov rax, 0          ; syscall: read
    mov rdi, r8         ; file descriptor
    lea rsi, [rel phdr_entry]
    mov rdx, 56         ; Taille d'une entrée PHDR (64 bits ELF)
    syscall

    ; Vérifier si c'est un PT_NOTE (type = 4)
    cmp dword [rel phdr_entry], 0x4
    je found_pt_note    ; Si oui, on a trouvé le segment PT_NOTE

    ; Passer à la prochaine entrée PHDR
    add qword [rel phdr_offset], 56
    inc rbx
    cmp bx, word [rel phdr_count]
    jl find_pt_note

; Si aucun PT_NOTE n'est trouvé, quitter avec une erreur
mov rax, 60             ; syscall: exit
mov rdi, 1              ; code d'erreur
syscall

found_pt_note:
    ; Sauvegarder l'offset du segment PT_NOTE
    mov qword [rel pt_note_offset], rsi

    ; Terminer proprement
    mov rax, 3              ; syscall: close
    mov rdi, r8
    syscall

    mov rax, 60             ; syscall: exit
    xor rdi, rdi            ; Code de sortie 0 (succès)
    syscall

exit_error:
    ; Afficher un message d'erreur
    mov rax, 1              ; syscall: write
    mov rdi, 1              ; stdout
    lea rsi, [rel error_msg]
    mov rdx, error_msg_len
    syscall

    mov rax, 60             ; syscall: exit
    mov rdi, 1              ; Code de sortie 1 (échec)
    syscall

invalid_elf:
    ; Afficher un message pour fichier non ELF
    mov rax, 1              ; syscall: write
    mov rdi, 1              ; stdout
    lea rsi, [rel not_elf_msg]
    mov rdx, not_elf_msg_len
    syscall

    mov rax, 60             ; syscall: exit
    mov rdi, 2              ; Code de sortie 2 (fichier invalide)
    syscall

section .data
filename db "hello", 0                  ; Nom du fichier ELF cible
error_msg db "Erreur lors de l'ouverture du fichier!", 0xa
error_msg_len equ $ - error_msg
not_elf_msg db "Le fichier n'est pas un ELF valide!", 0xa
not_elf_msg_len equ $ - not_elf_msg
phdr_offset dq 0           ; Offset des PHDR
phdr_entry  db 56 dup(0)   ; Buffer pour une entrée PHDR (taille max 56 octets)
phdr_count  dw 0           ; Nombre d'entrées PHDR
pt_note_offset dq 0        ; Offset du segment PT_NOTE

section .bss
elf_header resb 64                      ; Tampon pour stocker l'en-tête ELF
