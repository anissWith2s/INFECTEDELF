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
    lea rsi, [rel elf_header]
    mov rdx, EHDR_SIZE      ; Taille de l'en-tête ELF
    syscall
    test rax, rax
    js exit_error

    ; Vérifier le magic number ELF
    mov eax, dword [rel elf_header]
    cmp eax, ELF_MAGIC
    jne invalid_elf

    ; Vérifier que le fichier est un ELF 64 bits
    mov al, byte [rel elf_header + 4]
    cmp al, ELFCLASS64
    jne invalid_elf

    ; Lire e_phnum (nombre d'entrées PHDR)
    mov rax, 8              ; syscall: lseek
    mov rdi, r8
    mov rsi, E_PHNUM        ; Offset de e_phnum
    xor rdx, rdx            ; SEEK_SET
    syscall

    mov rax, 0              ; syscall: read
    mov rdi, r8
    lea rsi, [rel phdr_count]
    mov rdx, 2              ; Lire 2 octets
    syscall

    ; Lire e_phentsize (taille d'une entrée PHDR)
    mov rax, 8              ; syscall: lseek
    mov rdi, r8
    mov rsi, E_PHENTSIZE    ; Offset de e_phentsize
    xor rdx, rdx            ; SEEK_SET
    syscall

    mov rax, 0              ; syscall: read
    mov rdi, r8
    lea rsi, [rel phdr_entry_size]
    mov rdx, 2              ; Lire 2 octets
    syscall

    ; Lire e_phoff (offset des PHDR)
    mov rax, 8              ; syscall: lseek
    mov rdi, r8
    mov rsi, E_PHOFF        ; Offset de e_phoff
    xor rdx, rdx            ; SEEK_SET
    syscall

    mov rax, 0              ; syscall: read
    mov rdi, r8
    lea rsi, [rel phdr_offset]
    mov rdx, 8              ; Lire 8 octets
    syscall

    ; Positionner le curseur sur le premier PHDR
    mov r9, qword [rel phdr_offset] ; Charger l'offset initial des PHDR

find_pt_note:
    ; Lire une entrée PHDR
    mov rax, 8              ; syscall: lseek
    mov rdi, r8
    mov rsi, r9             ; Offset courant
    xor rdx, rdx            ; SEEK_SET
    syscall

    mov rax, 0              ; syscall: read
    mov rdi, r8
    lea rsi, [rel phdr_entry]
    mov rdx, qword [rel phdr_entry_size] ; Taille de l'entrée PHDR
    syscall

    ; Vérifier si c'est un PT_NOTE (type = 4)
    cmp dword [rel phdr_entry], PT_NOTE
    je found_pt_note

    ; Passer à l'entrée suivante
    add r9, qword [rel phdr_entry_size]
    inc rbx                 ; Incrémenter le compteur
    cmp bx, word [rel phdr_count]
    jl find_pt_note

    ; Aucun PT_NOTE trouvé, quitter avec une erreur
    mov rax, 60             ; syscall: exit
    mov rdi, 1              ; Code d'erreur
    syscall

found_pt_note:
    ; Sauvegarder l'offset du segment PT_NOTE
    mov qword [rel pt_note_offset], r9

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
phdr_offset dq 0                        ; Offset des segments PHDR
phdr_entry_size dw 0                    ; Taille d'une entrée PHDR
phdr_count dw 0                         ; Nombre d'entrées PHDR
pt_note_offset dq 0                     ; Offset du segment PT_NOTE

section .bss
elf_header resb 64                      ; Tampon pour l'en-tête ELF
phdr_entry resb 56                      ; Tampon pour une entrée PHDR
EHDR_SIZE equ 64                        ; Taille de l'en-tête ELF
ELF_MAGIC equ 0x464c457f                ; 0x7F "ELF" en little endian
ELFCLASS64 equ 2                        ; Classe ELF 64 bits
E_PHOFF equ 0x20                        ; Offset de e_phoff dans l'en-tête ELF
E_PHENTSIZE equ 0x36                    ; Offset de e_phentsize dans l'en-tête ELF
E_PHNUM equ 0x38                        ; Offset de e_phnum dans l'en-tête ELF
PT_NOTE equ 4                           ; Type PT_NOTE