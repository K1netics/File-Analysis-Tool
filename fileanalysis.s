;Author Tobias Tomana
;Purpose Forensic Analysis of Files

; To Do
; create logic to retrive and print metadata from struct

;Features
;File Metadata
;Hex Dump
;Count Byte
;Signature Detection
;Format Parsing
;Malware Detection 
;Output Results
;User Interaction 
section .data
    filename db 'test.txt', 0       ; Null-terminated string for filename
    err_msg db 'Error opening file', 0 ; Error message
    err_msg_len equ $ - err_msg      ; Length of error message
    buffer db 'Error code: ', 0      ; Buffer for the error message prefix
    buffer_len equ $ - buffer         ; Length of the error message prefix

section .bss
    fd resb 4                        ; Reserve 4 bytes for file descriptor
    data_buffer resb 256             ; Reserve 256 bytes for data buffer
    bytes_read resb 4                ; Store number of bytes read 
    error_code resb 4                ; Reserve space for error code string
    
    ;Stats Struct
    file_metadata resb 48  ; Reserve space for the struct (8 fields * 8 bytes for 64-bit architecture)

    ; Define each field in the struct
    st_dev   resb 8          ; Device ID (dev_t)
    st_ino   resb 8          ; Inode number (ino_t)
    st_mode  resb 8          ; File type and mode (mode_t)
    st_nlink resb 8          ; Number of hard links (nlink_t)
    st_uid   resb 8          ; Owner's user ID (uid_t)
    st_gid   resb 8          ; Owner's group ID (gid_t)
    st_size  resb 8          ; Total size, in bytes (off_t)
    st_atime resb 8          ; Last access time (time_t)
    st_mtime resb 8          ; Last modification time (time_t)
    st_ctime resb 8          ; Last status change time (time_t)

section .text
    global _start

_start:
    ; Open the file for reading
    mov rax, 2                       ; syscall: open
    lea rdi, [filename]              ; pointer to filename
    mov rsi, 0                       ; flags: O_RDONLY
    syscall

    ; Check for errors
    test rax, rax                    ; Check if rax is zero (error)
    js .error_open                   ; Jump to error handling if rax < 0

    mov [fd], rax                    ; Save file descriptor

    ; Read from the file
    mov rax, 0                       ; syscall: read
    mov rdi, [fd]                    ; file descriptor
    lea rsi, [data_buffer]           ; pointer to data buffer
    mov rdx, 256                     ; number of bytes to read
    syscall

    ; Store number of bytes read
    mov [bytes_read], rax

    ; Check if anything was read
    cmp rax, 0                       ; Compare the number of bytes read with 0
    jle .nothing_read                ; If less than or equal to 0, jump to nothing_read

    ; Print the data buffer to stdout
    mov rax, 1                       ; syscall: write
    mov rdi, 1                       ; file descriptor: stdout
    lea rsi, [data_buffer]           ; pointer to data buffer
    mov rdx, [bytes_read]            ; number of bytes to print
    syscall

    ; Close the file
    mov rax, 3                       ; syscall: close
    mov rdi, [fd]                    ; file descriptor
    syscall

    ; Exit the program
    mov rax, 60                      ; syscall: exit
    xor rdi, rdi                     ; exit code 0
    syscall

.nothing_read:
    ; Handle case where nothing was read
    mov rax, 1                       ; syscall: write
    mov rdi, 1                       ; file descriptor: stdout
    lea rsi, [err_msg]               ; pointer to error message
    mov rdx, err_msg_len             ; length of error message
    syscall
    jmp .exit                        ; Jump to exit

.error_open:
    ; Handle error opening file
    mov rax, 1                       ; syscall: write
    mov rdi, 1                       ; file descriptor: stdout
    lea rsi, [err_msg]               ; pointer to error message
    mov rdx, err_msg_len             ; length of error message
    syscall

    ; Print the error number
    mov rax, rax                     ; Move the error number into rax
    mov rbx, 10                      ; Base 10 for conversion
    lea rsi, [error_code]            ; Buffer for error code string
    xor rcx, rcx                     ; Clear counter

.convert_loop:
    xor rdx, rdx                     ; Clear rdx (remainder)
    div rbx                          ; Divide rax by 10, result in rax, remainder in rdx
    add dl, '0'                      ; Convert remainder to ASCII
    dec rsi                          ; Move buffer pointer back
    mov [rsi], dl                    ; Store character in buffer
    inc rcx                          ; Increment counter
    test rax, rax                    ; Check if rax is zero
    jnz .convert_loop                ; Continue if rax is not zero

    ; Print the error code
    mov rax, 1                       ; syscall: write
    mov rdi, 1                       ; file descriptor: stdout
    lea rsi, [rsi]                   ; pointer to error code string
    mov rdx, rcx                     ; length of error code
    syscall

    jmp .exit                        ; Jump to exit

.file_metadata:
    mov rax, 4                      
    lea rdi, [filename]             ;pointer to file
    lea rsi, [file_metadata]          ;pointer to stat structure. This will populate the metadata struct. 
    syscall                             

    cmp rax, -1          ; Check if rax is -1 (indicating an error)
    je .error            ; Jump to error handling if it is

    xor ebx, ebx

    .metadata_loop:
        
        





.exit:
    ; Exit the program
    mov rax, 60                      ; syscall: exit
    xor rdi, rdi                     ; exit code 0
    syscall
