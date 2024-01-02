[BITS 64]

EXTERN GraphStrike
GLOBAL Start

[SECTION .text$A]

Start:
    push   rsi
    mov    rsi, rsp
    and    rsp, 0FFFFFFFFFFFFFFF0h
    sub    rsp, 020h
    call   GraphStrike
    mov    rsp, rsi
    pop    rsi
    ret
