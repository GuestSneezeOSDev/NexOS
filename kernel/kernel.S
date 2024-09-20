[bits 32]
%define ERROR_CODE nop
%define ZERO push 0

extern idt_table

section .data
global intr_entry_table
intr_entry_table:

%macro VECTOR 2
section .text
intr_%1_entry:
%2

push ds
push es
push fs
push gs
pushad

mov al,0x20
out 0xa0,al
out 0x20,al

push %1

call [idt_table + %1*4]
jmp intr_exit

section .data
dd intr_%1_entry

%endmacro

section .text
global intr_exit
intr_exit:
; skip interrupt vector number
add esp,4
popad
pop gs
pop fs
pop es
pop ds

add esp,4
iretd


VECTOR 0X00, ZERO
VECTOR 0X01, ZERO
VECTOR 0X02, ZERO
VECTOR 0X03, ZERO
VECTOR 0X04, ZERO
VECTOR 0X05, ZERO
VECTOR 0X06, ZERO
VECTOR 0X07, ZERO
VECTOR 0X08, ERROR_CODE
VECTOR 0X09, ZERO
VECTOR 0X0a, ERROR_CODE
VECTOR 0X0b, ERROR_CODE
VECTOR 0X0c, ERROR_CODE
VECTOR 0X0d, ERROR_CODE
VECTOR 0X0e, ERROR_CODE
VECTOR 0X0f, ZERO
VECTOR 0X10, ZERO
VECTOR 0X11, ERROR_CODE
VECTOR 0X12, ZERO
VECTOR 0X13, ZERO
VECTOR 0X14, ZERO
VECTOR 0X15, ZERO
VECTOR 0X16, ZERO
VECTOR 0X17, ZERO
VECTOR 0X18, ZERO
VECTOR 0X19, ZERO
VECTOR 0X1a, ZERO
VECTOR 0X1b, ZERO
VECTOR 0X1c, ZERO
VECTOR 0X1d, ZERO
VECTOR 0X1e, ERROR_CODE
VECTOR 0X1f, ZERO
VECTOR 0X20, ZERO 
VECTOR 0X21, ZERO 
VECTOR 0X22, ZERO
VECTOR 0X23, ZERO
VECTOR 0X24, ZERO
VECTOR 0X25, ZERO
VECTOR 0X26, ZERO
VECTOR 0X27, ZERO
VECTOR 0X28, ZERO
VECTOR 0X29, ZERO
VECTOR 0X2a, ZERO
VECTOR 0X2b, ZERO
VECTOR 0X2c, ZERO
VECTOR 0X2d, ZERO
VECTOR 0X2e, ZERO
VECTOR 0X2f, ZERO

[bits 32]
extern syscall_table
section .text
global syscall_handler
syscall_handler:
push 0
push ds
push es
push fs
push gs
pushad

push 0x80

push edx
push ecx
push ebx

call [syscall_table+4*eax]
add esp,12

mov [esp+8*4], eax
jmp intr_exit



