[bits 32]
section .data
put_int_buffer dq 0

section .text
TI_GDT equ 0
RPL0 equ 0
SELECTOR_VIDEO equ (0x0003<<3) + TI_GDT + RPL0

global put_char
put_char:

pushad

mov ax, SELECTOR_VIDEO
mov gs, ax

mov dx, 0x03d4
mov al, 0x0e
out dx, al
mov dx, 0x03d5
in al, dx
mov ah, al
mov dx, 0x03d4
mov al, 0x0f
out dx, al
mov dx, 0x03d5
in al, dx
mov bx, ax
mov ecx, [esp+36]

cmp cl, 0xd
jz .is_carriage_return
cmp cl, 0xa
jz .is_line_feed
cmp cl, 0x8
jz .is_backspace
jmp .put_other

.is_backspace:
dec bx
shl bx, 1

mov byte [gs:bx], 0x20
inc bx
mov byte [gs:bx], 0x07
shr bx, 1
jmp .set_cursor

.put_other:
shl bx, 1
mov [gs:bx], cl
inc bx
mov byte [gs:bx], 0x07
shr bx, 1
inc bx
cmp bx, 2000
jl .set_cursor

.is_line_feed:
.is_carriage_return:
xor dx, dx
mov ax, bx
mov si, 80
div si
sub bx, dx
add bx, 80
cmp bx, 2000
jl .set_cursor


.roll_screen:
cld
; ((2000-80)*2)/4=960
mov ecx, 960
mov esi, 0xc00b80a0 ; beginning of line 0
mov edi, 0xc00b8000 ; beginning of line 1
; mov 4 bytes (double word) each time
rep movsd

; 1920*2 = 3840
mov ebx, 3840
mov ecx, 80
.cls:
mov word [gs:ebx], 0x0720
add ebx, 2
loop .cls
mov bx, 1920

.set_cursor:
mov dx, 0x03d4
mov al, 0x0e
out dx, al

mov dx, 0x03d5
mov al, bh
out dx, al

mov dx, 0x03d4
mov al, 0x0f
out dx, al

mov dx, 0x03d5
mov al, bl
out dx, al

.put_char_end:
popad
ret
global put_str
put_str:
push ebx
push ecx

xor ecx, ecx
mov ebx, [esp+12]

.impl:
mov cl, [ebx]

cmp cl, 0
jz .str_over

push ecx
call put_char
add esp, 4
inc ebx
loop .impl

.str_over:
pop ecx
pop ebx
ret

global put_int
put_int:
pushad
mov ebp, esp

;jmp $
mov eax, [ebp+36]
mov edx, eax

mov edi, 7
mov ecx, 8
mov ebx, put_int_buffer

.to_char_each_4_bits:
and edx, 0x0000000F
cmp edx, 9
jg .is_A2F
add edx, '0'
jmp .store
.is_A2F:
sub edx, 10
add edx, 'A'

.store:
mov [ebx+edi], dl
dec edi
shr eax, 4
mov edx, eax
loop .to_char_each_4_bits

.ready_to_print:
; -1 (0xffffffff) +1 = 0
inc edi

.skip_prefix_0:
cmp edi, 8
je .num_is_0

.detect_prefix_0:
mov cl, [put_int_buffer+edi]
inc edi
cmp cl, '0'
je  .skip_prefix_0
dec edi
jmp .put_each_num

.num_is_0:
; the number to be printed is zero
mov cl, '0'

.put_each_num:
push ecx
call put_char
add esp, 4
inc edi
mov cl, [put_int_buffer+edi]
cmp edi, 8
jl .put_each_num
popad
ret

global set_cursor
set_cursor:
pushad
mov bx, [esp+36]
mov dx, 0x03d4
mov al, 0x0e
out dx, al

mov dx, 0x03d5
mov al, bh
out dx, al

mov dx, 0x03d4
mov al, 0x0f
out dx, al

mov dx, 0x03d5
mov al, bl
out dx, al

popad
ret

global sys_clear
sys_clear:
pushad
mov ax, SELECTOR_VIDEO
mov gs, ax

mov ebx, 0
mov ecx, 80*25

.cls:
mov word [gs:ebx],0x0720
add ebx, 2
loop .cls

mov ebx, 0

.set_cursor:
mov dx, 0x03d4
mov al, 0x0e
out dx, al

mov dx, 0x03d5
mov al, bh
out dx, al

mov dx, 0x03d4
mov al, 0x0f
out dx, al

mov dx, 0x03d5
mov al, bl
out dx, al

.put_char_end:
popad
ret


