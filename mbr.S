%include "boot.inc"
SECTION MBR vstart=0x7c00
mov ax, cs
mov ds, ax
mov es, ax
mov ss, ax
mov fs, ax
mov sp, 0x7c00
; Starting address of graphics card text mode
mov ax, 0xb800
mov gs, ax

mov ax, 0x0600
mov bx, 0x0700
mov cx, 0x0
mov dx, 0x184f
int 0x10

mov byte [gs:0x00], '1'
; 0x1010 0100 -> foreground is red, background is green, blink
mov byte [gs:0x01], 0xA4


mov byte [gs:0x02], ' '
mov byte [gs:0x03], 0xA4

mov byte [gs:0x04], 'M'
mov byte [gs:0x05], 0xA4


mov byte [gs:0x06], 'B'
mov byte [gs:0x07], 0xA4


mov byte [gs:0x08], 'R'
mov byte [gs:0x09], 0xA4

; macro defined in boot inc
mov eax, LOADER_START_SECTOR
mov bx, LOADER_BASE_ADDR
mov cx, 4
call rd_disk_m_16
jmp LOADER_BASE_ADDR + 0x300
;jmp $

rd_disk_m_16:
mov esi, eax
mov dx, 0x1f2
; 8 bits for this I/O ports (all 8 bits except data)
mov al, cl
out dx, al
mov eax, esi

mov dx, 0x1f3
out dx, al

push cx
mov cl, 8
shr eax, cl
mov dx, 0x1f4
out dx, al

shr eax, cl
mov dx, 0x1f5
out dx, al

shr eax, cl
and al, 0x0f
or al, 0xe0
mov dx, 0x1f6
out dx, al

mov dx, 0x1f7
mov al, 0x20
out dx, al

.not_ready:
nop
; read from the same port: 0x1f7 -- Status reg
in al, dx
; check the third bit in Status reg
and al, 0x88
cmp al, 0x08
jnz .not_ready

pop ax
mov dx, 256
mul dx
mov cx, ax

mov dx, 0x1f0
.go_on_read:
in ax, dx
mov [bx], ax
add bx, 2
loop .go_on_read
ret

times 510-($-$$) db 0

db 0x55, 0xaa
