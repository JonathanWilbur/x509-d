.global getRandomInt
.text
getRandomInt:
	mov %ecx, 11
.checkIfRandomNumberIsAvailable:
    sub %ecx, 1
    jz .exit
    rdrand %eax
    jnc .checkIfRandomNumberIsAvailable
.exit:
    ret