include irvine32.inc

.data
    inputString BYTE 20 DUP (?),0
    resultString BYTE 20 DUP (?),0
    decrpyt BYTE 20 DUP (?),0
    reenter BYTE 20 DUP(?),0
    shiftValue DWORD ?
    promptInput BYTE "Enter a string to encrypt: ",0
    promptShift BYTE "Enter shift value: ",0
    encryptedMessage BYTE "Encrypted string: ",0
    decryptedMessage BYTE "Decrypted string: ",0
    promptreenter BYTE "Re-enter Password: ",0
    prompt1 BYTE "Validation Successful",0
    prompt2 BYTE "Unsuccessful Validation. Re enter password again",0
    prompt3 BYTE "Do you want to make another password? Type 1 if yes: ",0
    prompt4 BYTE "Invalid Length. Make the password at least 6 characters.",0
    spaceErrorMsg BYTE "Password cannot contain spaces. Please try again.",0
    noUppercaseMsg BYTE "Password must contain at least one uppercase letter.",0
    noLowercaseMsg BYTE "Password must contain at least one lowercase letter.",0
    noNumberMsg BYTE "Password must contain at least one number.",0

.code

main PROC

start:
    ;take pw input
    mov edx, OFFSET promptInput
    call WriteString
    mov ecx, 20
    lea edx, inputString
    call ReadString
    cmp eax, 6            ;to check length validity
    jge LengthValid
    mov edx, OFFSET prompt4
    call WriteString
    call crlf
    jmp start

LengthValid:               ;to check all kinds of validations
    call CheckForSpaces    ;checks if there is any space in the pw
    cmp eax, 1
    je SpaceError
    call CheckForUppercase  ;checks if there is no uppercase in the pw
    cmp eax, 0
    je NoUppercaseError
    call CheckForLowercase  ;checks if there is no lowercase in the pw
    cmp eax, 0
    je NoLowercaseError
    call CheckForNumbers    ;checks if there are no numbers in the pw
    cmp eax, 0
    je NoNumberError

    ;encrypts inputted pw string
    mov esi, OFFSET inputString
    mov edi, OFFSET resultString
    mov ecx, 3
    call CaesarEncrypt

    ;prints encrypted pw string
    mov edx, OFFSET encryptedMessage
    call WriteString
    mov edx, OFFSET resultString
    call WriteString
    call Crlf

    ;user re enters pw for checking
enteragain:
    mov edx, OFFSET promptreenter
    call WriteString
    mov ecx, 20
    lea edx, reenter
    call ReadString

    ;encrypts re entered pw as well
    mov esi, OFFSET reenter
    mov edi, OFFSET decrpyt
    mov ecx, 3
    call CaesarEncrypt

    ;compares entered pw encryption and re entered pw encryption
    INVOKE Str_compare, ADDR resultString, ADDR decrpyt
    je equal1               ;successful validation
    mov edx, OFFSET prompt2
    call WriteString
    call crlf
    jmp enteragain           ;asks to re enter until user enters correctly

equal1:
    mov edx, OFFSET prompt1
    call WriteString
    call crlf

    ;asks for using the program again
    mov edx, OFFSET prompt3
    call WriteString
    call crlf
    call readint
    cmp al, 1
    je start
    exit

SpaceError:
    mov edx, OFFSET spaceErrorMsg
    call WriteString
    call crlf
    jmp start

NoUppercaseError:
    mov edx, OFFSET noUppercaseMsg
    call WriteString
    call crlf
    jmp start

NoLowercaseError:
    mov edx, OFFSET noLowercaseMsg
    call WriteString
    call crlf
    jmp start

NoNumberError:
    mov edx, OFFSET noNumberMsg
    call WriteString
    call crlf
    jmp start

main ENDP

CheckForSpaces PROC
    mov esi, OFFSET inputString
CheckLoop:
    mov al, [esi]
    cmp al, 0      ;compares for null terminator
    je NoSpaces
    cmp al, ' '
    je SpaceFound
    inc esi
    jmp CheckLoop
SpaceFound:
    mov eax, 1
    ret
NoSpaces:
    xor eax, eax
    ret
CheckForSpaces ENDP

CheckForUppercase PROC
    mov esi, OFFSET inputString
CheckUpperLoop:
    mov al, [esi]
    cmp al, 0        ;compares for null terminator
    je NoUppercase
    cmp al, 'A'
    jl ContinueUpper
    cmp al, 'Z'
    jg ContinueUpper
UppercaseFound:
    mov eax, 1
    ret
ContinueUpper:
    inc esi
    jmp CheckUpperLoop
NoUppercase:
    xor eax, eax
    ret
CheckForUppercase ENDP

CheckForLowercase PROC
    mov esi, OFFSET inputString
CheckLowerLoop:
    mov al, [esi]
    cmp al, 0           ;compares for null terminator
    je NoLowercase
    cmp al, 'a'
    jl ContinueLower
    cmp al, 'z'
    jg ContinueLower
LowercaseFound:
    mov eax, 1
    ret
ContinueLower:
    inc esi
    jmp CheckLowerLoop
NoLowercase:
    xor eax, eax
    ret
CheckForLowercase ENDP

CheckForNumbers PROC
    mov esi, OFFSET inputString
CheckNumberLoop:
    mov al, [esi]
    cmp al, 0          ;compares for null terminator
    je NoNumber
    cmp al, '0'
    jl ContinueNumber
    cmp al, '9'
    jg ContinueNumber
NumberFound:
    mov eax, 1
    ret
ContinueNumber:
    inc esi
    jmp CheckNumberLoop
NoNumber:
    xor eax, eax
    ret
CheckForNumbers ENDP

CaesarEncrypt PROC
    movzx eax, byte ptr [esi]
    xor edx, edx
EncryptLoop:
    cmp al, 0
    je Done
    cmp al, '0'
    jl NotAlpha
    cmp al, '9'
    jle Numbers
    cmp al, 'A'
    jl NotAlpha
    cmp al, 'Z'
    jle Uppercase
    cmp al, 'a'
    jl NotAlpha
    cmp al, 'z'
    jg NotAlpha
Lowercase:
    sub al, 'a'
    add al, cl
    mov ebx, 26
    xor edx, edx
    idiv ebx
    mov al, dl
    add al, 'a'
    jmp StoreChar
Uppercase:
    sub al, 'A'
    add al, cl
    mov ebx, 26
    xor edx, edx
    idiv ebx
    mov al, dl
    add al, 'A'
    jmp StoreChar
Numbers:
    sub al, '0'
    add al, cl
    mov ebx, 10
    xor edx, edx
    idiv ebx
    mov al, dl
    add al, '0'
    jmp StoreChar
NotAlpha:
    mov al, byte ptr [esi]
StoreChar:
    mov byte ptr [edi], al
    inc esi
    inc edi
    movzx eax, byte ptr [esi]
    jmp EncryptLoop
Done:
    mov byte ptr [edi], 0
    ret
CaesarEncrypt ENDP

END main