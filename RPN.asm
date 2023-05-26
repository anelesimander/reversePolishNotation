data segment
    promptMsg db "unesi izraz (odvoji clanove separatorom):$"
    msg db 10,13,"Rezultat: $"
    inputBuffer DB 20 DUP('$') ;unos moze da bude dugacak zbog separatora i znakova
    resultBuffer DW 6 DUP('$') ;makximalan broj hex cifara koje mogu da se storuju u registar je 4 (FFFF),samim tim najveci broj koji moze da se dobije je 6 decimalnih cifa
data ends
    
stack_seg segment stack
        db 128 dup (?)
stack_seg       ENDS

code segment
ASSUME CS:code, DS:data, SS:stack_seg 
hexToDec proc
;procedura da rezultat koji je u hexadecimalnom zapisu konveruje u decimalni zapis
    MOV CX,0Ah ;ucitava delilac za konverziju iz hex u dec zapis
    LEA SI,resultBuffer ;ucitava buffer rezutata
hexToDecLoop:
    MOV DX,0H
    DIV CX; pre pozivanja hexToDec Ax registar je pop-ovan sa stecka i ovim se izvrsilo deljenje DX:AX sa BX (PROVERI)
    MOV [SI],DL ;smesta ostatak pri deljenju sa 10
    INC SI
    CMP AX,CX ;kada  vrednost u AX bude manja od deset upisujem je na poslednje mesto buffera
    JAE hexToDecLoop  
    MOV [SI],AL
    RET 4
hexToDec endp
print proc
;procedura za stampanje tog decimalnog broja
    PUSH AX
    PUSH BX
    PUSH CX
    PUSH DX
    PUSH SI

    XOR AX, AX
printResult:
    MOV AX, [SI] ;u AX ucitavam prvu vrednost za ispisivanje na ekran (ono sto se ispisuje ce se nalaziti samo u AL delu)
    MOV DL, AL   
    ADD DL, '0' ;konverzija u ASCII
    MOV AH, 02h 
    INT 21h
    ;kako je u hexToDec rezultat pisan od pozadi tj od poslednje do prve cifre ispisivacu u suprotnom smeru
    ;SI je ostao na zadnjoj poziciji gde je upisana zadnja cifra i od nje krecem i smanjujem sve dok ne prodjem pocetak buffera tj da SI bude manji od offset resultBuffer 
    DEC SI
    CMP SI,offset resultBuffer 
    JGE printResult

    POP SI
    POP DX
    POP CX
    POP BX
    POP AX

    RET 4
print endp 

start:
    MOV AX,data
    MOV DS, AX
    ;ispisivanje pocetne poruke za trazenje korisnickog unosa
    MOV AH, 09h
    LEA DX, promptMsg 
    INT 21h
    ;load inputBuffer-a 
    MOV AH, 0Ah
    LEA DX, inputBuffer
    INT 21h
    ;postavljam SI na pocetak adrese inputBuffer vrednosti
    MOV SI, OFFSET inputBuffer 
    ADD SI, 2 ;preskakanje duzine unosa 
    MOV CX,SI;CX koristim da mi oznaci prvu cifru svakog broja za slucajeve gde je visecifreni broj unet kao clan 
processLoop:
    MOV AL, [SI]
    CMP al,0dh; ako je enter nastavlja dalje sa programom ka konverziji i ispisu
    je continue
     
    CMP AL,20h;ako je separator
    JE addSep
    
    ;ako nije cifra onda je operator
    CMP AL, '0'
    JB isOperator
    CMP AL, '9'
    JA isOperator
    
    CMP SI,CX ;ako je prva cifra broja
    JE firstDigit   
    
    JMP input ;onda je neka od narednih cifara u unosu (ne prva cifra)
firstDigit:
    ;prvo se konvertuje iz ASCII i samo se push-uje na stack
    SUB AL, '0' 
    XOR AH,AH
    PUSH AX 
    JMP nextChar
input:
    ;prvo konverzija iz ASCII
    SUB AL, '0'
    XOR AH,AH
    
    POP BX;skidam predhodnu cifru sa stack-a jer njoj treba da uvecam deseticu
    PUSH AX ;pushujem novo-unetu cifru na stack jer za mnozenje mi treba AX registar
    MOV AX,BX
    MOV BX,10
    MUL BX;vrednoost mnozenja ostaje u AX registru
    
    POP BX;skidam sa stacka novo-unetu cifru i sabiram je
    ;pr. unos 243:
    ;-prvo se unosi dvojka
    ;-kada dodje 4 na unos treba da se uveca desetica predhodnoj cifri 20+4 i 24 se smesta nazad na stack
    ;-kada dodje 3 na unos treba broju sa stacka uvecati deseticu pa imamo 240+3 i onda to smestam na stack
    ;brojevi na stacku ce biti u hex notaciji
    ADD BX,AX
    PUSH BX
    JMP nextChar
addSep:
    ;postavlja vrednost CX na adresu prve cifre nareednog broja u unosu
    INC SI
    MOV CX,SI
    JMP processLoop ;nastavlja dalje sa unosom
isOperator:
    CMP AL, '+'
    JE addOperation
    CMP AL, '-'
    JE subOperation
    CMP AL, '*'
    JE mulOperation
    CMP AL, '/'
    JE divOperation
nextChar:
    ;povecavanje adrese da bi se obradio naredni karakter buffer
    INC SI
    LOOP processLoop

continue: 
    ;nakon obrade, za konverziju rezultata i ispisivanje na ekran 
    MOV AH, 09h 
    LEA DX, msg
    INT 21h 

    POP AX
    
    CALL hexToDec
    CALL print
    ;obustavljanje programa
    MOV AH, 4Ch
    INT 21h
addOperation:
    POP BX
    POP AX

    ADD AX, BX
    PUSH AX

    JMP nextChar
subOperation:
    POP BX
    POP AX

    SUB AX, BX
    PUSH AX

    JMP nextChar
mulOperation:
    POP BX
    POP AX

    MUL BX
    PUSH AX

    JMP nextChar
divOperation:
    POP BX
    POP AX

    DIV BX
    PUSH AX

    JMP nextChar
code ends
end start