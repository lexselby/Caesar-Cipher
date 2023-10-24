Title Final.asm
;// Program Description: This program uses a cipher similar to the Caesar Cipher to encrypt and decrypt phrases entered by the
;//                      user based on a key, also specified by the user.
;// Author: Alexa Selby
;// Creation Date: December 16, 2022


INCLUDE Irvine32.inc

;// PROTOS ---------------------------------------------------------------------

displayMenu PROTO, usrOption: PTR BYTE
pickAProc PROTO, populatedOption: BYTE
getPhrase PROTO, usrPhrase: PTR BYTE, strLen: PTR BYTE
UpperCase PROTO, origPhrase: PTR BYTE, phraseLen: BYTE
AlphaNum PROTO, alphaNumPhrase: PTR BYTE, tempPhrase: PTR BYTE, pLen: BYTE
checkIfEmpty PROTO, checkStr: PTR BYTE, isEmpty: PTR BYTE
copyString PROTO, str1: PTR BYTE, str2: PTR BYTE, strLen: BYTE
clearString PROTO, strn: PTR BYTE, sLen: BYTE
EncryptPhrase PROTO, eKey: PTR BYTE, eKeyLen: BYTE, ePhrase: PTR BYTE, ePhraseLen: BYTE             
DecryptPhrase PROTO, dKey: PTR BYTE, dKeyLen: BYTE, dPhrase: PTR BYTE, dPhraseLen: BYTE              
DisplayResult PROTO, rPhrase: PTR BYTE, rLen: BYTE
clearRegs PROTO
getKey PROTO, keyStr: PTR BYTE, maxKeyLength: PTR BYTE
WhichKey PROTO, choice: PTR BYTE, existingKey: PTR BYTE
WhichPhrase PROTO, choice: PTR BYTE, existingPhrase: PTR BYTE

;// -----------------------------------------------------------------------------

;// constants -------------------------------------------------------------------
maxStrLen = 150d
newLine EQU<0ah, 0dh>

;// -----------------------------------------------------------------------------

.data
;// variables -------------------------------------------------------------------

phraseChoice BYTE 0h
thePhrase BYTE maxStrLen DUP(0)
tempString BYTE maxStrLen DUP(0h)
realPhraseLen BYTE maxStrLen
userOption BYTE 0h
isStrEmpty BYTE 0h
keyOption BYTE 0h ;//user selects key option
theKey BYTE maxStrLen DUP (0) ;//key used
theKeyLen BYTE maxStrLen DUP (0)
errorMsg BYTE "You have selected an invalid option.", 
			   newline, "Please try again.", newline, 0h

;// ------------------------------------------------------------------------------

.code
main PROC

INVOKE clearRegs                        ;// clears registers
startHere:                              ;// menu display
	call clrscr                         ;// clearing screen
	INVOKE DisplayMenu, ADDR userOption

	;is option legal

	cmp userOption, 1d
	jb invalid
	cmp userOption, 4d
	jb driver
	cmp userOption, 4d
	je done

invalid:                        ;//display error if there is one
	push EDX
	mov EDX, OFFSET errorMsg
	call crlf
	call WriteString
	call WaitMsg
	jmp startHere

driver:                          ;//makes the menu function
	INVOKE pickAProc, userOption

jmp startHere

done:
exit
main ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;------------------------------------------------------------------------
;asks user if they want to use an old key or enter a new key 
;Recieves: address of the variable to store the users choice
;Returns: the key if a new one is entered
;-------------------------------------------------------------------------

WhichKey PROC, choice: PTR BYTE, existingKey: PTR BYTE
	.data
	existingKeyPrompt BYTE "Existing key has been found: " , 0

	whichKeyPrompt BYTE 'Enter a new key or keep the existing one?', 0Ah, 0Dh,
	'1. Enter New Key', 0Ah, 0Dh,
	'2. Use Existing Key', 0Ah, 0Dh,
	'Select an option (1 OR 2): ', 0

	WKerrorMsg BYTE "You have selected an invalid option.", 
			   newline, "Please try again.", newline, 0h

	.code

	call clrscr

	whichKeyLoop:
		Invoke checkIfEmpty, ADDR theKey, ADDR isStrEmpty ;// check if the key is not an empty string
		mov bl, isStrEmpty                                ;// move variable that indicates whether key is empty or not into bl 
		cmp bl, 1                                         ;// if 1, the key is not empty
		je newOrOld                                       ;// done
		cmp bl, 0                                         ;// if 0, the key is empty
		je newKey                                         ;// user must enter a key

	newKey:
		Invoke getKey, ADDR theKey, ADDR theKeyLen  ;// get the new key
		jmp QuitIt                                  ;// done

	newOrOld:
		mov EDX, OFFSET existingKeyPrompt ;// alerting user that there is an existing key
		call WriteString
		mov EDX, existingKey              ;// displaying the existing key
		call WriteString

		call crlf
		call crlf

		mov EDX, OFFSET whichKeyPrompt    ;// ask user if they want to use the existing key or make a new one
		call WriteString
		call ReadDec             ;// get user input
		mov esi, choice          ;// using esi to access byte ptr of keyChoice variable
		mov [esi], al            ;// moving the users option into the keyChoice variable

		cmp al, 1      ;// if choice one, new key
		je newKey
		cmp al, 2      ;// if choice two, done
		je QuitIt
		jmp invalid    ;// else, invalid option

	invalid:
		mov EDX, OFFSET WKerrorMsg ;// display error message for invalid input
		call crlf
		call WriteString
		call crlf
		call WaitMsg
		call clrscr
		jmp whichKeyLoop           ;// start loop again

	QuitIt: ;// done

	ret
WhichKey ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;----------------------------------------------------------------------------
;obtains a key from the user
;Recieves: the address of the string that will store the key
;          the address of the variable that will store the length of the key
;Returns:  the key entered by the user
;          the length of the key entered by the user
;----------------------------------------------------------------------------

getKey PROC, keyStr: PTR BYTE, maxKeyLength: PTR BYTE
.data
keyPrompt byte "Please enter a key up to 150 characters long", newLine,
				    "     ==>    ",0h

.code

	Invoke clearString, keyStr, 150d

	mov esi, maxKeyLength ;// using esi to access the byte ptr (OFFSET) of the realStrLen variable
	mov edi, keyStr       ;// using edi to access the byte ptr (OFFSET) of the "theString" variable

	push EDX
	mov EDX, OFFSET keyPrompt
	call crlf
	call WriteString           ;// prompt for phrase
	pop EDX
	mov EDX, edi               ;// moving the buffer ("theString" OFFSET) in to edx to store the users entered phrase
	mov EDX,  keyStr
	mov ECX, 150d               ;// max length of the phrase the user can enter  
	call ReadString            ;// take in phrase
	mov [esi], al              ;// update keyLen variable with the new string length

ret
getKey ENDP


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;------------------------------------------------------------------------
;displays the main menu options for the user and obtains the users option 
;choice
;Recieves: address of the variable storing the user option
;Returns:  populated user option variable
;-------------------------------------------------------------------------

displayMenu PROC, usrOption: PTR BYTE
	.data
	MainMenu BYTE "Main Menu", newline, 
	"1.  Enter a Phrase", newline, 
	"2.  Encrypt the Phrase", newline, 
	"3.  Decrypt a Phrase", newline,
	"4.  Exit" , newline, 
	"         Please make a selection ==>   ", 0h

	.code
	mov EDX, OFFSET MainMenu
	call WriteString
	call ReadDec             ;// get user input
	mov esi, usrOption       ;// using esi to access byte ptr of userOption variable
	mov [esi], al            ;// moving the users option into the userOption variable

	ret
displayMenu ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;------------------------------------------------------------------------
;calls the appropriate procedure depending on the users option choice
;Recieves: the variable storing the users option
;Returns:  none
;-------------------------------------------------------------------------

pickAProc PROC, populatedOption: BYTE
	cmp populatedOption, 2d ;//option 1
	jb option1

	cmp populatedOption, 3d ;//option 2
	jb option2

	cmp populatedOption, 4d ;//option 3
	jb option3

	jmp QuitIt              ;//option 4

	option1: ;// get phrase
		INVOKE getPhrase, OFFSET thePhrase, OFFSET realPhraseLen
		jmp QuitIt

	option2: ;// encrypt
		Invoke WhichPhrase, ADDR phraseChoice, ADDR thePhrase
		Invoke WhichKey, ADDR keyOption, ADDR theKey
		INVOKE EncryptPhrase, ADDR theKey, theKeyLen, ADDR thePhrase, realPhraseLen
		jmp QuitIt

	option3: ;// decrypt
		Invoke WhichPhrase, ADDR phraseChoice, ADDR thePhrase
		Invoke WhichKey, ADDR keyOption, ADDR theKey
		INVOKE DecryptPhrase, ADDR theKey, theKeyLen, ADDR thePhrase, realPhraseLen
		jmp QuitIt

	QuitIt: ;//option 4
	ret
pickAProc ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;------------------------------------------------------------------------
;asks user if they want to use an old phrase or enter a new phrase
;Recieves: address of the variable to store the users choice
;Returns: the phrase if a new one is entered
;-------------------------------------------------------------------------

WhichPhrase PROC, choice: PTR BYTE, existingPhrase: PTR BYTE
	.data
	existingPhrasePrompt BYTE "Existing phrase has been found: " , 0

	whichPhrasePrompt BYTE 'Enter a new phrase or keep the existing one?', 0Ah, 0Dh,
	'1. Enter New Phrase', 0Ah, 0Dh,
	'2. Use Existing Phrase', 0Ah, 0Dh,
	'Select an option (1 OR 2): ', 0

	WPerrorMsg BYTE "You have selected an invalid option.", 
			   newline, "Please try again.", newline, 0h

	.code

	call clrscr

	whichPhraseLoop:
		Invoke checkIfEmpty, ADDR thePhrase, ADDR isStrEmpty ;// check if the key is not an empty string
		mov bl, isStrEmpty                                   ;// move variable that indicates whether key is empty or not into bl 
		cmp bl, 1                                            ;// if 1, the key is not empty
		je newOrOld                                          ;// done
		cmp bl, 0                                            ;// if 0, the key is empty
		je newPhrase                                         ;// user must enter a key

	newPhrase:
		Invoke getPhrase, ADDR thePhrase, ADDR realPhraseLen  ;// get the new key
		jmp QuitIt                                            ;// done

	newOrOld:
		mov EDX, OFFSET existingPhrasePrompt ;// alerting user that there is an existing key
		call WriteString
		mov EDX, existingPhrase              ;// displaying the existing key
		call WriteString

		call crlf
		call crlf

		mov EDX, OFFSET whichPhrasePrompt ;// ask user if they want to use the existing key or make a new one
		call WriteString
		call ReadDec             ;// get user input
		mov esi, choice          ;// using esi to access byte ptr of keyChoice variable
		mov [esi], al            ;// moving the users option into the keyChoice variable

		cmp al, 1      ;// if choice one, new key
		je newPhrase
		cmp al, 2      ;// if choice two, done
		je QuitIt
		jmp invalid    ;// else, invalid option

	invalid:
		mov EDX, OFFSET WPerrorMsg ;// display error message for invalid input
		call crlf
		call WriteString
		call crlf
		call WaitMsg
		call clrscr
		jmp whichPhraseLoop           ;// start loop again

	QuitIt: ;// done

	ret
WhichPhrase ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;-----------------------------------------------------------------------------
;obtains a phrase from the user
;Recieves: address of the string that will hold the phrase entered by the user
;          address of the variable that will hold the length of the phrase
;Returns:  the phrase that was entered by the user
;          the length of the phrase
;-----------------------------------------------------------------------------

getPhrase PROC, usrPhrase: PTR BYTE, strLen: PTR BYTE
.data
	opt1Prompt byte "Please enter a phrase up to 150 characters long", newLine,
				    "     ==>    ",0h
	.code

	Invoke clearString, usrPhrase, 150d

	mov esi, strLen    ;// using esi to access the byte ptr (OFFSET) of the realStrLen variable
	mov edi, usrPhrase ;// using edi to access the byte ptr (OFFSET) of the "theString" variable

	push EDX
	mov EDX, OFFSET opt1Prompt
	call WriteString           ;// prompt for phrase
	pop EDX
	mov EDX, edi               ;// moving the buffer ("theString" OFFSET) in to edx to store the users entered phrase
	mov EDX,  usrPhrase
	mov cl, 150d            ;// max length of the phrase the user can enter  ("realStrLen")
	call ReadString            ;// take in phrase
	mov [esi], al              ;// update realStrLen variable with the new string length
	
	INVOKE UpperCase, ADDR thePhrase, realPhraseLen
	INVOKE AlphaNum, ADDR thePhrase, ADDR tempString, realPhraseLen
	ret
getPhrase ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;------------------------------------------------------------------------
;converts all lower case letters in a string to uppercase letters
;Recieves: address of the string being converted to upercase
;          the length of the string being converted to uppercase
;Returns:  string converted to uppercase
;-------------------------------------------------------------------------

UpperCase PROC, origPhrase: PTR BYTE, phraseLen: BYTE
	
	INVOKE ClearRegs

	mov edi, origPhrase  ;// using edi to access the "theString" variable OFFSET
	movzx ECX, phraseLen ;// setting the loop counter to the length of the phrase (realStrLen)

	LowCheckLoop:
	mov bl, [edi + edx]  ;// individual letters in "theString"

	cmp bl, 61h          ;// check for lowercase
	jb cont
	cmp bl, 7Ah
	ja cont
	push ebx
	sub bl, 20h          ;// converting to upper
	mov [edi + edx], bl  ;// storing
	pop ebx

	cont:
		inc edx          ;// next index
		loop LowCheckLoop
	
	ret
UpperCase ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;----------------------------------------------------------------------------
;removes all non-alphanumeric characters from a string
;Recieves: the string being converted to only contain alphanumeric characters
;          the address of a temporary string
;          the length of the string being converted
;Returns:  string converted to contain only alphanumeric characters
;-----------------------------------------------------------------------------

AlphaNum PROC, alphaNumPhrase: PTR BYTE, tempPhrase: PTR BYTE, pLen: BYTE
	
	INVOKE ClearRegs

	mov esi, alphaNumPhrase ;// using esi to access the byte ptr of "theString" (OFFSET)
	mov edi, tempPhrase     ;// using edi to access the byt ptr of "tempString" (OFFSET)
	movzx ECX, pLen         ;// setting the loop counter to "realStrLen"

	opt3Loop:
	mov bl, [esi] ;// index of "theString"
	mov al, [edi] ;// index of "tempString"

	cmp bl, 30h   ;// is the character below ascii 30h (number 0)
	jb cont       ;// if yes, ignore the character
	cmp bl, 39h   ;// is the character above ascii 39h (number 9)
	ja upper      ;// if yes, check if the character is an upper case letter

	mov [edi], bl ;// if no for both, move the character into the tempString
	inc edi
	jmp cont	  ;// continue

	upper:
		cmp bl, 41h   ;// is the character below ascii 41h (letter A)
		jb cont       ;// if yes, ignore the character
		cmp bl, 5Ah   ;// is the character above ascii 5A (letter Z)
		ja lowerCase  ;// if yes, then check if the character is a lower case letter 

		mov [edi], bl ;// if no for both, move the character into the tempString
		inc edi       ;// next index of tempString
		jmp cont      ;// if no for both, continue

	lowerCase:
		cmp bl, 61h   ;// is the character below ascii 61h (letter a)
		jb cont       ;// if yes, then ignore the character
		cmp bl, 7Ah   ;// is the character above ascii 7Ah (letter z)
		ja cont       ;// if yes, then ignore the character

		mov [edi], bl ;// if no for both, move the character into the tempString
		inc edi       ;// next index of tempString
		jmp cont      ;// if no for both, continue

	cont:
		inc esi       ;// next index of "theString"
		loop opt3Loop ;// go back to the beginning of the loop


	INVOKE clearString, alphaNumPhrase, pLen            ;// clearing "theString"
	INVOKE copyString, alphaNumPhrase, tempPhrase, pLen ;// copying "tempString" into "theString"
	INVOKE clearString, tempPhrase, pLen                ;// clearing "tempString"
	jmp quit                                            ;// done

	quit:
	ret
AlphaNum ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;----------------------------------------------------------------------------------
;checks to see if a string is empty or not
;Recieves: address of the string being checked
;          address of a variable that indicates whether the string is empty or not
;Returns:  the value of the variable that indicates whether the string is empty
;----------------------------------------------------------------------------------

checkIfEmpty PROC, checkStr: PTR BYTE, isEmpty: PTR BYTE
.data
emptyStringError BYTE "OOPS! The string is empty or has not been entered.", newline, 
						"Choose option 1 to enter a string.", newline, 0h

.code

	push esi ;// preserving esi
	push edi ;// preserving edi

	mov esi, checkStr ;// accessing the string being checked
	mov edi, isEmpty  ;// eccessing the isEmpty variable

	mov bl, [esi]     ;// moving the first character in the string into bl

	cmp bl, 0h   ;// if bl is equal to 0h
	je empty     ;// the string is empty
	cmp bl, 1h   ;// else, the string is not empty
	jae notEmpty ;// proceed accordingly

	empty:
		mov [edi], bl ;// adjust the variable
		jmp quit      ;// done

	notEmpty:
		mov bl, 1h    ;// moving 1 into bl
		mov [edi], bl ;// using bl to adjust the variable
		jmp quit      ;// done

	quit:

	pop edi ;// restoring edi
	pop esi ;// restoring esi

	ret
checkIfEmpty ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;-----------------------------------------------------------------------------
;copys the contents of one string into another string
;Recieves: address of the string being copied
;          address of a temporary string
;          length of the string being copied
;Returns:  copied string
;------------------------------------------------------------------------------

copyString PROC, str1: PTR BYTE, str2: PTR BYTE, strLen: BYTE

	INVOKE ClearRegs

	mov esi, str1     ;// using esi to access byte ptr of "theString" (OFFSET)
	mov edi, str2     ;// using edi to access byte ptr of "tempString" (OFFSET)
	movzx ecx, strLen ;// setting the loop count to "realStrLen"

	copyingString:
		mov bl, [edi] ;// moving the current index of "tempString" into bl
		mov [esi], bl ;// moving the character in the current index of "tempString" into "theString"
		inc edi       ;// next index of "tempString"
		inc esi       ;// next index of "theString"
	loop copyingString

	ret
copyString ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;------------------------------------------------------------------------
;clears a string
;Recieves: address of the string to be cleared
;          length of the string to be cleared
;Returns:  cleared string 
;-------------------------------------------------------------------------

clearString PROC, strn: PTR BYTE, sLen: BYTE

	INVOKE ClearRegs

	mov esi, strn     ;// using esi to access byte ptr of "theString"
	movzx ecx, sLen   ;// setting the loop counter to the "realStrLen"

	clearingString:
		mov [esi], bl ;// clearing the current indexed character of "theString"
		inc esi       ;// next index
	loop clearingString              

	ret
clearString ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;---------------------------------------------------------------------------
;encrypts a phrase
;Recieves: address of the key
;          length of the key
;          address of the phrase
;          length of the phrase
;Returns:  encrypted phrase
;---------------------------------------------------------------------------

EncryptPhrase PROC, eKey: PTR BYTE, eKeyLen: BYTE, ePhrase: PTR BYTE, ePhraseLen: BYTE
.data
	EncryptionMsg BYTE "After encryption, ", 0h

.code

Invoke clearRegs       ;// clearing registers

mov ESI, ePhrase       ;// accessing the phrase
mov EDI, eKey          ;// accessing the key

movzx ECX, ePhraseLen  ;// setting the loop counter to the length of the phrase being encrypted

jmp encrypt         ;// begin encryption

encrypt:
	mov EAX, 0      ;// clear before every loop for div remainder use
	cmp dl, eKeyLen ;// using dl as a counter to signal the end of the key
	je restartKey   ;// go back to beginning of key 

	cmp BYTE PTR [ESI], 'A' ;// if character is above the ascii val for 'A'
	jge letterEncryption    ;// the encryption should be adjusted for a letter
	cmp BYTE PTR [ESI], '9' ;// if character is below the ascii val for '9'
	jle numberEncryption    ;// the encryption should be adjusted for a number

restartKey:
	mov EDI, eKey ;// go to beginning of key
	mov dl, 0     ;// reset the key length counter
	jmp encrypt   ;// resume encryption

letterEncryption:
	mov	AL, [EDI] ;// move key into al
	mov BL, 1AH   ;// move 26 into bl
	div BL        ;// divide key using 26
	sub [ESI], AH ;// subtract ah from current character

	cmp BYTE PTR [ESI], 'Z' ;// if less than ascii for 'Z'
	jle shiftForUpper       ;// shift appropriately
	sub BYTE PTR [ESI], 1Ah ;// else, subtract 26
	jge continue            ;// continue

shiftForUpper:
	cmp BYTE PTR [ESI], 'A' ;// if greater than ascii for 'A'
	jge continue            ;// continue
	add BYTE PTR [ESI], 1Ah ;// else, add 26 
	jmp continue            ;// continue

numberEncryption:
	mov	AL, [EDI]          ;// move key into al
	mov BL, 10d            ;// move 10 into bl
	div BL                 ;// divide key using 10
	sub BYTE PTR [ESI], AH ;// subtract ah from current character

	cmp BYTE PTR [ESI], '9' ;// if less than '9'
	jle shiftForNum         ;// shift appropriately
	sub BYTE PTR [ESI], AH  ;// else, subtract 10 
	jge continue            ;// continue

shiftForNum:
	cmp BYTE PTR [ESI], '0' ;// if greater than '0'
	jge continue            ;// continue
	add BYTE PTR [ESI], 10d ;// else, add 10
	jmp continue            ;// continue

continue:
	inc ESI  ;// move to next character in string
	inc EDI  ;// move to next chracter in key
	inc dl   ;// increase key length counter

loop encrypt 

call clrscr  ;// clear the screen
 
mov EDX, OFFSET EncryptionMsg
call WriteString                          ;// printing the encryption message

INVOKE DisplayResult, ePhrase, ePhraseLen ;// printing the encrpted phrase
	ret
EncryptPhrase ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;---------------------------------------------------------------------------
;decrypts a phrase
;Recieves: address of the key
;          length of the key
;          address of the phrase
;          length of the phrase
;Returns:  decrypted phrase
;---------------------------------------------------------------------------

DecryptPhrase PROC, dKey: PTR BYTE, dKeyLen: BYTE, dPhrase: PTR BYTE, dPhraseLen: BYTE  
.data
	DecryptionMsg BYTE "After decryption, ", 0h

.code

Invoke clearRegs ;// clearing registers

mov ESI, dPhrase ;// accessing the phrase
mov EDI, dKey    ;// accessing the key

movzx ECX, dPhraseLen ;// using the phrase length as the loop counter

jmp decrypt           ;// begin decryption

decrypt:
	mov EAX, 0       ;// clear before every loop for div remainder
	cmp dl, dKeyLen  ;// if end of key
	je restartKey    ;// move back to beginning of key

	cmp BYTE PTR [ESI], 'A' ;// if character is above the ascii val for 'A'
	jge letterDecryption    ;// the decryption should be adjusted for a letter
	cmp BYTE PTR [ESI], '9' ;// if character is below the ascii val for '9'
	jle numberDecryption    ;// the decryption should be adjusted for a number

restartKey:
	mov EDI, dKey ;// moving back to the beginning of the key
	mov dl, 0     ;// resetting the key position counter
	jmp decrypt   ;// resuming encryption

letterDecryption:
	mov	AL, [EDI] ;// move key into al
	mov BL, 1AH   ;// move 26 into bl
	div BL        ;// divide key using 26
	add [ESI], AH ;// add ah to current char in esi 

	cmp BYTE PTR [ESI], 'Z' ;// if less than or equal to 'Z'
	jle shiftForUpper       ;// shift appropriately
	sub BYTE PTR [ESI], 1Ah ;// add 26 
	jge continue            ;// continue

shiftForUpper:
	cmp BYTE PTR [ESI], 'Z' ;// if less than or equal to 'Z'
	jle continue            ;// continue
	add BYTE PTR [ESI], 1Ah ;// else, add 26 
	jmp continue            ;// continue

numberDecryption:
	mov	AL, [EDI]          ;// move key into al
	mov BL, 10d            ;// move 10 into bl
	div BL                 ;// divide key using 10
	add BYTE PTR [ESI], AH ;// add letter to value in ah

	cmp BYTE PTR [ESI], '9' ;// if less than or equa to '9'
	jle shiftForNum         ;// shift appropriately
	sub BYTE PTR [ESI], 10d ;// subtract 10 
	jge continue            ;// continue

shiftForNum:
	cmp BYTE PTR [ESI], '9' ;// if less than or equal to '0'
	jle continue            ;// continue '0'
	add BYTE PTR [ESI], 10d ;// else, add 10
	jmp continue            ;// continue

continue:
	inc ESI  ;// next character in string
	inc EDI  ;// next chracter in key
	inc dl   ;// increase key position counter

loop decrypt 

call clrscr                   ;// clear the screen
mov EDX, OFFSET DecryptionMsg ;// print the decryption message
call WriteString              ;// printing

INVOKE DisplayResult, dPhrase, dPhraseLen ;// printing the decrypted phrase

	ret
DecryptPhrase ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;---------------------------------------------------------------------------
;prints the resulting phrase of either encryption or decryption
;Recieves: address of the encrypted or decrypted phrase
;Returns:  none
;---------------------------------------------------------------------------

DisplayResult PROC, rPhrase: PTR BYTE, rLen: BYTE
	.data
	DisplayPrompt BYTE "the phrase is now: ",0h

	.code

	mov EDX, OFFSET DisplayPrompt
	call WriteString
	call crlf

	Invoke clearRegs

	mov ESI, rPhrase ;// accessing the phrase
	movzx ECX, rLen  ;// using the length of the phrase as the loop counter

	printing:
		cmp bl, 7     ;// after 7 characters have been printed 
		je printSpace ;// print a space

		mov al, [ESI]  ;// moving the current character of the phrase into al for printing 
		call WriteChar ;// printing the character
		jmp continue   ;// continue

		printSpace:
			push eax       ;// saving spot in the phrase
			mov al, ' '    ;// moving a blank space into al
			call WriteChar ;// printing the blank space
			pop eax        ;// restoring spot in the phrase
			mov bl, 0      ;// reseting the character counter
			jmp printing   ;// go to beginning of loop
			

		continue:
			inc ESI ;// next index of the phrase
			inc bl  ;// adding 1 to the character counter

	loop printing

	call crlf    ;// newline
	call crlf    ;// newline
	call WaitMsg ;// giving user time to read the printed phrase
	
	ret
DisplayResult ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;------------------------------------------------------------------------
;clears all registers
;Recieves: all registers
;Returns:  cleared registers
;-------------------------------------------------------------------------

clearRegs PROC 
	
	mov EAX, 0h
	mov EBX, 0h
	mov ECX, 0h
	mov EDX, 0h
	mov ESI, 0h
	mov EDI, 0h

	ret 
clearRegs ENDP
END main