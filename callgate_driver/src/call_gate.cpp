#include <ntifs.h>
#include <string.h>
#include <Ntstrsafe.h>

#include "call_gate.h"


__declspec(naked) void turn_off_write_privilege()
{
	__asm
	{
		cli
		push eax
		mov eax, cr0
		and eax, 0xFFFeFFFF
		mov cr0, eax
		pop eax
		sti
		ret
	}
}

__declspec(naked) void turn_on_write_privilege()
{
	__asm
	{
		cli
		push eax
		mov eax, cr0
		or ebx, 0x00010000
		mov cr0, eax
		pop eax
		sti
		ret
	}
}

GDTR_reg get_GDTR()
{
	GDTR_reg gdtr_reg = { 0 };
	__asm sgdt gdtr_reg
	// size always store with one less of its true size
	gdtr_reg.size += 1;

	return gdtr_reg;
}

//	Adds a new memory descriptor at the end to the GDT 
//	return selector of new descriptor.
USHORT set_callgate_descriptor(ULONGLONG  memory_descriptor)
{
	USHORT selector, gdt_index;
	char* gdt_table;
	GDTR_reg gdtr_reg;

	selector = 0;
	gdtr_reg = get_GDTR();

	gdt_index = GDT_index;
	// a maximum of (8192 - 1[first zero descriptor]) entries may be specified.
	if (gdt_index <= GDT_max_index)
	{
		gdt_table = (char*)gdtr_reg.address;

		turn_off_write_privilege();
		memcpy(&gdt_table[gdt_index * GDT_descriptor_size], &memory_descriptor, GDT_descriptor_size);
		turn_on_write_privilege();

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
		selector |= 3;			// set TI = 0, RPL to 3	=> allow access to this selector from ring-3
	}
	return selector;
}

//	Remove callgate descriptor from GDT.
void remove_callgate_descriptor()
{
	USHORT gdt_index;
	char* gdt_table;
	GDTR_reg gdtr_reg;

	gdtr_reg = get_GDTR();

	gdt_index = GDT_index;

	// a maximum of (8192 - 1[first zero descriptor]) entries may be specified.
	if (gdt_index <= GDT_max_index)
	{
		gdt_table = (char*)gdtr_reg.address;

		turn_off_write_privilege();
		memset(&gdt_table[gdt_index * GDT_descriptor_size], 0, GDT_descriptor_size);
		turn_on_write_privilege();
	}
}

CALL_GATE_DESCRIPTOR build_call_gate_descriptor(PVOID entryPoint) {
	ULONG address = (ULONG)entryPoint;
	CALL_GATE_DESCRIPTOR callGateDescr = { 0 };

	callGateDescr.offset_00_15 = 0x0000ffff & address;				//Offset(specifies the procedure’s entry - point within its code - segment)
	address = address >> 16;
	callGateDescr.offset_16_31 = 0x0000ffff & address;				//Offset (specifies the procedure’s entry-point within its code-segment)
	callGateDescr.selector = 0x8;									//Code-selector (specifies memory-segment containing procedure code)
	callGateDescr.argCount = 0x2;									//Parameter count (specifies how many parameter-values will be copied)								
	callGateDescr.type = 0xC;										//Gate - Type('0x4' means a 16 - bit call - gate, '0xC' means a 32 - bit call - gate)
	callGateDescr.dpl = 0x3;										//DPL = Descriptor Privilege Level (ring-0, ring-1, ring-2, ring-3) 
	callGateDescr.pFlag = 0x1;										//P = present (1 = yes, 0 = no)

	//								 P|DLP|S  type  zeros  params
	//callGateDescr(flags only) =	   1110	  1100  0000   0001b   <=> 0xec02

	return callGateDescr;
}

void InstallCallGate(char Install, PVOID entryPoint)
{
	CCHAR i;
	USHORT selector;
	PETHREAD Thread;
	KAFFINITY Affinity;
	ULONGLONG descr;
	CALL_GATE_DESCRIPTOR call_gate_descriptor;
	pKeSetAffinityThread KeSetAffinityThread;

	UNICODE_STRING Name = RTL_CONSTANT_STRING(L"KeSetAffinityThread");
	KeSetAffinityThread = (pKeSetAffinityThread)MmGetSystemRoutineAddress(&Name);

	call_gate_descriptor = build_call_gate_descriptor(entryPoint);
	memcpy(&descr, &call_gate_descriptor, GDT_descriptor_size);

	Thread = (PETHREAD)__readfsdword(KTHREAD_OFFSET);	// fs:[KTHREAD_OFFSET]
	Affinity = KeSetAffinityThread(Thread, 1);

	if (Install)
	{
		for (i = 0; i < KeNumberProcessors; i++)
		{
			KeSetAffinityThread(Thread, 1 << i);
			selector = set_callgate_descriptor(descr);
#if defined(DEBUG)
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CallGate inserted! use selector: 0x%02x\n", selector);
#endif
		}
	}
	else
	{
		for (i = 0; i < KeNumberProcessors; i++)
		{
			KeSetAffinityThread(Thread, 1 << i);
			remove_callgate_descriptor();
#if defined(DEBUG)
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CallGate removed!\n");
#endif			
		}
	}

	KeSetAffinityThread(Thread, Affinity);
}