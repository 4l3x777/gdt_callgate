#pragma once
#include <ntifs.h>
#include <string.h>
#include <Ntstrsafe.h>

// user-defined param
#define GDT_index 0x15

// GDT params
#define GDT_max_index 8191
#define GDT_descriptor_size 8

//WIN 7 X86 6.1.7601.24545 KERNEL OFFSETS
#define KTHREAD_OFFSET    0x124    // nt!_KPCR.PcrbData.CurrentThread

#pragma pack(1)
typedef struct _CALL_GATE_DESCRIPTOR
{
	unsigned short offset_00_15;
	unsigned short selector;
	unsigned short argCount : 5;
	unsigned short zeroes : 3;
	unsigned short type : 4;
	unsigned short sFlag : 1;
	unsigned short dpl : 2;
	unsigned short pFlag : 1;
	unsigned short offset_16_31;
} CALL_GATE_DESCRIPTOR, * PCALL_GATE_DESCRIPTOR;
#pragma pack()

#pragma pack(push,1)
typedef struct _GDTR_reg
{
	USHORT size;
	DWORD address;	
}GDTR_reg;
#pragma pack(pop)

typedef KAFFINITY(*pKeSetAffinityThread)(PETHREAD, KAFFINITY);

void InstallCallGate(char Install, PVOID entryPoint);