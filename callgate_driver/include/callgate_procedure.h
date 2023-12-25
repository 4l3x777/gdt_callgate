#pragma once
#include <ntifs.h>
#include <string.h>
#include <Ntstrsafe.h>

//WIN 7 X86 6.1.7601.24545 KERNEL OFFSETS
#define KTHREAD_OFFSET    0x124    // nt!_KPCR.PcrbData.CurrentThread
#define EPROCESS_OFFSET   0x050    // nt!_KTHREAD.ApcState.Process
#define PID_OFFSET        0x0B4    // nt!_EPROCESS.UniqueProcessId
#define FLINK_OFFSET      0x0B8    // nt!_EPROCESS.ActiveProcessLinks.Flink
#define TOKEN_OFFSET      0x0F8    // nt!_EPROCESS.Token

// INPUT STACK PARAMS:
//  SOURCE_PID		[esp+12]
//	TARGET_PID		[esp+8]
//	CS SELECTOR		[esp+4]
//	RETADDR			[esp]
ULONG_PTR call_gate_proc();
