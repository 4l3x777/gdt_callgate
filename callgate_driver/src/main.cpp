#include <ntifs.h>
#include <string.h>
#include <Ntstrsafe.h>

#include "call_gate.h"
#include "callgate_procedure.h"

#define deviceName		L"\\Device\\CallGate"
#define symbolicName	L"\\DosDevices\\CallGate"

extern "C" void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	InstallCallGate(FALSE, NULL);
#if defined(DEBUG)
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Driver Unload!\n");
#endif
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{			
	pDriverObject->DriverUnload = DriverUnload;
#if defined(DEBUG)
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Driver Entry!\n");
#endif
	InstallCallGate(TRUE, (PVOID)call_gate_proc);
	return STATUS_SUCCESS;
}