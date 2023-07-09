#include <fltKernel.h>
#include <ntifs.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include <bcrypt.h>




#define SystemProcessesAndThreadsInformation 5

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG         WaitTime;
	PVOID         StartAddress;
	CLIENT_ID     ClientId;
	ULONG64       Priority;
	LONG          BasePriority;
	ULONG         ContextSwitches;
	ULONG         ThreadState;
	ULONG         WaitReason;
	ULONG         PadPadAlignment;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;


typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG                     NextEntryOffset;
	ULONG                     NumberOfThreads;
	LARGE_INTEGER             WorkingSetPrivateSize;
	ULONG                     HardFaultCount;
	ULONG                     NumberOfThreadsHighWatermark;
	ULONGLONG                 CycleTime;
	LARGE_INTEGER             CreateTime;
	LARGE_INTEGER             UserTime;
	LARGE_INTEGER             KernelTime;
	UNICODE_STRING            ImageName;
	ULONG64                   BasePriority;
	HANDLE                    UniqueProcessId;
	HANDLE                    InheritedFromUniqueProcessId;
	ULONG                     HandleCount;
	ULONG                     SessionId;
	ULONG_PTR                 UniqueProcessKey;
	SIZE_T                    PeakVirtualSize;
	SIZE_T                    VirtualSize;
	ULONG                     PageFaultCount;
	SIZE_T                    PeakWorkingSetSize;
	SIZE_T                    WorkingSetSize;
	SIZE_T                    QuotaPeakPagedPoolUsage;
	SIZE_T                    QuotaPagedPoolUsage;
	SIZE_T                    QuotaPeakNonPagedPoolUsage;
	SIZE_T                    QuotaNonPagedPoolUsage;
	SIZE_T                    PagefileUsage;
	SIZE_T                    PeakPagefileUsage;
	SIZE_T                    PrivatePageCount;
	LARGE_INTEGER             ReadOperationCount;
	LARGE_INTEGER             WriteOperationCount;
	LARGE_INTEGER             OtherOperationCount;
	LARGE_INTEGER             ReadTransferCount;
	LARGE_INTEGER             WriteTransferCount;
	LARGE_INTEGER             OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
}SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

EXTERN_C_START
NTSTATUS ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
EXTERN_C_END

ULONG PsFindProcessByName();
VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj);


typedef NTSTATUS(*PfnZwQueryInformationProcess) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

PfnZwQueryInformationProcess ZwQueryInformationProcess;
NTSTATUS InitGloableFunction();