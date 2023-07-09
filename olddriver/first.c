#include "ctfsys.h"


#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)


typedef NTSTATUS(*PfnZwQueryInformationProcess) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

PfnZwQueryInformationProcess ZwQueryInformationProcess;



ULONG ctfhide_pid = 0;
HANDLE FileHandle;
IO_STATUS_BLOCK IoStatusBlock;




//内核中的sleep()实现
#define DELAY_ONE_MICROSECOND	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND * 1000)

VOID KeSleep(IN LONG msec) {
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}



ULONG PsFindProcessByName() {
	PWCHAR ProcessName = L"ctfhide.exe";
	//PWCHAR ProcessName = L"cmd.exe";
	ULONG size = 0;
	PVOID buffer;
	PSYSTEM_PROCESS_INFORMATION	procInfo;
	ULONG count = 0;
	ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, NULL, 0, &size);
	buffer = ExAllocatePool(PagedPool, size);
	ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, buffer, size, NULL);
	procInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
	do {
		if (procInfo->ImageName.Buffer && !wcscmp(procInfo->ImageName.Buffer, ProcessName)) {
			//ctfhide_pid = (ULONG)(procInfo->UniqueProcessId);
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:pid is | ctfpid %lu | procinfo %lu ", ctfhide_pid, procInfo->UniqueProcessId);
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:current imagename | %wZ", &procInfo->ImageName);
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:current thread num | %lu", procInfo->NumberOfThreads);
			++count;
		}
		procInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG64)procInfo + procInfo->NextEntryOffset);
	} while (procInfo->NextEntryOffset);
	ExFreePool(buffer);

	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:current proc count | %lu", count);
	return count;
}



NTSTATUS InitGloableFunction()
{
	UNICODE_STRING UtrZwQueryInformationProcessName =
		RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
	ZwQueryInformationProcess =
		(PfnZwQueryInformationProcess)MmGetSystemRoutineAddress(&UtrZwQueryInformationProcessName);
	return STATUS_SUCCESS;
}



NTSTATUS GetPathByPid(IN ULONG pid, OUT PANSI_STRING pAnsiNtPath)
{

	HANDLE hProcess = 0;
	CLIENT_ID cid;
	OBJECT_ATTRIBUTES obj;
	NTSTATUS ntStatus;
	ULONG RetLength = 0;
	PVOID pBuffer = NULL;
	HANDLE hFile;
	IO_STATUS_BLOCK iostu;
	PVOID FileObject = NULL;
	PFILE_OBJECT pMyFileObject = NULL;
	UNICODE_STRING DosName;
	UNICODE_STRING FunllPath;

	if (ZwQueryInformationProcess == NULL)
		return STATUS_UNSUCCESSFUL;

	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = 0;
	InitializeObjectAttributes(&obj, 0, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
	ntStatus = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &obj, &cid);
	if (!NT_SUCCESS(ntStatus))
		return STATUS_UNSUCCESSFUL;


	ntStatus = ZwQueryInformationProcess(hProcess, ProcessImageFileName, NULL, 0, &RetLength);
	if (STATUS_INFO_LENGTH_MISMATCH != ntStatus)
		return STATUS_UNSUCCESSFUL;


	pBuffer = ExAllocatePoolWithTag(PagedPool, RetLength, 'niBI');
	if (NULL == pBuffer)
		return STATUS_UNSUCCESSFUL;


	ntStatus = ZwQueryInformationProcess(hProcess, ProcessImageFileName, pBuffer, RetLength, &RetLength);
	if (!NT_SUCCESS(ntStatus))
	{
		if (NULL != pBuffer)
		{
			ExFreePoolWithTag(pBuffer, 'niBI');
		}
		return STATUS_UNSUCCESSFUL;
	}


	InitializeObjectAttributes(&obj, pBuffer, OBJ_KERNEL_HANDLE, 0, 0);
	ntStatus = ZwOpenFile(
		&hFile,
		GENERIC_READ,
		&obj,
		&iostu,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		0);
	if (!NT_SUCCESS(ntStatus))
	{
		if (NULL != pBuffer)
		{
			ExFreePoolWithTag(pBuffer, 'niBI');
		}
		ZwClose(hFile);
		return STATUS_UNSUCCESSFUL;
	}


	ntStatus = ObReferenceObjectByHandle(
		hFile,
		GENERIC_ALL,
		*IoFileObjectType,
		KernelMode,
		&FileObject,
		NULL);

	if (!NT_SUCCESS(ntStatus))
	{
		if (NULL != pBuffer)
		{
			ExFreePoolWithTag(pBuffer, 'niBI');
		}
		ntStatus = ObDereferenceObject(FileObject);
		ZwClose(hFile);
		return STATUS_UNSUCCESSFUL;
	}
	pMyFileObject = (PFILE_OBJECT)FileObject;
	if (NULL == pMyFileObject)
	{
		if (NULL != pBuffer)
		{
			ExFreePoolWithTag(pBuffer, 'niBI');
		}
		ntStatus = ObDereferenceObject(FileObject);
		ZwClose(hFile);
		return STATUS_UNSUCCESSFUL;

	}

	RtlVolumeDeviceToDosName(pMyFileObject->DeviceObject, &DosName);


	FunllPath.MaximumLength = pMyFileObject->FileName.MaximumLength + DosName.MaximumLength;
	FunllPath.Length = pMyFileObject->FileName.Length + DosName.Length;
	FunllPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, FunllPath.MaximumLength, 0);


	RtlCopyUnicodeString(&FunllPath, &DosName);
	RtlAppendUnicodeStringToString(&FunllPath, &pMyFileObject->FileName);
	RtlUnicodeStringToAnsiString(pAnsiNtPath, &FunllPath, TRUE); 


	ExFreePool(FunllPath.Buffer); 
	if (NULL != pBuffer)
	{
		ExFreePoolWithTag(pBuffer, 'niBI');
	}

	ntStatus = ObDereferenceObject(FileObject);
	ZwClose(hFile);
	return STATUS_SUCCESS;
}



// 从应用层向驱动层发送pid
#define  NOV_DVC_SEND_PID \
	(ULONG)CTL_CODE( \
	FILE_DEVICE_UNKNOWN, \
	0x914,METHOD_BUFFERED, \
	FILE_WRITE_DATA)

// 从ring3读取一个字符串
#define  NOV_DVC_RECV_STR \
	(ULONG)CTL_CODE( \
	FILE_DEVICE_UNKNOWN, \
	0x895,METHOD_BUFFERED, \
	FILE_READ_DATA)


PDEVICE_OBJECT g_cdo = NULL;

const GUID  NOV_GUID_CLASS_MYCDO =
{ 0x19b3d1e0L, 0x2273, 0x29f1, {0x77,0x23, 0x55, 0x1d, 0x11, 0x42, 0x19, 0x09} };

#define NOV_CDO_SYB_NAME    L"\\??\\n0val1s_2780f9d7"


NTSTATUS NOVDispatch(
	IN PDEVICE_OBJECT dev,
	IN PIRP irp)
{
	PIO_STACK_LOCATION  irpsp = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ret_len = 0;
	while (dev == g_cdo)
	{

		if (irpsp->MajorFunction == IRP_MJ_CREATE || irpsp->MajorFunction == IRP_MJ_CLOSE)
		{
			break;
		}

		if (irpsp->MajorFunction == IRP_MJ_DEVICE_CONTROL)
		{
			PVOID pid_buffer = irp->AssociatedIrp.SystemBuffer;
			ULONG inlen = irpsp->Parameters.DeviceIoControl.InputBufferLength;
			ULONG outlen = irpsp->Parameters.DeviceIoControl.OutputBufferLength;
			ULONG len;
			switch (irpsp->Parameters.DeviceIoControl.IoControlCode)
			{
			case NOV_DVC_SEND_PID:
				ASSERT(pid_buffer != NULL);
				ASSERT(inlen > 0);
				ASSERT(outlen == 0);
				ctfhide_pid = *((ULONG*)pid_buffer);
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:ctfhide.exe pid | %lu", *((ULONG*)pid_buffer));
				break;
			case NOV_DVC_RECV_STR:
			default:
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}
		break;
	}
	irp->IoStatus.Information = ret_len;
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}




// 获取文件大小
ULONG64	GetFileSize(HANDLE hFile, 
					  IO_STATUS_BLOCK iosb 
					  //UNICODE_STRING ustrFileName
					  )
{
	//HANDLE hFile = NULL;
	//OBJECT_ATTRIBUTES objectAttributes = { 0 };
	//IO_STATUS_BLOCK iosb = { 0 };
	FILE_STANDARD_INFORMATION fsi = { 0 };
	NTSTATUS status = STATUS_SUCCESS;


	status = ZwQueryInformationFile(hFile, &iosb, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:getting txt size failed | status: %d", status);
		return STATUS_UNSUCCESSFUL;
	}

	return fsi.EndOfFile.QuadPart;
}




VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{
	//UNREFERENCED_PARAMETER(pDriverObj);
	UNICODE_STRING cdo_syb = RTL_CONSTANT_STRING(NOV_CDO_SYB_NAME);
	ASSERT(g_cdo != NULL);
	IoDeleteSymbolicLink(&cdo_syb);
	IoDeleteDevice(g_cdo);
	ZwClose(FileHandle);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[-]ctfsys: bye…\r\n");
}



NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, OUT PUNICODE_STRING reg_path)
{

//#if DBG
//    _asm int 3
//#endif 
	NTSTATUS status;

    UNICODE_STRING welco = RTL_CONSTANT_STRING(L"[+]ctfsys-n0val1s:welcome to rsctf 2021!");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "%wZ", &welco);

	//检测是否有ctfhide进程在运行，有则获取其pid
	if (PsFindProcessByName()) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:ctfhide.exe is on!\r\n");
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[-]ctfsys:ctfhide process not found,aborting...\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	//ring3->ring0设备通信部分
	UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;WD)");
	UNICODE_STRING cdo_name = RTL_CONSTANT_STRING(L"\\Device\\ctf_2780f9d7");
	UNICODE_STRING cdo_syb = RTL_CONSTANT_STRING(NOV_CDO_SYB_NAME);

	status = IoCreateDeviceSecure(
		pDriverObj,
		0, &cdo_name,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE, &sddl,
		(LPCGUID)&NOV_GUID_CLASS_MYCDO,
		&g_cdo);
	if (!NT_SUCCESS(status))
		return status;

	IoDeleteSymbolicLink(&cdo_syb);
	status = IoCreateSymbolicLink(&cdo_syb, &cdo_name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(g_cdo);
		return status;
	}


	ULONG i;
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObj->MajorFunction[i] = NOVDispatch;
	}
	g_cdo->Flags &= ~DO_DEVICE_INITIALIZING;


	//内核当前线程睡眠1000ms，与ring3程序通信同步
	//LONG secs = 1000;
	////if(ctfhide_pid!=0)
	//KeSleep(secs);

	//todo1
	
	UNICODE_STRING FileName;
	WCHAR wTxtPathBuf3[256] = { 0 };
	//RtlInitUnicodeString(&FileName, L"\\??\\C:\\hidden.txt");
	RtlInitEmptyUnicodeString(&FileName, wTxtPathBuf3, 256 * sizeof(WCHAR));


	while (TRUE) {
		if (ctfhide_pid != 0) {
			ANSI_STRING AnsiNtPath;
			InitGloableFunction();

			//切断ctfhide.exe路径后exe部分，长度为11
			GetPathByPid(ctfhide_pid, &AnsiNtPath);
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:before 11 ansi_path | %Z", &AnsiNtPath);

			USHORT charsToRemove = 11;
			AnsiNtPath.Length -= sizeof(CHAR) * charsToRemove;
			AnsiNtPath.MaximumLength -= sizeof(CHAR) * charsToRemove;

			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:11 ed ansi_path | %Z", &AnsiNtPath);

			//初始化hidden.txt字符串准备拼接
			ANSI_STRING AnsiPartTxt;
			CHAR* hidden_txt = "hidden.txt";
			RtlInitAnsiString(&AnsiPartTxt, hidden_txt);

			//初始化空字符串为最后拼接完的txt路径（ansi字符串）
			//ANSI_STRING ansiNewPath;
			//CHAR dst_buf[256] = { 0 };
			//RtlInitEmptyAnsiString(&ansiNewPath, dst_buf, 100 * sizeof(CHAR));
			//
			//拼接
			//RtlCopyString(&ansiNewPath, &AnsiNtPath);
			//在ntifs.h中才可用的ansi拼接函数，引入该头文件会导致EPROCESS结构体被重定义为_KROCESS
			//RtlAppendStringToString(&ansiNewPath, &AnsiPartTxt);


			//定义两个新的空Unicode字符串
			UNICODE_STRING wNtPath;
			WCHAR bufNtPath[256] = { 0 };
			RtlInitEmptyUnicodeString(&wNtPath, bufNtPath, 256 * sizeof(WCHAR));

			UNICODE_STRING wPartTxt;
			WCHAR bufPartTxt[256] = { 0 };
			RtlInitEmptyUnicodeString(&wPartTxt, bufPartTxt, 256 * sizeof(WCHAR));

			//将两部分ansi路径分别转为unicode再拼接
			RtlAnsiStringToUnicodeString(&wNtPath, &AnsiNtPath, FALSE);
			RtlAnsiStringToUnicodeString(&wPartTxt, &AnsiPartTxt, FALSE);

			UNICODE_STRING wTxtPath;
			WCHAR bufTxtPath[256] = { 0 };
			RtlInitEmptyUnicodeString(&wTxtPath, bufTxtPath, 256 * sizeof(WCHAR));

			//拼接
			RtlCopyUnicodeString(&wTxtPath, &wNtPath);
			RtlAppendUnicodeStringToString(&wTxtPath, &wPartTxt);




			//添加\\??\\路径前缀
			UNICODE_STRING wPathPrefix = { 0 };
			RtlInitUnicodeString(&wPathPrefix, L"\\??\\");

			UNICODE_STRING wTxtPathFinal;
			WCHAR wTxtPathBuf2[256] = { 0 };
			RtlInitEmptyUnicodeString(&wTxtPathFinal, wTxtPathBuf2, 256 * sizeof(WCHAR));

			RtlCopyUnicodeString(&wTxtPathFinal, &wPathPrefix);
			RtlAppendUnicodeStringToString(&wTxtPathFinal, &wTxtPath);




			//文件保护
			RtlCopyUnicodeString(&FileName, &wTxtPathFinal);
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:getting txt path | %wZ", &FileName);

			OBJECT_ATTRIBUTES FileAttr;

			InitializeObjectAttributes(&FileAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
			status = ZwOpenFile(&FileHandle, FILE_SHARE_READ, &FileAttr, &IoStatusBlock, 0, 0);
			if (status == STATUS_SUCCESS) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:protection on!\n");
			}
			else {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[-]ctfsys:init protection failed...\n");
			}
			break;
		}
	}



	while (TRUE) {
		//todo 2:
		//1.循环打开文件，并获取hidden.txt文件大小，
		//只要大小大于0就什么也不做，需要小于等于0（文件不存在）才执行解密
		//
		//2.预先存储密文，实现解密函数；（aes,xxtea,自定义函数（最好不好分析，魔改现有）
		//文件不存在则进入解密函数，打印解密后flag
		ULONG64 currentTxtSize = GetFileSize(FileHandle, IoStatusBlock);
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:current txt size | %llu bytes\n", currentTxtSize);
		KeSleep(3000);
		if (currentTxtSize <= 0) {
			break;
		}
	}

	while (TRUE) {
		if (PsFindProcessByName()) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:ctfhide.exe is still on!\r\n");
			break;
		}
		else {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[-]ctfsys:ctfhide process not found,aborting...\r\n");
			return STATUS_UNSUCCESSFUL;
		}
	}


	//cng api解密flag
	UCHAR initor[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	UCHAR blob[] =
	{
		0x30, 0x02, 0x00, 0x00, 0x4b, 0x53, 0x53, 0x4d,
		0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
		0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa,
		0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe,
		0xb6, 0x92, 0xcf, 0x0b, 0x64, 0x3d, 0xbd, 0xf1,
		0xbe, 0x9b, 0xc5, 0x00, 0x68, 0x30, 0xb3, 0xfe,
		0xb6, 0xff, 0x74, 0x4e, 0xd2, 0xc2, 0xc9, 0xbf,
		0x6c, 0x59, 0x0c, 0xbf, 0x04, 0x69, 0xbf, 0x41,
		0x47, 0xf7, 0xf7, 0xbc, 0x95, 0x35, 0x3e, 0x03,
		0xf9, 0x6c, 0x32, 0xbc, 0xfd, 0x05, 0x8d, 0xfd,
		0x3c, 0xaa, 0xa3, 0xe8, 0xa9, 0x9f, 0x9d, 0xeb,
		0x50, 0xf3, 0xaf, 0x57, 0xad, 0xf6, 0x22, 0xaa,
		0x5e, 0x39, 0x0f, 0x7d, 0xf7, 0xa6, 0x92, 0x96,
		0xa7, 0x55, 0x3d, 0xc1, 0x0a, 0xa3, 0x1f, 0x6b,
		0x14, 0xf9, 0x70, 0x1a, 0xe3, 0x5f, 0xe2, 0x8c,
		0x44, 0x0a, 0xdf, 0x4d, 0x4e, 0xa9, 0xc0, 0x26,
		0x47, 0x43, 0x87, 0x35, 0xa4, 0x1c, 0x65, 0xb9,
		0xe0, 0x16, 0xba, 0xf4, 0xae, 0xbf, 0x7a, 0xd2,
		0x54, 0x99, 0x32, 0xd1, 0xf0, 0x85, 0x57, 0x68,
		0x10, 0x93, 0xed, 0x9c, 0xbe, 0x2c, 0x97, 0x4e,
		0x13, 0x11, 0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17,
		0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5,
		0x13, 0xaa, 0x29, 0xbe, 0x9c, 0x8f, 0xaf, 0xf6,
		0xf7, 0x70, 0xf5, 0x80, 0x00, 0xf7, 0xbf, 0x03,
		0x13, 0x62, 0xa4, 0x63, 0x8f, 0x25, 0x86, 0x48,
		0x6b, 0xff, 0x5a, 0x76, 0xf7, 0x87, 0x4a, 0x83,
		0x8d, 0x82, 0xfc, 0x74, 0x9c, 0x47, 0x22, 0x2b,
		0xe4, 0xda, 0xdc, 0x3e, 0x9c, 0x78, 0x10, 0xf5,
		0x72, 0xe3, 0x09, 0x8d, 0x11, 0xc5, 0xde, 0x5f,
		0x78, 0x9d, 0xfe, 0x15, 0x78, 0xa2, 0xcc, 0xcb,
		0x2e, 0xc4, 0x10, 0x27, 0x63, 0x26, 0xd7, 0xd2,
		0x69, 0x58, 0x20, 0x4a, 0x00, 0x3f, 0x32, 0xde,
		0xa8, 0xa2, 0xf5, 0x04, 0x4d, 0xe2, 0xc7, 0xf5,
		0x0a, 0x7e, 0xf7, 0x98, 0x69, 0x67, 0x12, 0x94,
		0xc7, 0xc6, 0xe3, 0x91, 0xe5, 0x40, 0x32, 0xf1,
		0x47, 0x9c, 0x30, 0x6d, 0x63, 0x19, 0xe5, 0x0c,
		0xa0, 0xdb, 0x02, 0x99, 0x22, 0x86, 0xd1, 0x60,
		0xa2, 0xdc, 0x02, 0x9c, 0x24, 0x85, 0xd5, 0x61,
		0x8c, 0x56, 0xdf, 0xf0, 0x82, 0x5d, 0xd3, 0xf9,
		0x80, 0x5a, 0xd3, 0xfc, 0x86, 0x59, 0xd7, 0xfd,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x43, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x6d, 0x00,
		0x6f, 0x00, 0x6e, 0x00, 0x20, 0x00, 0x46, 0x00,
		0x69, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x73, 0x00,
		0x5c, 0x00, 0x53, 0x00, 0x69, 0x00, 0x65, 0x00,
		0x6d, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x73, 0x00,
		0x5c, 0x00, 0x41, 0x00, 0x75, 0x00, 0x74, 0x00,
		0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x74, 0x00,
		0x69, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x5c, 0x00,
		0x53, 0x00, 0x69, 0x00, 0x6d, 0x00, 0x61, 0x00,
		0x74, 0x00, 0x69, 0x00, 0x63, 0x00, 0x20, 0x00,
		0x4f, 0x00, 0x41, 0x00, 0x4d, 0x00, 0x00, 0x00,
		0x53, 0x00, 0x69, 0x00, 0x6d, 0x00, 0x61, 0x00,
		0x74, 0x00, 0x69, 0x00, 0x63, 0x00, 0x5f, 0x00,
		0x4f, 0x00, 0x41, 0x00, 0x4d, 0x00, 0x5f, 0x00,
		0x44, 0x00, 0x41, 0x00, 0x54, 0x00, 0x41, 0x00,
		0x3d, 0x00, 0x43, 0x00, 0x3a, 0x00, 0x5c, 0x00,
		0xa0, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	UCHAR secret[] =
	{
		0xbd, 0xec, 0xf8, 0xfd, 0x20, 0xdb, 0x6f, 0x05,
		0x09, 0x99, 0xee, 0x8a, 0x61, 0xbe, 0x4f, 0x4a,
		0x73, 0x23, 0x08, 0x7f, 0xbb, 0x48, 0x50, 0x03,
		0xb2, 0x9f, 0x8f, 0x81, 0xa0, 0xc2, 0x83, 0x72
	};




	status = STATUS_UNSUCCESSFUL;
	PUCHAR		pbBlob = NULL;
	PUCHAR		pbSeText = NULL;
	PUCHAR		pbPlainText = NULL;
	PUCHAR		pbKOB = NULL;
	PUCHAR		pbInitor = NULL;

	DWORD					cbSeText = 0,
							cbPlainText = 0,
							cbData = 0,
							cbKOB = 0,
							cbBlockLen = 0,
							cbBlob = 0;

	BCRYPT_ALG_HANDLE       hAesAlg = NULL;
	BCRYPT_KEY_HANDLE       hKey = NULL;






	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&hAesAlg,
		BCRYPT_AES_ALGORITHM,
		NULL,
		0)))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:error OpenAlgorithmProvider | 0x%x\n", status);
		goto Cleanup;
	}


	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAesAlg,
		BCRYPT_OBJECT_LENGTH,
		(PUCHAR)&cbKOB,
		sizeof(DWORD),
		&cbData,
		0)))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys: error GetProperty | 0x%x\n", status);
		goto Cleanup;
	}


	pbKOB = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, cbKOB, 'KyyO');
	if (NULL == pbKOB)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys: error KOB allocate | 0x%x\n", status);
		goto Cleanup;
	}



	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAesAlg,
		BCRYPT_BLOCK_LENGTH,
		(PUCHAR)&cbBlockLen,
		sizeof(DWORD),
		&cbData,
		0)))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys: error calc block | 0x%x\n", status);
		goto Cleanup;
	}

	if (cbBlockLen > sizeof(initor))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys: error block bigger than initor | 0x%x\n", status);
		goto Cleanup;
	}



	pbInitor = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, cbBlockLen, 'ivBL');
	if (NULL == pbInitor)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys: error block allocate | 0x%x\n", status);
		goto Cleanup;
	}

	memcpy(pbInitor, initor, cbBlockLen);

	if (!NT_SUCCESS(status = BCryptSetProperty(
		hAesAlg,
		BCRYPT_CHAINING_MODE,
		(PUCHAR)BCRYPT_CHAIN_MODE_CBC,
		sizeof(BCRYPT_CHAIN_MODE_CBC),
		0)))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys: error SetProperty choose mode | 0x%x\n", status);
		goto Cleanup;
	}


	pbBlob = blob;
	cbBlob = 560;
	if (!NT_SUCCESS(status = BCryptImportKey(
		hAesAlg,
		NULL,
		BCRYPT_OPAQUE_KEY_BLOB,
		&hKey,
		pbKOB,
		cbKOB,
		pbBlob,
		cbBlob,
		0)))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys: error imporT | 0x%x\n", status);
		goto Cleanup;
	}




	pbSeText = secret;
	cbSeText = 32;
	if (!NT_SUCCESS(status = BCryptDecrypt(
		hKey,
		pbSeText,
		cbSeText,
		NULL,
		pbInitor,
		cbBlockLen,
		NULL,
		0,
		&cbPlainText,
		BCRYPT_BLOCK_PADDING)))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys: error get plaintext size | 0x%x\n", status);
		goto Cleanup;
	}

	pbPlainText = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, cbPlainText, 'plTx');
	if (NULL == pbPlainText)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys: error plaintext allocate | 0x%x\n", status);
		goto Cleanup;
	}



	if (!NT_SUCCESS(status = BCryptDecrypt(
		hKey,
		pbSeText,
		cbSeText,
		NULL,
		pbInitor,
		cbBlockLen,
		pbPlainText,
		cbPlainText,
		&cbPlainText,
		BCRYPT_BLOCK_PADDING)))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys: critical error | 0x%x\n", status);
		goto Cleanup;
	}


	ANSI_STRING fg;
	RtlInitAnsiString(&fg, pbPlainText);
	fg.Length = fg.MaximumLength = 16;

	//UCHAR fgBuf[16] = { 0 };
	//RtlInitEmptyAnsiString(&fg, fgBuf, 16 * sizeof(UCHAR));
	//for (DWORD i = 0; i < 16; i++) {
	//	fg.Buffer[i] = pbSeText[i];
	//}


	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+]ctfsys:congratulation! | flag{%Z}\n", &fg);
	
	ExFreePoolWithTag(pbPlainText, 'plTx');
	ExFreePoolWithTag(pbKOB, 'KyyO');
	ExFreePoolWithTag(pbInitor, 'ivBL');



	pDriverObj->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;


Cleanup:

	if (hAesAlg)
	{
		BCryptCloseAlgorithmProvider(hAesAlg, 0);
	}

	if (hKey)
	{
		BCryptDestroyKey(hKey);
	}

	if (pbSeText)
	{
		pbSeText = 0;
	}

	if (pbBlob) 
	{
		pbBlob = 0;
	}

	if (pbPlainText)
	{
		ExFreePoolWithTag(pbPlainText, 'plTx');
	}

	if (pbKOB)
	{
		ExFreePoolWithTag(pbKOB, 'KyyO');
	}

	if (pbInitor)
	{
		ExFreePoolWithTag(pbInitor, 'ivBL');
	}


	return STATUS_UNSUCCESSFUL;
}
