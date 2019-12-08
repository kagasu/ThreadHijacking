#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iomanip>
#include <iostream>

#define DebugLog(str) std::cout << "[DEBUG] [LINE: " << std::dec << __LINE__ << "] " << str << std::endl;

DWORD GetMainThreadIdByProcessId(DWORD processId)
{
	// https://stackoverflow.com/a/1982200
	auto hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnapshot == INVALID_HANDLE_VALUE)
	{
		DebugLog("CreateToolhelp32Snapshot failed");
	}
	THREADENTRY32 tEntry = { 0 };
	tEntry.dwSize = sizeof(THREADENTRY32);
	for (auto success = Thread32First(hThreadSnapshot, &tEntry);
		success && GetLastError() != ERROR_NO_MORE_FILES;
		success = Thread32Next(hThreadSnapshot, &tEntry))
	{
		if (tEntry.th32OwnerProcessID == processId)
		{
			return tEntry.th32ThreadID;
		}
	}
	return NULL;
}

DWORD GetProcessIdByName(const wchar_t* targetProcessName)
{
	DWORD processIds[1024];
	DWORD cbNeeded;

	if (EnumProcesses(processIds, sizeof(processIds), &cbNeeded))
	{
		for (DWORD i = 0; i < cbNeeded / sizeof(DWORD); i++)
		{
			TCHAR processName[MAX_PATH] = { 0 };
			auto hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIds[i]);

			if (hProcess != NULL)
			{
				DWORD size = MAX_PATH;
				if (QueryFullProcessImageName(hProcess, NULL, processName, &size))
				{
					// std::wcout << processName << "," << targetProcessName << std::endl;
					if (wcsstr(processName, targetProcessName))
					{
						CloseHandle(hProcess);
						return processIds[i];
					}
				}

				CloseHandle(hProcess);
			}
		}
	}

	return -1;
}

int main()
{
	uint8_t shellcode[] = {
		0x60,						  // pushad
		0x9C,						  // pushfd
		0x68, 0x00, 0x00, 0x00, 0x00, // push 0x00
		0x68, 0x00, 0x00, 0x00, 0x00, // push 0x00
		0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0x00000000
		0xFF, 0xD0,					  // call eax
		0xBB, 0x00, 0x00, 0x00, 0x00, // mov ebx, 0x00000000
		0x89, 0x03,					  // mov [ebx], eax
		// change esp when calling convention is "__cdecl"
		// 0x83, 0xC4, 0x08,		  // add esp, 0x08
		0x9D,						  // popfd
		0x61,						  // popad
		0xC3,						  // retn
	};

	auto processId = GetProcessIdByName(L"Victim.exe");
	auto arg1 = 1;
	auto arg2 = 1;
	const auto functionAddress = 0x003B1020;
	const auto offsetOfFunctionArgument1 = 3;
	const auto offsetOfFunctionArgument2 = 8;
	const auto offsetOfFunctionAddress = 13;
	const auto offsetOfReturnAddress = 20;

	// write arg1, arg2
	memcpy(&shellcode[offsetOfFunctionArgument1], &arg1, sizeof(arg1));
	memcpy(&shellcode[offsetOfFunctionArgument2], &arg2, sizeof(arg2));

	// write function address
	memcpy(&shellcode[offsetOfFunctionAddress], &functionAddress, sizeof(functionAddress));

	auto threadId = GetMainThreadIdByProcessId(processId);
	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
	if (hProcess == NULL)
	{
		DebugLog("OpenProcess failed");
		return 1;
	}
	auto hThread = OpenThread(THREAD_ALL_ACCESS, false, threadId);
	if (hThread == NULL)
	{
		DebugLog("OpenThread failed");
		return 1;
	}

	SuspendThread(hThread);

	auto allocatedReturnValue = VirtualAllocEx(hProcess, NULL, sizeof(DWORD), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (allocatedReturnValue == NULL)
	{
		DebugLog("VirtualAlloc failed");
		return 1;
	}

	// write return address
	memcpy(&shellcode[offsetOfReturnAddress], &allocatedReturnValue, sizeof(allocatedReturnValue));

	auto allocatedShellCodeAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (allocatedShellCodeAddress == NULL)
	{
		DebugLog("VirtualAlloc failed");
		return 1;
	}
	std::cout << "allocatedShellCodeAddress: 0x" << std::hex << allocatedShellCodeAddress << std::endl;

	if (!WriteProcessMemory(hProcess, allocatedShellCodeAddress, &shellcode, sizeof(shellcode), nullptr))
	{
		DebugLog("WriteProcessMemory failed");
	}

	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(hThread, &context))
	{
		DebugLog("GetThreadContext failed");
	}

	// push return address
	context.Esp -= 4;
	if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(context.Esp), &context.Eip, sizeof(DWORD), nullptr))
	{
		DebugLog("WriteProcessMemory failed");
		return 1;
	}

	// change EIP(Extend instruction pointer)
	context.Eip = reinterpret_cast<DWORD>(allocatedShellCodeAddress);

	if (!SetThreadContext(hThread, &context))
	{
		DebugLog("SetThreadContext failed");
		return 1;
	}

	ResumeThread(hThread);

	// wait for execute
	Sleep(1000);

	// read return value
	DWORD returnValue = 0;
	if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(allocatedReturnValue), &returnValue, sizeof(returnValue), nullptr))
	{
		DebugLog("ReadProcessMemory failed");
		return 1;
	}

	std::cout << "Return value:" << std::dec << returnValue << std::endl;

	system("pause");
	return 0;
}
