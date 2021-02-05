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
		0x50, // push rax
		0x51, // push rcx
		0x52, // push rdx
		0x53, // push rbx
		0x54, // push rsp
		0x55, // push rbp
		0x56, // push rsi
		0x57, // push rdi

		0xba, 0x00, 0x00, 0x00, 0x00, // mov edx, arg2
		0xb9, 0x00, 0x00, 0x00, 0x00, // mov ecx, arg1
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, address

		0xff, 0xd0, // call rax

		0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, address
		0x48, 0x89, 0x02, // mov [rdx], rax

		0x5f, // pop rdi
		0x5e, // pop rsi
		0x5d, // pop rbp
		0x5c, // pop rsp
		0x5b, // pop rbx
		0x5a, // pop rdx
		0x59, // pop rcx
		0x58, // pop rax

		0xc3, // ret
	};

	auto processId = GetProcessIdByName(L"Victim.exe");
	auto arg1 = 1;
	auto arg2 = 1;
	const auto functionAddress = 0x00007FF7B7F11020;
	const auto offsetOfFunctionArgument1 = 9;
	const auto offsetOfFunctionArgument2 = 14;
	const auto offsetOfFunctionAddress = 20;
	const auto offsetOfReturnAddress = 32;

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

	auto allocatedReturnValue = VirtualAllocEx(hProcess, NULL, sizeof(uint64_t), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
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
	context.Rsp -= 8;
	if (!WriteProcessMemory(hProcess, reinterpret_cast<uint64_t*>(context.Rsp), &context.Rip, sizeof(uint64_t), nullptr))
	{
		DebugLog("WriteProcessMemory failed");
		return 1;
	}

	// change RIP
	context.Rip = reinterpret_cast<uint64_t>(allocatedShellCodeAddress);

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
	if (!ReadProcessMemory(hProcess, reinterpret_cast<uint64_t*>(allocatedReturnValue), &returnValue, sizeof(returnValue), nullptr))
	{
		DebugLog("ReadProcessMemory failed");
		return 1;
	}

	std::cout << "Return value:" << std::dec << returnValue << std::endl;

	system("pause");
	return 0;
}
