#pragma once
#include <Windows.h>
#include <Shlwapi.h>
#include <winternl.h>
#include <psapi.h>
#include <iostream>
#include <string>
#pragma comment(lib, "Ntdll.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Psapi.lib") 
constexpr unsigned int STATUS_SUCCESS = 0x0;
constexpr unsigned int STATUS_INFO_LENGTH_MISMATCH = 0x0C0000004;

EXTERN_C NTSTATUS NTAPI NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

void EnumerateProcessModules(DWORD processID) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == NULL) {
        std::wcerr << L"Unable to open process for PID " << processID << std::endl;
        return;
    }

   
    HMODULE hModules[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        int numModules = cbNeeded / sizeof(HMODULE);
        std::wcout << L"Modules for PID: " << processID << std::endl;
        for (int i = 0; i < numModules; ++i) {
            wchar_t moduleName[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, hModules[i], moduleName, sizeof(moduleName) / sizeof(wchar_t))) {
                std::wcout << L"Module " << i + 1 << ": " << moduleName << std::endl;
            }
        }
    }
    else {
        std::wcerr << L"Failed to enumerate modules for PID " << processID << std::endl;
    }

    CloseHandle(hProcess);
}

INT main(VOID) {

    DWORD processID;
    std::wcout << L"Enter the PID to fetch process details: ";
    std::wcin >> processID;

    DWORD dwRet;
    DWORD dwSize = 0x0;
    NTSTATUS dwStatus = STATUS_INFO_LENGTH_MISMATCH;
    PSYSTEM_PROCESS_INFORMATION wrench = nullptr;

    while (TRUE) {
        if (wrench != nullptr) {
            VirtualFree(wrench, 0x0, MEM_RELEASE);
        }

        wrench = (PSYSTEM_PROCESS_INFORMATION)VirtualAlloc(nullptr, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        dwStatus = NtQuerySystemInformation(SystemProcessInformation, (PVOID)wrench, (ULONG)dwSize, &dwRet);
        if (dwStatus == STATUS_SUCCESS) { break; }
        else if (dwStatus != STATUS_INFO_LENGTH_MISMATCH) {
            VirtualFree(wrench, 0x0, MEM_RELEASE);
            wrench = nullptr;
            std::cout << "Error fetching details" << std::endl;
            return 0x1;
        }

        dwSize = dwRet + (2 << 12);
    }

    bool processFound = false;

    do {

        DWORD currentProcessID = HandleToUlong(wrench->UniqueProcessId);

        if (currentProcessID == processID) {
            processFound = true;
            std::wcout << L"PID: " << currentProcessID << std::endl
                << L"Session ID: " << wrench->SessionId << std::endl
                << L"Image Name: " << (wrench->ImageName.Buffer ? wrench->ImageName.Buffer : L"") << std::endl
                << L"# Handles: " << wrench->HandleCount << std::endl
                << L"# Threads: " << wrench->NumberOfThreads << std::endl
                << L"Virtual Size: " << wrench->VirtualSize << std::endl
                << L"Peak Virtual Size: " << wrench->PeakVirtualSize << std::endl
                << L"Pagefile Usage: " << wrench->PagefileUsage << std::endl
                << L"Peak Pagefile Usage: " << wrench->PeakPagefileUsage << std::endl
                << L"Working Set Size: " << wrench->WorkingSetSize << std::endl
                << L"Peak Working Set Size: " << wrench->PeakWorkingSetSize << std::endl
                << L"Quota Non-Paged Pool Usage: " << wrench->QuotaNonPagedPoolUsage << std::endl
                << L"Quota Paged Pool Usage: " << wrench->QuotaPagedPoolUsage << std::endl
                << L"-------------------------------------------------------------------------------------" << std::endl;

            EnumerateProcessModules(currentProcessID);
            break;
        }

        wrench = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)wrench + wrench->NextEntryOffset);
    } while (wrench->NextEntryOffset != 0);

    if (!processFound) {
        std::wcout << L"PID " << processID << L" not found." << std::endl;
    }

    VirtualFree(wrench, 0x0, MEM_RELEASE);
    wrench = nullptr;

    return 0x0;

}
