// MIT License

// Copyright (c) 2021 TheCruZ

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <iostream>
#include <vector>
#include <ntstatus.h>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <fstream>
#include "driver/driver_binary.h" // Include the driver binary data
#pragma warning(disable : 4005)
#pragma warning(default : 4005)

// Kernel driver defines and structures
#define offset_io_mirrore   0x2338
#define file_device_mirrore 0x3009

#define ioctl_get_module_information (ULONG)CTL_CODE(file_device_mirrore, offset_io_mirrore + 0x0010, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define ioctl_copy_memory (ULONG)CTL_CODE(file_device_mirrore, offset_io_mirrore + 0x0050, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define ioctl_protect_memory (ULONG)CTL_CODE(file_device_mirrore, offset_io_mirrore + 0x0100, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define ioctl_alloc_memory (ULONG)CTL_CODE(file_device_mirrore, offset_io_mirrore + 0x0150, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define ioctl_free_memory (ULONG)CTL_CODE(file_device_mirrore, offset_io_mirrore + 0x0200, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

// Driver structures
typedef struct _set_module_information
{
    ULONG pid;
    wchar_t sz_name[32];
} set_module_information, *pset_module_information;

typedef struct _get_module_information
{
    ULONGLONG base_image;
    ULONGLONG size_of_image;
} get_module_information, *pget_module_information;

typedef struct _copy_memory
{
    ULONGLONG buffer;
    ULONGLONG address;
    ULONGLONG size;
    ULONG pid;
    BOOLEAN write;
} copy_memory, *pcopy_memory;

typedef struct _protect_memory
{
    ULONG pid;
    ULONGLONG address;
    ULONGLONG size;
    PDWORD new_protect;
} protect_memory, *pprotect_memory;

typedef struct _alloc_memory
{
    ULONG pid;
    ULONGLONG out_address;
    ULONGLONG size;
    ULONG protect;
} alloc_memory, *palloc_memory;

typedef struct _free_memory
{
    ULONG pid;
    ULONGLONG address;
} free_memory, *pfree_memory;

// Forward declaration of driver class
class c_driver;
c_driver& driver();

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif // _WIN64

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif // _WIN64

#define log_info(fmt, ...) 
#define log_warn(fmt, ...) 
#define log_error(fmt, ...) 

#define mks(STRING) ([&] {                                       \
    constexpr auto _{ crypt(STRING, seed(__FILE__, __LINE__)) }; \
    return std::string{ crypt(_.data, _.seed).data };            \
}())

// Driver implementation
#define DVR_DEVICE_FILE L"\\\\.\\EIQDV" 

class c_driver
{
public:
    c_driver() {}
    ~c_driver() { if (h_driver != INVALID_HANDLE_VALUE) CloseHandle(h_driver); }

    DWORD process_id = 0;

    static c_driver& singleton()
    {
        static c_driver p_object;
        return p_object;
    }

    void handle_driver()
    {
        h_driver = CreateFileW(DVR_DEVICE_FILE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    }

    void attach_process(DWORD pid)
    {
        process_id = pid;
    }

    NTSTATUS send_service(ULONG ioctl_code, LPVOID io, DWORD size)
    {
        if (h_driver == INVALID_HANDLE_VALUE)
            return STATUS_DEVICE_DOES_NOT_EXIST;

        if (!DeviceIoControl(h_driver, ioctl_code, io, size, nullptr, 0, NULL, NULL))
            return STATUS_UNSUCCESSFUL;

        return STATUS_SUCCESS;
    }

    NTSTATUS get_module_information_ex(const wchar_t* name, pget_module_information mod)
    {
        if (h_driver == INVALID_HANDLE_VALUE)
            return STATUS_DEVICE_DOES_NOT_EXIST;
        
        set_module_information req = { 0 };

        req.pid = process_id;
        wcscpy_s(req.sz_name, name);

        if (!DeviceIoControl(h_driver, ioctl_get_module_information, &req, sizeof(req), mod, sizeof(get_module_information), 0, NULL))
            return STATUS_UNSUCCESSFUL;

        return STATUS_SUCCESS;
    }

    NTSTATUS read_memory_ex(PVOID base, PVOID buffer, DWORD size)
    {
        copy_memory req = { 0 };

        req.pid = process_id;
        req.address = reinterpret_cast<ULONGLONG>(base);
        req.buffer = reinterpret_cast<ULONGLONG>(buffer);
        req.size = (uint64_t)size;
        req.write = FALSE;

        return send_service(ioctl_copy_memory, &req, sizeof(req));
    }

    NTSTATUS write_memory_ex(PVOID base, PVOID buffer, DWORD size)
    {
        copy_memory req = { 0 };

        req.pid = process_id;
        req.address = reinterpret_cast<ULONGLONG>(base);
        req.buffer = reinterpret_cast<ULONGLONG>(buffer);
        req.size = (uint64_t)size;
        req.write = TRUE;

        return send_service(ioctl_copy_memory, &req, sizeof(req));
    }

    NTSTATUS protect_memory_ex(uint64_t base, uint64_t size, PDWORD protection)
    {
        protect_memory req = { 0 };

        req.pid = process_id;
        req.address = base;
        req.size = size;
        req.new_protect = protection;

        return send_service(ioctl_protect_memory, &req, sizeof(req));
    }

    PVOID alloc_memory_ex(DWORD size, DWORD protect)
    {
        PVOID p_out_address = NULL;
        alloc_memory req = { 0 };

        req.pid = process_id;
        req.out_address = reinterpret_cast<ULONGLONG>(&p_out_address);
        req.size = size;
        req.protect = protect;

        send_service(ioctl_alloc_memory, &req, sizeof(req));

        return p_out_address;
    }

    NTSTATUS free_memory_ex(PVOID address)
    {
        free_memory req = { 0 };

        req.pid = process_id;
        req.address = reinterpret_cast<ULONGLONG>(address);

        return send_service(ioctl_free_memory, &req, sizeof(req));
    }
    
    inline bool is_loaded() const { return h_driver != INVALID_HANDLE_VALUE; }

private:    
    c_driver(const c_driver&) = delete;
    c_driver& operator = (const c_driver&) = delete;
    HANDLE h_driver = INVALID_HANDLE_VALUE;
};

inline c_driver& driver()
{
    return c_driver::singleton();
}

// Function to extract driver binary to a file
bool extract_driver(const std::wstring& driver_path) {
    std::ofstream file(driver_path, std::ios::binary);
    if (!file.is_open()) {
        std::wcerr << L"Failed to create driver file: " << driver_path << std::endl;
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(g_driver_binary), g_driver_binary_size);
    file.close();
    
    if (file.fail()) {
        std::wcerr << L"Failed to write driver file data" << std::endl;
        return false;
    }
    
    return true;
}

// Install and start the driver service
bool install_driver_service(const std::wstring& driver_path) {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        std::wcerr << L"Failed to open Service Control Manager. Error: " << GetLastError() << std::endl;
        return false;
    }
    
    // Create the service
    SC_HANDLE service = CreateServiceW(
        scm,
        L"EIQDV",                  // Service name
        L"EIQDV Driver",           // Display name
        SERVICE_ALL_ACCESS,        // Desired access
        SERVICE_KERNEL_DRIVER,     // Service type
        SERVICE_DEMAND_START,      // Start type
        SERVICE_ERROR_NORMAL,      // Error control
        driver_path.c_str(),       // Binary path
        NULL, NULL, NULL, NULL, NULL
    );
    
    if (!service) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            // Service already exists, try to open it
            service = OpenServiceW(scm, L"EIQDV", SERVICE_ALL_ACCESS);
            if (!service) {
                std::wcerr << L"Failed to open existing driver service. Error: " << GetLastError() << std::endl;
                CloseServiceHandle(scm);
                return false;
            }
        } else {
            std::wcerr << L"Failed to create driver service. Error: " << error << std::endl;
            CloseServiceHandle(scm);
            return false;
        }
    }
    
    // Start the service
    if (!StartService(service, 0, NULL)) {
        DWORD error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            std::wcerr << L"Failed to start driver service. Error: " << error << std::endl;
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }
    }
    
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

// Uninstall the driver service
bool uninstall_driver_service() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        std::wcerr << L"Failed to open Service Control Manager. Error: " << GetLastError() << std::endl;
        return false;
    }
    
    SC_HANDLE service = OpenServiceW(scm, L"EIQDV", SERVICE_ALL_ACCESS);
    if (!service) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            // Service doesn't exist, so we're good
            CloseServiceHandle(scm);
            return true;
        }
        
        std::wcerr << L"Failed to open driver service. Error: " << error << std::endl;
        CloseServiceHandle(scm);
        return false;
    }
    
    // Stop the service first
    SERVICE_STATUS status;
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        DWORD error = GetLastError();
        if (error != ERROR_SERVICE_NOT_ACTIVE) {
            std::wcerr << L"Failed to stop driver service. Error: " << error << std::endl;
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }
    }
    
    // Delete the service
    if (!DeleteService(service)) {
        std::wcerr << L"Failed to delete driver service. Error: " << GetLastError() << std::endl;
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }
    
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

// Function to initialize the driver
bool init_driver()
{
    // Get temp directory path
    wchar_t temp_path[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_path);
    
    // Create driver path
    std::wstring driver_path = std::wstring(temp_path) + L"EIQDV.sys";
    
    // Extract the driver binary to the temporary file
    if (!extract_driver(driver_path)) {
        std::wcerr << L"Failed to extract driver binary" << std::endl;
        return false;
    }
    
    // Install and start the driver service
    if (!install_driver_service(driver_path)) {
        std::wcerr << L"Failed to install driver service" << std::endl;
        return false;
    }
    
    // Now try to connect to the driver
    driver().handle_driver();
    
    // Check if we successfully connected to the driver
    if (!driver().is_loaded()) {
        std::wcerr << L"Failed to connect to driver" << std::endl;
        return false;
    }
    
    std::wcout << L"Driver loaded successfully" << std::endl;
    return true;
}

// Function to cleanup driver resources
void cleanup_driver() {
    // Close the driver handle first
    driver().~c_driver();
    
    // Uninstall the driver service
    if (!uninstall_driver_service()) {
        std::wcerr << L"Failed to uninstall driver service" << std::endl;
    }
    
    // Delete the driver file
    wchar_t temp_path[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_path);
    std::wstring driver_path = std::wstring(temp_path) + L"EIQDV.sys";
    
    if (std::filesystem::exists(driver_path)) {
        try {
            std::filesystem::remove(driver_path);
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "Failed to delete driver file: " << e.what() << std::endl;
        }
    }
}

// Helper structure for injection methods
struct TargetProcess {
    std::wstring display_name;
    std::wstring process_name;
    std::wstring dll_name;
    DWORD process_id;
};

#define k32func(f) auto s##f(mks(#f)); _##f = (t##f)GetProcAddress(k32, s##f.c_str()); assert(_##f != NULL)
#define a32func(f) auto s##f(mks(#f)); _##f = (t##f)GetProcAddress(a32, s##f.c_str()); assert(_##f != NULL)

typedef DWORD (WINAPI *tGetFullPathNameW)(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart);
typedef DWORD (WINAPI *tGetLastError)();
typedef HANDLE (WINAPI *tCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL (WINAPI *tProcess32FirstW)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef BOOL (WINAPI *tProcess32NextW)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef BOOL (WINAPI *tCloseHandle)(HANDLE hObject);
typedef HANDLE (WINAPI *tOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef LPVOID (WINAPI *tVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI *tVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef BOOL (WINAPI *tVirtualFreeEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef BOOL (WINAPI *tWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
typedef BOOL (WINAPI *tReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
typedef HMODULE (WINAPI *tLoadLibraryW)(LPCWSTR lpLibFileName);
typedef BOOL (WINAPI *tIsWow64Process)( HANDLE hProcess, PBOOL Wow64Process);
typedef BOOL (WINAPI *tOpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
typedef BOOL (WINAPI *tLookupPrivilegeValueW)(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
typedef HANDLE (WINAPI *tGetCurrentProcess)();
typedef HANDLE (WINAPI *tCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
                                             LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef BOOL (WINAPI *tAdjustTokenPrivileges)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState,
                                             DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);

tCreateToolhelp32Snapshot _CreateToolhelp32Snapshot = 0;
tGetFullPathNameW _GetFullPathNameW = 0;
tGetLastError _GetLastError = 0;
tProcess32FirstW _Process32FirstW = 0;
tProcess32NextW _Process32NextW = 0;
tCloseHandle _CloseHandle = 0;
tOpenProcess _OpenProcess = 0;
tVirtualAllocEx _VirtualAllocEx = 0;
tVirtualProtectEx _VirtualProtectEx = 0;
tVirtualFreeEx _VirtualFreeEx = 0;
tWriteProcessMemory _WriteProcessMemory = 0;
tReadProcessMemory _ReadProcessMemory = 0;
tCreateRemoteThread _CreateRemoteThread = 0;
tLoadLibraryW _LoadLibraryW = 0;
tIsWow64Process _IsWow64Process = 0;
tGetCurrentProcess _GetCurrentProcess = 0;
tOpenProcessToken _OpenProcessToken = 0;
tLookupPrivilegeValueW _LookupPrivilegeValueW = 0;
tAdjustTokenPrivileges _AdjustTokenPrivileges = 0;

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);
#ifdef _WIN64
using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif // _WIN64

struct MANUAL_MAPPING_DATA
{
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
    f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif // _WIN64
    BYTE* pbase;
    HINSTANCE hMod;
    DWORD fdwReasonParam;
    LPVOID reservedParam;
    BOOL SEHSupport;
};

typedef enum
{
    FR_READ_WRITE = 0,
    FR_READ_ONLY,
} flag_t;

typedef struct
{
    HANDLE hMap;
    HANDLE handle;
    flag_t access;
    size_t size;
    uint8_t *start;
} File;

File open_or_create_file(const wchar_t *path, flag_t access, int create);
File open_file(const wchar_t *path, flag_t access);
int close_file(HANDLE handle);
int file_exists(const wchar_t *path);
int get_file_size(File *f);
int map_file(File *f);
int unmap_file(File f);

File open_file(const wchar_t *path, flag_t access)
{
    File f = open_or_create_file(path, access, 0);
    if (f.handle == INVALID_HANDLE_VALUE)
    {
        log_error("Couldn't open file: %S", path);
        exit(1);
    }
    return f;
}

File open_or_create_file(const wchar_t *path, flag_t access, int create)
{
    File f = {0};
    DWORD dwCreationDisposition;
    if (create && !file_exists(path))
        dwCreationDisposition = CREATE_NEW;
    else
        dwCreationDisposition = OPEN_EXISTING;

    DWORD dwDesiredAccess;
    switch (access)
    {
        case FR_READ_WRITE:
            dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
            break;
        case FR_READ_ONLY:
            dwDesiredAccess = GENERIC_READ;
            break;
        default:
        {
            assert(0 && "unreachable");
            exit(1);
        }
        break;
    }

    f.handle = CreateFileW(path, dwDesiredAccess, 0, 0, dwCreationDisposition, FILE_ATTRIBUTE_NORMAL, 0);
    if (f.handle == INVALID_HANDLE_VALUE)
    {
        log_error("Opening file %S", path);
        return f;
    }
    if (dwCreationDisposition == OPEN_EXISTING && !get_file_size(&f))
    {
        log_error("Invalid file size %S", path);
        close_file(f.handle);
        f.handle = INVALID_HANDLE_VALUE;
        return f;
    }
    f.access = access;
    return f;
}

int close_file(HANDLE handle)
{
    if (_CloseHandle(handle) == 0)
    {
        log_error("CloseHandle failed (%ld)", GetLastError());
        return 0;
    }
    return 1;
}

int file_exists(const wchar_t *path)
{
    DWORD dwAttrib = GetFileAttributesW(path);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
            !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

int get_file_size(File *f)
{
    LARGE_INTEGER lpFileSize;
    if (!GetFileSizeEx(f->handle, &lpFileSize))
    {
        log_error("GetFileSizeEx failed (%ld)", GetLastError());
        return 0;
    }
    f->size = lpFileSize.QuadPart;
    return 1;
}

int map_file(File *f)
{
    DWORD flProtect;
    switch (f->access)
    {
        case FR_READ_WRITE:
            flProtect = PAGE_READWRITE;
            break;
        case FR_READ_ONLY:
            flProtect = PAGE_READONLY;
            break;
        default:
            return 0;
    }

    f->hMap = CreateFileMappingA(f->handle, 0, flProtect, 0, 0, 0);
    if (f->hMap == 0)
    {
        log_error("CreateFileMappingA failed (%ld)", GetLastError());
        _CloseHandle(f->handle);
        return 0;
    }

    DWORD dwDesiredAccess;
    switch (f->access)
    {
        case FR_READ_WRITE:
            dwDesiredAccess = FILE_MAP_ALL_ACCESS;
            break;
        case FR_READ_ONLY:
            dwDesiredAccess = FILE_MAP_READ;
            break;
        default:
            return 0;
    }

    f->start = (uint8_t *)MapViewOfFile(f->hMap, dwDesiredAccess, 0, 0, 0);
    if (f->start == 0)
    {
        log_error("MapViewOfFile failed (%ld)", GetLastError());
        _CloseHandle(f->hMap);
        _CloseHandle(f->handle);
        return 0;
    }
    return 1;
}

int unmap_file(File f)
{
    if (UnmapViewOfFile(f.start) == 0)
    {
        log_error("UnmapViewOfFile failed (%ld)", GetLastError());
        return 0;
    }
    if (_CloseHandle(f.hMap) == 0)
    {
        log_error("_CloseHandle failed (%ld)", GetLastError());
        return 0;
    }
    return 1;
}

// https://gist.github.com/EvanMcBroom/ace2a9af19fb5e7b2451b1cd4c07bf96
constexpr uint32_t modulus() {
    return 0x7fffffff;
}

constexpr uint32_t prng(const uint32_t input) {
    return (input * 48271) % modulus();
}

template<size_t N>
constexpr uint32_t seed(const char(&entropy)[N], const uint32_t iv = 0) {
    auto value{ iv };
    for (size_t i{ 0 }; i < N; i++) {
        // Xor 1st byte of seed with input byte
        value = (value & ((~0) << 8)) | ((value & 0xFF) ^ entropy[i]);
        // Rotate left 1 byte
        value = value << 8 | value >> ((sizeof(value) * 8) - 8);
    }
    // The seed is required to be less than the modulus and odd
    while (value > modulus()) value = value >> 1;
    return value << 1 | 1;
}

template<typename T, size_t N>
struct encrypted {
    int seed;
    T data[N];
};

template<size_t N>
constexpr auto crypt(const char(&input)[N], const uint32_t seed = 0) {
    encrypted<char, N> blob{};
    blob.seed = seed;
    for (uint32_t index{ 0 }, stream{ seed }; index < N; index++) {
        blob.data[index] = input[index] ^ stream;
        stream = prng(stream);
    }
    return blob;
}

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData)
{
    if (!pData) {
        pData->hMod = (HINSTANCE)0x404040;
        return;
    }

    BYTE* pBase = pData->pbase;
    auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
    auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif // _WIN64
    auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

    BYTE* LocationDelta = pBase - pOpt->ImageBase;
    if (LocationDelta) {
        if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
            auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
            while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
                UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

                for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
                    if (RELOC_FLAG(*pRelativeInfo)) {
                        UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                        *pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
                    }
                }
                pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
            }
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDescr->Name) {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);

            ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

            if (!pThunkRef)
                pThunkRef = pFuncRef;

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
                }
                else {
                    auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDescr;
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback)
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, NULL);
    }

    bool ExceptionSupportFailed = false;

#ifdef _WIN64
    if (pData->SEHSupport) {
        auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excep.Size) {
            if (!_RtlAddFunctionTable(
                reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
                excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
                ExceptionSupportFailed = true;
            }
        }
    }
#endif // _WIN64

    _DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

    if (ExceptionSupportFailed)
        pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
    else
        pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}

//Note: Exception support only x64 with build params /EHa or /EHc
bool manual_map_dll(HANDLE hProc, BYTE* pSrcData, bool ClearHeader = true, bool ClearNonNeededSections = true, bool AdjustProtections = true,
                  bool SEHExceptionSupport = true, DWORD fdwReason = DLL_PROCESS_ATTACH, LPVOID lpReserved = 0);

bool manual_map_dll(HANDLE hProc, BYTE* pSrcData, bool ClearHeader, bool ClearNonNeededSections, bool AdjustProtections,
                    bool SEHExceptionSupport, DWORD fdwReason, LPVOID lpReserved)
{
    IMAGE_NT_HEADERS* pOldNtHeader = NULL;
    IMAGE_OPTIONAL_HEADER* pOldOptHeader = NULL;
    IMAGE_FILE_HEADER* pOldFileHeader = NULL;
    BYTE* pTargetBase = NULL;

    if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) {
        log_error("Invalid file format");
        return false;
    }

    pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
    pOldOptHeader = &pOldNtHeader->OptionalHeader;
    pOldFileHeader = &pOldNtHeader->FileHeader;

    if (pOldFileHeader->Machine != CURRENT_ARCH) {
        log_error("Invalid platform");
        return false;
    }

    pTargetBase = reinterpret_cast<BYTE*>(_VirtualAllocEx(hProc, NULL, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pTargetBase) {
        log_error("Target process memory allocation failed 0x%X", _GetLastError());
        return false;
    }

    DWORD oldp = 0;
    _VirtualProtectEx(hProc, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

    MANUAL_MAPPING_DATA data {0};
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
    data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else 
    SEHExceptionSupport = false;
#endif // _WIN64
    data.pbase = pTargetBase;
    data.fdwReasonParam = fdwReason;
    data.reservedParam = lpReserved;
    data.SEHSupport = SEHExceptionSupport;

    if (!_WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, NULL)) {
        log_error("Couldn't write file header 0x%X", _GetLastError());
        _VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
    for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            if (!_WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, NULL)) {
                log_error("Couldn't map sections: 0x%X", _GetLastError());
                _VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
                return false;
            }
        }
    }

    BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(_VirtualAllocEx(hProc, NULL, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!MappingDataAlloc) {
        log_error("Target process mapping allocation failed 0x%X", _GetLastError());
        _VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    if (!_WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), NULL)) {
        log_error("Couldn't write mapping 0x%X", _GetLastError());
        _VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        _VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        return false;
    }

    void* pShellcode = _VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcode) {
        log_error("Memory shellcode allocation failed 0x%X", _GetLastError());
        _VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        _VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        return false;
    }

    if (!_WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, NULL)) {
        log_error("Couldn't write shellcode 0x%X", _GetLastError());
        _VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        _VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        _VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }

    log_info("Mapped at %p", pTargetBase);
    log_info("Mapping info at %p", MappingDataAlloc);
    log_info("Shellcode at %p", pShellcode);

    HANDLE hThread = _CreateRemoteThread(hProc, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, NULL);
    if (!hThread) {
        log_error("Thread creation failed 0x%X", _GetLastError());
        _VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        _VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        _VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }
    _CloseHandle(hThread);

    log_info("Thread created at: %p, waiting for return.", pShellcode);

    HINSTANCE hCheck = NULL;
    while (!hCheck) {
        DWORD exitcode = 0;
        GetExitCodeProcess(hProc, &exitcode);
        if (exitcode != STILL_ACTIVE) {
            log_error("Process crashed, exit code: %d", exitcode);
            return false;
        }

        MANUAL_MAPPING_DATA data_checked {0};
        _ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), NULL);
        hCheck = data_checked.hMod;

        if (hCheck == (HINSTANCE)0x404040) {
            log_error("Wrong mapping ptr");
            _VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
            _VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
            _VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
            return false;
        }
        else if (hCheck == (HINSTANCE)0x505050) {
            log_warn("Exception support failed");
        }
        Sleep(10);
    }

    BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
    if (emptyBuffer == NULL) {
        log_error("Unable to allocate memory");
        return false;
    }
    SecureZeroMemory(emptyBuffer, 1024 * 1024 * 20);

    if (ClearHeader) {
        if (!_WriteProcessMemory(hProc, pTargetBase, emptyBuffer, 0x1000, NULL)) {
            log_warn("Couldn't clear header");
        }
    }

    if (ClearNonNeededSections) {
        auto pdata_s = mks(".pdata");
        auto rsrc_s = mks(".rsrc");
        auto reloc_s = mks(".reloc");
        pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
        for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->Misc.VirtualSize) {
                if ((SEHExceptionSupport ? 0 : strcmp((char*)pSectionHeader->Name, pdata_s.c_str()) == 0) ||
                    strcmp((char*)pSectionHeader->Name, rsrc_s.c_str()) == 0 ||
                    strcmp((char*)pSectionHeader->Name, reloc_s.c_str()) == 0) {
                    log_info("Clearing %s", pSectionHeader->Name);
                    if (!_WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, NULL)) {
                        log_error("Couldn't clear section %s: 0x%X", pSectionHeader->Name, _GetLastError());
                    }
                }
            }
        }
    }

    if (AdjustProtections) {
        pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
        for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->Misc.VirtualSize) {
                DWORD old = 0;
                DWORD newP = PAGE_READONLY;

                if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
                    newP = PAGE_READWRITE;
                }
                else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
                    newP = PAGE_EXECUTE_READ;
                }
                if (_VirtualProtectEx(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old)) {
                    log_info("Section %s set as %lX", (char*)pSectionHeader->Name, newP);
                }
                else {
                    log_error("Section %s not set as %lX", (char*)pSectionHeader->Name, newP);
                }
            }
        }
        DWORD old = 0;
        _VirtualProtectEx(hProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
    }

    if (!_WriteProcessMemory(hProc, pShellcode, emptyBuffer, 0x1000, NULL)) {
        log_warn("Couldn't clear shellcode");
    }
    if (!_VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE)) {
        log_warn("Couldn't release shell code memory");
    }
    if (!_VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE)) {
        log_warn("Couldn't release mapping data memory");
    }

    return true;
}

static inline bool is_correct_target_arch(HANDLE hProc)
{
    BOOL bTarget = FALSE;
    if (!_IsWow64Process(hProc, &bTarget))
        return false;
    BOOL bHost = FALSE;
    _IsWow64Process(_GetCurrentProcess(), &bHost);
    return (bTarget == bHost);
}

static inline DWORD get_process_id(const wchar_t *process_name)
{
    DWORD process_id = 0;
    HANDLE hSnap = _CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (_Process32FirstW(hSnap, &procEntry))
        {
            do
            {
                if (!_wcsicmp(procEntry.szExeFile, process_name))
                {
                    process_id = procEntry.th32ProcessID;
                    break;
                }
            } while (_Process32NextW(hSnap, &procEntry));
        }
    }
    _CloseHandle(hSnap);
    return process_id;
}

// Get process ID from PID input directly
static inline DWORD get_process_id_from_input()
{
    DWORD pid = 0;
    std::cout << "Enter process ID (PID): ";
    std::cin >> pid;
    return pid;
}

// Get process name from list of processes
static inline std::wstring select_process_from_list()
{
    HANDLE hSnap = _CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    std::vector<std::pair<DWORD, std::wstring>> processes;
    
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (_Process32FirstW(hSnap, &procEntry))
        {
            int index = 0;
            do
            {
                processes.push_back({procEntry.th32ProcessID, std::wstring(procEntry.szExeFile)});
                std::wcout << index << ": " << procEntry.szExeFile << " (PID: " << procEntry.th32ProcessID << ")" << std::endl;
                index++;
            } while (_Process32NextW(hSnap, &procEntry));
        }
    }
    _CloseHandle(hSnap);
    
    int selection = -1;
    std::cout << "Select a process by number: ";
    std::cin >> selection;
    
    if(selection >= 0 && selection < processes.size())
    {
        std::cout << "Selected: " << processes[selection].second.c_str() << " (PID: " << processes[selection].first << ")" << std::endl;
        return processes[selection].second;
    }
    
    return L"";
}

// Get DLL path from user
static inline std::wstring get_dll_path_from_user()
{
    std::wstring path;
    std::wcout << "Enter DLL path: ";
    std::wcin >> path;
    return path;
}

// Get process ID by window class name
static inline DWORD get_process_id_by_window_class(const char* window_class_name)
{
    DWORD thread_id = 0;
    DWORD process_id = 0;
    
    while (!process_id)
    {
        thread_id = GetWindowThreadProcessId(FindWindowA(window_class_name, NULL), &process_id); 
        if (process_id == 0) {
            Sleep(20);
        }
    } 
    
    return process_id;
}

// Driver-based manual mapping
bool manual_map_dll_with_driver(DWORD process_id, BYTE* pSrcData, bool ClearHeader = true, bool ClearNonNeededSections = true)
{
    if (!driver().is_loaded()) {
        log_error("Driver not loaded, falling back to standard injection");
        // Fall back to standard injection if driver isn't available
        HANDLE hProc = _OpenProcess(PROCESS_ALL_ACCESS, 0, process_id);
        if (hProc == NULL) {
            log_error("Couldn't open process: 0x%X", _GetLastError());
            return false;
        }
        
        bool result = manual_map_dll(hProc, pSrcData, ClearHeader, ClearNonNeededSections, true, true, DLL_PROCESS_ATTACH, NULL);
        _CloseHandle(hProc);
        return result;
    }
    
    IMAGE_NT_HEADERS* pOldNtHeader = NULL;
    
    if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) {
        log_error("Invalid file format");
        return false;
    }

    pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
    
    if (pOldNtHeader->FileHeader.Machine != CURRENT_ARCH) {
        log_error("Invalid platform");
        return false;
    }
    
    // Attach to the target process
    driver().attach_process(process_id);
    
    // Allocate memory in the target process
    PVOID allocate_base = driver().alloc_memory_ex(pOldNtHeader->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);
    if (!allocate_base) {
        log_error("Failed to allocate memory in target process");
        return false;
    }
    
    log_info("Allocated base: 0x%p", allocate_base);
    
    // Write PE header
    if (driver().write_memory_ex(allocate_base, pSrcData, 0x1000) >= 0) {
        log_info("Successfully wrote PE header");
    } else {
        log_error("Failed to write PE header");
        driver().free_memory_ex(allocate_base);
        return false;
    }
    
    // Write sections
    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
    for (UINT i = 0; i < pOldNtHeader->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            if (driver().write_memory_ex(
                (PVOID)((uintptr_t)allocate_base + pSectionHeader->VirtualAddress),
                (PVOID)((uintptr_t)pSrcData + pSectionHeader->PointerToRawData),
                pSectionHeader->SizeOfRawData) >= 0) {
                log_info("Wrote section %s", pSectionHeader->Name);
            } else {
                log_error("Failed to write section %s", pSectionHeader->Name);
                driver().free_memory_ex(allocate_base);
                return false;
            }
        }
    }
    
    // Create a remote thread to execute DllMain
    PVOID loadLibraryAddr = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    
    // Adjust protections for sections
    if (ClearHeader) {
        BYTE* emptyBuffer = (BYTE*)malloc(0x1000);
        if (emptyBuffer) {
            SecureZeroMemory(emptyBuffer, 0x1000);
            driver().write_memory_ex(allocate_base, emptyBuffer, 0x1000);
            free(emptyBuffer);
        }
    }
    
    if (ClearNonNeededSections) {
        BYTE* emptyBuffer = (BYTE*)malloc(0x100000); // 1MB buffer
        if (emptyBuffer) {
            SecureZeroMemory(emptyBuffer, 0x100000);
            
            pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
            for (UINT i = 0; i < pOldNtHeader->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
                if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) > 0) {
                    if (driver().write_memory_ex(
                        (PVOID)((uintptr_t)allocate_base + pSectionHeader->VirtualAddress),
                        emptyBuffer,
                        pSectionHeader->SizeOfRawData) >= 0) {
                        log_info("Cleared section %s", pSectionHeader->Name);
                    }
                }
            }
            
            free(emptyBuffer);
        }
    }
    
    log_info("Driver-based manual mapping complete, entry point at %p", 
        (PVOID)((uintptr_t)allocate_base + pOldNtHeader->OptionalHeader.AddressOfEntryPoint));
    
    return true;
}

int wmain(int argc, wchar_t **argv, wchar_t **envp)
{
    auto sKernel32Dll(mks("Kernel32.dll"));
    auto sAdvapi32Dll(mks("Advapi32.dll"));
    auto k32 = GetModuleHandleA(sKernel32Dll.c_str());
    auto a32 = LoadLibraryA(sAdvapi32Dll.c_str());
    k32func(CreateToolhelp32Snapshot);
    k32func(GetFullPathNameW);
    k32func(GetLastError);
    k32func(Process32FirstW);
    k32func(Process32NextW);
    k32func(CloseHandle);
    k32func(OpenProcess);
    k32func(VirtualAllocEx);
    k32func(VirtualProtectEx);
    k32func(VirtualFreeEx);
    k32func(WriteProcessMemory);
    k32func(ReadProcessMemory);
    k32func(CreateRemoteThread);
    k32func(LoadLibraryW);
    k32func(IsWow64Process);
    k32func(GetCurrentProcess);
    a32func(OpenProcessToken);
    a32func(LookupPrivilegeValueW);
    a32func(AdjustTokenPrivileges);

    // Default values
    auto process_name_s = mks("osu!.exe");
    auto process_name_w = std::wstring(process_name_s.begin(), process_name_s.end());
#ifdef _WIN64
    auto dll_name_s = mks("SSSISANIGGER-lazer.dll");
#else
    auto dll_name_s = mks("SSSISANIGGER.dll");
#endif // _WIN64
    auto dll_name_w = std::wstring(dll_name_s.begin(), dll_name_s.end());

    bool use_driver = false;
    bool use_window_class = false;
    bool select_process_from_list_flag = false;
    bool use_pid_directly = false;
    bool use_manual_dll_path = false;
    char* window_class_name = NULL;
    DWORD process_id = 0;
    
    // Initialize driver
    if (init_driver()) {
        std::cout << "Driver loaded successfully" << std::endl;
        use_driver = true;
    } else {
        std::cout << "Driver not loaded, using standard injection" << std::endl;
    }

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--help") == 0 || wcscmp(argv[i], L"-h") == 0) {
            std::cout << "Usage: injector.exe [options]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  --help, -h           Show this help message" << std::endl;
            std::cout << "  --process, -p NAME   Specify process name" << std::endl;
            std::cout << "  --dll, -d PATH       Specify DLL path" << std::endl;
            std::cout << "  --pid, -i PID        Specify process ID directly" << std::endl;
            std::cout << "  --class, -c NAME     Specify window class name" << std::endl;
            std::cout << "  --list, -l           Select process from list" << std::endl;
            std::cout << "  --driver, -r         Force use of driver (if available)" << std::endl;
            return 0;
        } else if ((wcscmp(argv[i], L"--process") == 0 || wcscmp(argv[i], L"-p") == 0) && i + 1 < argc) {
            process_name_w = argv[i + 1];
            i++;
        } else if ((wcscmp(argv[i], L"--dll") == 0 || wcscmp(argv[i], L"-d") == 0) && i + 1 < argc) {
            dll_name_w = argv[i + 1];
            use_manual_dll_path = true;
            i++;
        } else if ((wcscmp(argv[i], L"--pid") == 0 || wcscmp(argv[i], L"-i") == 0) && i + 1 < argc) {
            process_id = _wtoi(argv[i + 1]);
            use_pid_directly = true;
            i++;
        } else if ((wcscmp(argv[i], L"--class") == 0 || wcscmp(argv[i], L"-c") == 0) && i + 1 < argc) {
            // Convert wide string to char* for window class
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, argv[i + 1], -1, NULL, 0, NULL, NULL);
            window_class_name = new char[size_needed];
            WideCharToMultiByte(CP_UTF8, 0, argv[i + 1], -1, window_class_name, size_needed, NULL, NULL);
            use_window_class = true;
            i++;
        } else if (wcscmp(argv[i], L"--list") == 0 || wcscmp(argv[i], L"-l") == 0) {
            select_process_from_list_flag = true;
        } else if (wcscmp(argv[i], L"--driver") == 0 || wcscmp(argv[i], L"-r") == 0) {
            if (use_driver) {
                std::cout << "Will use driver for injection" << std::endl;
            } else {
                std::cout << "Driver not available, using standard injection" << std::endl;
            }
        }
    }
    
    // Interactive process selection if requested
    if (select_process_from_list_flag) {
        std::wstring selected = select_process_from_list();
        if (!selected.empty()) {
            process_name_w = selected;
        } else {
            std::cout << "No valid process selected" << std::endl;
            return 1;
        }
    }
    
    // Get process ID based on the method chosen
    if (use_pid_directly) {
        if (process_id == 0) {
            process_id = get_process_id_from_input();
        }
    } else if (use_window_class) {
        process_id = get_process_id_by_window_class(window_class_name);
    } else {
        const wchar_t *process_name = process_name_w.c_str();
        process_id = get_process_id(process_name);
    }
    
    // Clean up window class name if allocated
    if (window_class_name) {
        delete[] window_class_name;
    }
    
    if (process_id == 0) {
        log_error("Failed to get process id: launch %S first!", process_name_w.c_str());
        return 1;
    }
    
    std::cout << "Targeting process ID: " << process_id << std::endl;
    
    // Interactive DLL path selection if requested
    if (use_manual_dll_path && dll_name_w.empty()) {
        dll_name_w = get_dll_path_from_user();
    }

    TOKEN_PRIVILEGES priv = {0};
    HANDLE hToken = NULL;
    if (_OpenProcessToken(_GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (_LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
            _AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

        _CloseHandle(hToken);
    }

    // If using driver, use the driver-based injection
    if (use_driver) {
        // Process DLL path 
        const wchar_t *dll_name = dll_name_w.c_str();
        static wchar_t module_path[MAX_PATH * 2];
        DWORD module_path_length = _GetFullPathNameW(dll_name, MAX_PATH * 2, module_path, NULL);
        
        if (module_path_length == 0) {
            log_error("Failed to retrieve the full path and file name of the dll. (0x%X)", _GetLastError());
            return 1;
        }

        if (!file_exists(module_path)) {
            log_error("File %S doesn't exist", module_path);
            return 1;
        }

        File module_file = open_file(module_path, FR_READ_ONLY);
        if (!map_file(&module_file)) {
            log_error("Couldn't map module file");
            close_file(module_file.handle);
            return 1;
        }
        
        if (manual_map_dll_with_driver(process_id, (BYTE*)module_file.start)) {
            std::cout << "Driver-based injection successful" << std::endl;
        } else {
            std::cout << "Driver-based injection failed" << std::endl;
        }
        
        unmap_file(module_file);
        close_file(module_file.handle);
    } else {
        // Standard injection as before
        HANDLE hProc = _OpenProcess(PROCESS_ALL_ACCESS, 0, process_id);
        if (hProc == NULL) {
            log_error("Couldn't open process: 0x%X", _GetLastError());
            return 1;
        }

        if (!is_correct_target_arch(hProc)) {
            log_error("Couldn't confirm target process architecture: 0x%X", _GetLastError());
            _CloseHandle(hProc);
            return 1;
        }

        const wchar_t *dll_name = dll_name_w.c_str();
        static wchar_t module_path[MAX_PATH * 2];
        DWORD module_path_length = _GetFullPathNameW(dll_name, MAX_PATH * 2, module_path, NULL);
        if (module_path_length == 0) {
            log_error("Failed to retrieve the full path and file name of the dll. (0x%X)", _GetLastError());
            _CloseHandle(hProc);
            return 1;
        }

        if (!file_exists(module_path)) {
            log_error("File %S doesn't exist", module_path);
            _CloseHandle(hProc);
            return 1;
        }

        File module_file = open_file(module_path, FR_READ_ONLY);
        if (!map_file(&module_file)) {
            log_error("Couldn't map module file");
            close_file(module_file.handle);
            _CloseHandle(hProc);
            return 1;
        }

        LPVOID config_path = _VirtualAllocEx(hProc, NULL, sizeof(module_path), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!config_path)
            log_warn("Couldn't allocate config path 0x%X", _GetLastError());
        else if (!_WriteProcessMemory(hProc, config_path, module_path, sizeof(module_path), NULL))
            log_warn("Couldn't write config path 0x%X", _GetLastError());

        manual_map_dll(hProc, (BYTE *)module_file.start, true, true, true, true, DLL_PROCESS_ATTACH, config_path);

        unmap_file(module_file);
        close_file(module_file.handle);

        _CloseHandle(hProc);
    }
    
    // Add this near the end of wmain before returning
    if (use_driver) {
        cleanup_driver();
    }
    
    return 0;
}
