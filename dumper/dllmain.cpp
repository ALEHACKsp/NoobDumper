#include <cstdio>
#include <fstream>
#include "hook32.h" //include hook
#include "spoof.h"

#ifdef _WIN64
LPCSTR caption = "Dumper x64";
#elif _WIN32
LPCSTR caption = "Dumper x86";
#endif

typedef BOOL(WINAPI* tWriteProcessMemory) (HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesWritten);
tWriteProcessMemory oWriteProcessMemory = nullptr;
//int i = 0;
BOOL WINAPI hkWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesWritten)
{
	//i++;
	char bufferPath[1337] = "dump.bin";
	DWORD dwNumRead = 0;

	//sprintf(bufferPath, "E:\\Desktop\\ManualMap-master\\Release\\file%d.bin", i);

	FILE * fp = fopen(bufferPath, "a+");
	if (fp) {
		fwrite(lpBuffer, nSize, nSize, fp);
		fclose(fp);
	}
	//if (i == 3)ExitProcess(1337);

	return oWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		HMODULE Kernel32 = GetModuleHandleA("kernel32");
		char* WPMAddy = (char*)GetProcAddress(Kernel32, "WriteProcessMemory");

		oWriteProcessMemory = (tWriteProcessMemory)TrampHook32(WPMAddy, (char*)hkWriteProcessMemory, 5);
		TrampHook32((char*)oWriteProcessMemory, (char*)hkWriteProcessMemory, 5);

		Spoof_Identifiers(); //maybe not even required, addons.
		MessageBoxA(NULL, "Hooks and spoofs initialized!", caption, NULL);
	}
    return TRUE;
}

