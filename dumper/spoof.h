#pragma once
#include <Windows.h>
#include "hook32.h"
typedef UINT(WINAPI* tGetSystemFirmwareTable)(_In_ DWORD FirmwareTableProviderSignature, _In_ DWORD FirmwareTableID, _Out_writes_bytes_to_opt_(BufferSize, return) PVOID pFirmwareTableBuffer, _In_ DWORD BufferSize);
tGetSystemFirmwareTable oGetSystemFirmwareTable = nullptr;
typedef VOID(WINAPI* tGetSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
tGetSystemInfo oGetSystemInfo = nullptr;

auto  Kernel32					 =		  GetModuleHandleA("kernel32");
char* GetSystemFirmwareTableAdr	 = (char*)GetProcAddress(Kernel32, "GetSystemFirmwareTable");
char* GetSystemInfoAdr			 = (char*)GetProcAddress(Kernel32, "GetSystemInfo");

VOID WINAPI hkGetSystemInfo(LPSYSTEM_INFO lpSystemInfo)
{
	lpSystemInfo->dwPageSize = 0x1337;
	lpSystemInfo->dwProcessorType = 0xdead;
	lpSystemInfo->wProcessorArchitecture = 0x69;

	oGetSystemInfo(lpSystemInfo);
}

UINT WINAPI hkGetSystemFirmwareTable(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize) {

	FirmwareTableProviderSignature = 0x1337;
	FirmwareTableID = 0x1337;
	pFirmwareTableBuffer = NULL;
	BufferSize = 0;

	return oGetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID, pFirmwareTableBuffer, BufferSize);
}
void Spoof_Identifiers() {
	

	oGetSystemFirmwareTable = (tGetSystemFirmwareTable)TrampHook32(GetSystemFirmwareTableAdr, (char*)hkGetSystemFirmwareTable, 5);
	TrampHook32((char*)oGetSystemFirmwareTable, (char*)hkGetSystemFirmwareTable, 5);

	oGetSystemInfo = (tGetSystemInfo)TrampHook32(GetSystemInfoAdr, (char*)hkGetSystemInfo, 5);
	TrampHook32((char*)oGetSystemInfo, (char*)hkGetSystemInfo, 5);

}
