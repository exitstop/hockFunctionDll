// pch.cpp: файл исходного кода, соответствующий предварительно скомпилированному заголовочному файлу

#include "pch.h"

#include <string>
#include <iostream>
#include <algorithm>
#include <deque>
#include <iomanip>
#include <sstream>

// При использовании предварительно скомпилированных заголовочных файлов необходим следующий файл исходного кода для выполнения сборки.
std::string hexToString(uint32_t h)
{
	std::deque<uint8_t> lbyte;
	while (h) {
		lbyte.push_front(h & 0xff);
		h >>= 8;
	}
	std::ostringstream oss;
	for (uint8_t i : lbyte)
		oss << std::hex << std::setfill('0') << std::setw(2) << (int)i;
	std::string hex = oss.str();
	return oss.str();
}


MODULEENTRY32 ListProcessModules(DWORD dwPID, std::wostringstream& out)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32{ 0 };

	//  Take a snapshot of all modules in the specified process. 
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		//printError(TEXT("CreateToolhelp32Snapshot (of modules)"));
		return me32;
	}

	//  Set the size of the structure before using it. 
	me32.dwSize = sizeof(MODULEENTRY32);

	//  Retrieve information about the first module, 
	//  and exit if unsuccessful 
	if (!Module32First(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);     // Must clean up the snapshot object! 
		return me32;
	}

	do
	{
		std::wstring name = me32.szModule;
		std::transform(name.begin(), name.end(), name.begin(), ::toupper);
		if (wcscmp(name.c_str(), L"LIBCEF.DLL") == 0) {
			out << me32.szModule << std::endl;
			out << me32.szExePath << std::endl;
			out << "0x" << hexToString(me32.th32ProcessID).c_str() << std::endl;
			out << "0x" << hexToString(me32.GlblcntUsage).c_str() << std::endl;
			out << "0x" << hexToString(me32.ProccntUsage).c_str() << std::endl;
			out << "0x" << hexToString((uint32_t)me32.modBaseAddr).c_str() << std::endl;
			out << "0x" << hexToString(me32.modBaseSize).c_str() << std::endl;
			break;
		}

	} while (Module32Next(hModuleSnap, &me32));

	//  Do not forget to clean up the snapshot object. 
	CloseHandle(hModuleSnap);
	return me32;
}

PVOID WINAPI GetFunctionAddress(LPCTSTR DllName, LPCSTR FunctionName, BOOL LoadDll)
{
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_EXPORT_DIRECTORY pIED;

	HMODULE hModule;
	PDWORD Address, Name;
	PWORD Ordinal;

	DWORD i;

	if (LoadDll)
	{
		hModule = LoadLibrary(DllName);
	}

	else
	{
		hModule = GetModuleHandle(DllName);
	}

	if (!hModule)
	{
		return NULL;
	}

	pIDH = (PIMAGE_DOS_HEADER)hModule;

	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pIDH->e_lfanew);

	if (pINH->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		return NULL;
	}

	pIED = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	Address = (PDWORD)((LPBYTE)hModule + pIED->AddressOfFunctions);
	Name = (PDWORD)((LPBYTE)hModule + pIED->AddressOfNames);

	Ordinal = (PWORD)((LPBYTE)hModule + pIED->AddressOfNameOrdinals);

	for (i = 0; i < pIED->AddressOfFunctions; i++)
	{
		if (!strcmp(FunctionName, (char*)hModule + Name[i]))
		{
			return (PVOID)((LPBYTE)hModule + Address[Ordinal[i]]);
		}
	}

	return NULL;
}