// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"

#include <cstdint>
#include <sstream>
#include <iostream>
#include <string>
#include <array>
#include <algorithm>

bool Hook(void* toHook, void* ourFunct, int len) {
	if (len < 5) {
		return false;
	}

	DWORD curProtection;
	VirtualProtect(toHook, len, PAGE_EXECUTE_READWRITE, &curProtection);

	memset(toHook, 0x90, len);

	DWORD relativeAddress = ((DWORD)ourFunct - (DWORD)toHook) - 5;

	*(BYTE*)toHook = 0xE9;
	*(DWORD*)((DWORD)toHook + 1) = relativeAddress;

	DWORD temp;
	VirtualProtect(toHook, len, curProtection, &temp);

	return true;
}

DWORD jmpBackAddy;
wchar_t* stackChar;

void muFunc()
{	
	std::wostringstream out(L"");
	std::wstring wstr = static_cast<const wchar_t*>(stackChar);

	auto result0 = wstr.find(L"allThreatsFound");

	if (result0 != std::wstring::npos) {
		auto result1 = wstr.find(L":", result0);
		auto result2 = wstr.find(L",", result1);

		if ((result2 - result1) < 0) {
			out << __FILE__ << ":" << __LINE__ << "\n" << " error find string: (result2 - result1) < 0;" << std::endl;
			MessageBox(NULL, static_cast<LPCWSTR>(std::wstring(out.str()).c_str()), L"Injected Dll", MB_OKCANCEL);
			return;
		}
		std::wstring countVirus(L"", result2 - result1);
		
		std::copy(wstr.begin() + result1, wstr.begin() + result2, countVirus.begin());		
		out << "found virus: " << countVirus << std::endl;
		MessageBox(NULL, static_cast<LPCWSTR>(std::wstring(out.str()).c_str()), L"Injected Dll", MB_OKCANCEL);
	}	
}

void __declspec(naked) ourFunct() 
{
	
	__asm {
		push eax
		mov eax, [esp + 8]
		cmp eax, 0
		jz mak0
		mov eax, [eax]
	mak0:
		mov[stackChar], eax
		pop eax
	}
	if (stackChar) {
		muFunc();	
	}
	__asm {
		
		push ebp
		mov ebp, esp
		sub esp, 0x0C
		jmp[jmpBackAddy]
	}
	
}


DWORD WINAPI MainThread(LPVOID param) 
{	
	// Получаем адрес функции жертвы
	uint8_t *hModule = (uint8_t*)GetFunctionAddress(L"libcef.dll", "cef_v8value_create_string", false);

	const size_t hookLength = 6;
	jmpBackAddy = (size_t)hModule + hookLength;

	Hook(hModule,ourFunct, hookLength);
	//FreeLibraryAndExitThread((HMODULE)param, 0);

	return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//CreateThread(0, 0, MainThread, hModule, 0, 0);
		MainThread(0);

		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}


