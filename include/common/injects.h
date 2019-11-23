#pragma once

typedef DWORD(WINAPI *typeFuncThread)(LPVOID);
typedef SIZE_T(*typeInjectCode)(HANDLE hprocess, typeFuncThread startFunc, HMODULE* newBaseImage);
typedef bool(*typeRunInjectCode)(HANDLE hprocess, HANDLE hthread, typeFuncThread startFunc, typeInjectCode func);


namespace Injects
{

	
	bool IntoProcess2(DWORD pid, typeFuncThread func);
}
