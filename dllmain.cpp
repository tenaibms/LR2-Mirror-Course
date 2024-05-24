#include <windows.h>
#include <safetyhook.hpp>
#include <iostream>
#include <format>
#include <print>
#include "dllmain.h"

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) 
{
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(instance);
		CreateThread(NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(ThreadMain), NULL, NULL, NULL);
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		if (reserved != nullptr) {
			break;
		}
		// Perform cleanup here if necessary
		break;
	}

	return TRUE;
}

SafetyHookMid mirror_hook;
SafetyHookMid reset_hook;

namespace offsets {
	uintptr_t current_opt = 0x0FF848;
	uintptr_t mirror = 0x433A5A;
}

void __stdcall ThreadMain(HINSTANCE instance)
{
#if _DEBUG
	AllocConsole();
	freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
#endif

	// Because the second instruction is called expecting an ebx with zero, we must make two hooks
	// One to set ebx to the correct value if mirrored, and the next to reset ebx to zero 

	/*
	 * .text:00433A5A 89 9C 24 C8 00 00+                mov     [esp+0A0740h+var_A0678], ebx	// Sets current option to nonran
	 * .text:00433A61 89 9C 24 CC 00 00+                mov     [esp+0A0740h+var_A0674], ebx	// Sets something else(?) that expects a value of zero
	*/

	mirror_hook = safetyhook::create_mid(reinterpret_cast<void*>(offsets::mirror), [](safetyhook::Context& ctx){
		int current_opt = *reinterpret_cast<int*>(offsets::current_opt);
		current_opt == 1 ? ctx.ebx  = current_opt : ctx.ebx = 0;
#if _DEBUG
		std::print("EBX: {} Current Opt: {}\n", ctx.ebx, current_opt);
#endif
	});

	reset_hook = safetyhook::create_mid(reinterpret_cast<void*>(offsets::mirror + 7), [](safetyhook::Context& ctx) {
		ctx.ebx = 0;
#if _DEBUG
		std::print("EBX: {}\n", ctx.ebx);
#endif
	});
}
