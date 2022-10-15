#include <iostream>
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <thread>
#include <stdio.h>
#include <string>
#include <Wininet.h>
#include <D3dx9tex.h>
#include <vector>
#include <TlHelp32.h>
#include <strsafe.h>
#include <fstream>
#include <tchar.h>
#include <d3d9.h>
#include <Psapi.h>
#include <map>
#include <array>
#include <comdef.h>
#include <Wbemidl.h>
#include <thread>

#include <iphlpapi.h>

#include <algorithm>
#include <stdexcept>

#include <stdint.h>
#include <stdlib.h>

#include <atlimage.h>

#include <winternl.h>

#include "gdiplus.h"


#pragma comment(lib, "Gdiplus.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "psapi.lib")
//#pragma comment(lib, "D3dx9")
#pragma comment(lib,"d3d9.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")//
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")


using namespace std;

#include "imgui-docking/imgui.h"
#include "imgui-docking/imgui_impl_dx9.h"
#include "imgui-docking/imgui_impl_win32.h"

#pragma region hde

#if defined(HWBP_X86)
#include "hde/hde32/include/hde32.h"

using hde_t = hde32s;

inline auto hde_disasm(void* p, hde_t* hde) {
	return hde32_disasm(p, hde);
}

#else
#include "hde/hde64/include/hde64.h"

using hde_t = hde64s;

inline auto hde_disasm(void* p, hde_t* hde) {
	return hde64_disasm(p, hde);
}

#endif
#pragma endregion

#include "nmd-master/nmd-master/nmd_assembly.h"

#include "global.h"
#include "eat_hook.h"
#include "utils.h"
#include "process.h"
#include "modules.h"
#include "bitset.h"
#include "thread.h"
#include "hardware_breakpoint.h"
#include "scan.h"
#include "dump.h"
#include "pattern.h"
#include "drivers.h"

//#define NO_VMP1
