namespace drivers
{
	MYLOG driver_running;
	bool open_log_driver_running;

}

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

void list_drivers()
{

	NTSTATUS status;
	PRTL_PROCESS_MODULES ModuleInfo;

	typedef NTSTATUS(NTAPI* pfnNtQuerySystemInformation)(int SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

	DWORD_PTR Addr_NtQuerySystemInformation = (DWORD_PTR)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	pfnNtQuerySystemInformation oNtQuerySystemInformation = (pfnNtQuerySystemInformation)Addr_NtQuerySystemInformation;

	if (!oNtQuerySystemInformation)
	{
		return;
	}

	ModuleInfo = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!ModuleInfo)
	{
		drivers::driver_running.AddLog("[driver] Unable to allocate memory for module list (%d)\n", GetLastError());
		return;
	}

	status = oNtQuerySystemInformation(11, ModuleInfo, 1024 * 1024, NULL);

	if (status != 0x0)
	{
		drivers::driver_running.AddLog("[driver] Error: Unable to query module list (%#x)\n", status);
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		return;
	}


	for (ULONG i = 0; i < ModuleInfo->NumberOfModules; i++)
	{
		drivers::driver_running.AddLog("[%i] name: %s base: %p size: %X\n",i,  ModuleInfo->Modules[i].FullPathName, ModuleInfo->Modules[i].ImageBase, ModuleInfo->Modules[i].ImageSize);
	}

	VirtualFree(ModuleInfo, 0, MEM_RELEASE);

	return;
}

void draw_drivers_tab()
{

	if (ImGui::Button("list drivers"))
	{
		drivers::driver_running.Clear();
		drivers::open_log_driver_running = 1;
		list_drivers();
	}

	if (drivers::open_log_driver_running)
		drivers::driver_running.Draw("drivers running", &drivers::open_log_driver_running);
}