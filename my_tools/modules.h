namespace modules
{
	bool get_module_info_from_process_by_pid(DWORD ProcessId, const char* ModuleName, PMODULEENTRY32 module_info, bool IsWow64);
	vector<MODULEINFO>list_module_info(HANDLE hProcess);
	MODULEINFO get_module_info(HANDLE hProcess, DWORD_PTR module_base);
	char* get_module_name(HANDLE hProcess, HMODULE module);
	MODULEINFO get_module_info_by_name(HANDLE hProcess, const char* module_name);
}

vector<MODULEINFO>modules::list_module_info(HANDLE hProcess)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;
	vector<MODULEINFO>module_info_vec;
	if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
	{
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];
			MODULEINFO ModuleInfo;
						
			if (GetModuleInformation(hProcess, hMods[i], &ModuleInfo, sizeof(ModuleInfo)))
				module_info_vec.push_back(ModuleInfo);
		}
	}	

	return module_info_vec;
}

MODULEINFO modules::get_module_info(HANDLE hProcess, DWORD_PTR module_base)
{
	vector<MODULEINFO>list_module = list_module_info(hProcess);
	for (auto modules : list_module)
	{
		if (modules.lpBaseOfDll == reinterpret_cast<LPVOID>(module_base))
			return modules;
	}
}

MODULEINFO modules::get_module_info_by_name(HANDLE hProcess, const char* module_name1)
{
	

	vector<MODULEINFO>modules_r = modules::list_module_info(hProcess);
	if (modules_r.empty())
	{
		utils::WriteLog("[-] failed to get list of modules %X...\n", GetLastError());
		//return module_info;
	}

	for (auto item : modules_r)
	{		

		char * module_name = modules::get_module_name(hProcess, (HMODULE)item.lpBaseOfDll);
		if (!module_name)
		{
			utils::WriteLog("[-] failed to get module name...\n");
			continue;
		}
		
		if (utils::strcontain(module_name, module_name1))			
			return item;	

	}
	utils::WriteLog("[-] not found\n");
}

char* modules::get_module_name(HANDLE hProcess, HMODULE module)
{
	char module_name[MAX_PATH];
	if (GetModuleFileNameExA(hProcess, module, module_name, sizeof(module_name)))
	{
		return module_name;
	}
	return NULL;
	
}

bool modules::get_module_info_from_process_by_pid(DWORD ProcessId, const char* ModuleName, PMODULEENTRY32 module_info, bool IsWow64)
{
	MODULEENTRY32 ModuleEntry = { 0 };

	HANDLE SnapShot = INVALID_HANDLE_VALUE;	
	if(IsWow64)
		SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, ProcessId);
	else
		SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);

	if (SnapShot == INVALID_HANDLE_VALUE)
	{
		utils::WriteLog("[-] handle invalidate...\n");
		return NULL;
	}

	ModuleEntry.dwSize = sizeof(ModuleEntry);

	if (!Module32First(SnapShot, &ModuleEntry))
	{
		CloseHandle(SnapShot);
		utils::WriteLog("[-] Module32First failed.. %X.\n", GetLastError());
		return NULL;
	}

	do
	{
		printf("%s\n", ModuleEntry.szModule);
		if (!strcmp(ModuleEntry.szModule, ModuleName))
		{
			*module_info = ModuleEntry;
			CloseHandle(SnapShot);
			return TRUE;
		}

	} while (Module32Next(SnapShot, &ModuleEntry));

	utils::WriteLog("[-] not found anything in process modules...\n");
	CloseHandle(SnapShot);
	return NULL;
}
