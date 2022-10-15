namespace scan_global
{
	namespace byte_scan_by_file
	{
		char path_file_bp0[256];
		char path_file_bp1[256];

		int type_section = 0;
		char section_name[256] = ".text";
		int section_index = 0;

        MYLOG Log;
        bool open_log;
	}

	namespace byte_scan_by_process_and_module
	{
		char process_name[256] = "crossfire.exe";
		char module_name[256] = "d3d9.dll";

		int type_section = 0;
		char section_name[256] = ".text";
		int section_index = 0;		

		MYLOG Log;
		bool open_log;
	}

}

void scan_byte_patch_file(const char* path1, const char* path2)
{
	if (!path1 || !path2 || !strlen(path1) || !strlen(path2))
	{
		scan_global::byte_scan_by_file::Log.AddLog("[-] input file erro\n");
		return;
	}

	DWORD_PTR allocated_memory_for_path_0 = load_file_in_memory(path1);
	if (!allocated_memory_for_path_0)
	{
		scan_global::byte_scan_by_file::Log.AddLog("[-] failed to allocate memory for path file 0... %X\n", GetLastError());		
		return;
	}

	DWORD_PTR allocated_memory_for_path_1 = load_file_in_memory(path2);
	if (!allocated_memory_for_path_1)
	{
		scan_global::byte_scan_by_file::Log.AddLog("[-] failed to allocate memory for path file 1... %X\n", GetLastError());
		return;
	}

	scan_global::byte_scan_by_file::Log.AddLog("[+] path0 module allocated at: %p\n", allocated_memory_for_path_0);
	scan_global::byte_scan_by_file::Log.AddLog("[+] path1 module allocated at: %p\n", allocated_memory_for_path_1);

	PIMAGE_SECTION_HEADER section_path0_image = NULL;
	PIMAGE_SECTION_HEADER section_path1_image = NULL;

	if (scan_global::byte_scan_by_file::type_section == 0)
	{
		section_path0_image = utils::get_section_by_name(scan_global::byte_scan_by_file::section_name, allocated_memory_for_path_0);
		section_path1_image = utils::get_section_by_name(scan_global::byte_scan_by_file::section_name, allocated_memory_for_path_1);
	}

	if (scan_global::byte_scan_by_file::type_section == 1)
	{
		section_path0_image = get_section_by_index(scan_global::byte_scan_by_file::section_index, allocated_memory_for_path_0);
		section_path1_image = get_section_by_index(scan_global::byte_scan_by_file::section_index, allocated_memory_for_path_1);
	}


	if (!section_path0_image)
	{
		scan_global::byte_scan_by_file::Log.AddLog("[-] failed to find .text section in path image 0... %X\n", GetLastError());
		VirtualFree((void*)allocated_memory_for_path_0, NULL, MEM_RELEASE);
		VirtualFree((void*)allocated_memory_for_path_1, NULL, MEM_RELEASE);
		return;
	}

	
	if (!section_path1_image)
	{
		scan_global::byte_scan_by_file::Log.AddLog("[-] failed to find .text section in process image 1... %X\n", GetLastError());
		VirtualFree((void*)allocated_memory_for_path_0, NULL, MEM_RELEASE);
		VirtualFree((void*)allocated_memory_for_path_1, NULL, MEM_RELEASE);
		
		return;
	}

	if (section_path0_image->SizeOfRawData != section_path1_image->SizeOfRawData)
	{
		scan_global::byte_scan_by_file::Log.AddLog("[-] sections sizes are incompible, maybe packed module %X\n", GetLastError());
		VirtualFree((void*)allocated_memory_for_path_0, NULL, MEM_RELEASE);
		VirtualFree((void*)allocated_memory_for_path_1, NULL, MEM_RELEASE);		
		return;
	}


	PVOID address0 = (BYTE*)allocated_memory_for_path_0 + section_path0_image->VirtualAddress;
	PVOID address1 = (BYTE*)allocated_memory_for_path_1 + section_path1_image->VirtualAddress;


	scan_global::byte_scan_by_file::Log.AddLog("[+] section path module at: %p\n", address0);
	scan_global::byte_scan_by_file::Log.AddLog("[+] section loaded module at: %p\n", address1);
	scan_global::byte_scan_by_file::Log.AddLog("[+] initing scan...\n");

	if (!memcmp(address0, address1, section_path0_image->SizeOfRawData))
	{
		scan_global::byte_scan_by_file::Log.AddLog("[+] has not found any abnormality %X\n\n", GetLastError());
		VirtualFree((void*)allocated_memory_for_path_0, NULL, MEM_RELEASE);
		VirtualFree((void*)allocated_memory_for_path_1, NULL, MEM_RELEASE);
		
		return;
	}

	scan_global::byte_scan_by_file::Log.AddLog("[+] found abnormality...\n[+] scannig location\n");

	DWORD_PTR patch_found;
	for (int i = 0; i < section_path0_image->SizeOfRawData; i++)
	{
		BYTE check0 = *(BYTE*)((DWORD_PTR)address0 + i);
		BYTE check1 = *(BYTE*)((DWORD_PTR)address1 + i);
		if (check0 != check1)
		{
			scan_global::byte_scan_by_file::Log.AddLog("[?] patched at rva -> %p = %X\n", allocated_memory_for_path_0 + section_path0_image->VirtualAddress + i - allocated_memory_for_path_0, *(BYTE*)((DWORD_PTR)address1 + i));
		}
	}

	VirtualFree((void*)allocated_memory_for_path_0, NULL, MEM_RELEASE);
	VirtualFree((void*)allocated_memory_for_path_1, NULL, MEM_RELEASE);	

}

//UserMode -> create for kernel mode too
void scan_byte_patch_module_in_process(const char* process, const char* module_name)
{
	
	if (!process || !module_name || !strlen(process) || !strlen(module_name))
	{
		scan_global::byte_scan_by_process_and_module::Log.AddLog("[-] input file erro\n");		
		return;
	}

	DWORD pid = process::get_pid_process(process);
	if (!pid)
	{
		scan_global::byte_scan_by_process_and_module::Log.AddLog("[-] failed to get pid, probaly process not runnig %X...\n", GetLastError());
		return;
	}

	HANDLE hProcess = OpenProcess(GENERIC_ALL, NULL, pid);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		scan_global::byte_scan_by_process_and_module::Log.AddLog("[-] failed to open process %X...\n", GetLastError());
		return;
	}

	BOOL IsWOW64;
	if (!IsWow64Process(hProcess, &IsWOW64))
	{
		utils::WriteLog("[-] failed to know process arquiteture... %X\n", GetLastError());
		CloseHandle(hProcess);
		return;
	}

	//lista os modulos 
	MODULEENTRY32 module_info;
	if (!modules::get_module_info_from_process_by_pid(pid, module_name, &module_info, IsWOW64))
	{
		scan_global::byte_scan_by_process_and_module::Log.AddLog("[-] get_module_info_from_process_by_pid failed... %X\n", GetLastError());
		CloseHandle(hProcess);
		return;
	}

	if (!module_info.modBaseAddr || !module_info.modBaseSize || !strlen(module_info.szExePath) || !strlen(module_info.szModule))
	{
		scan_global::byte_scan_by_process_and_module::Log.AddLog("[-] failed to get module info from process... %X\n", GetLastError());
		CloseHandle(hProcess);
		return;
	}

	scan_global::byte_scan_by_process_and_module::Log.AddLog("[+] module %s found at: %p in %s process\n", module_info.szExePath, module_info.modBaseAddr, process);

	
	DWORD_PTR allocated_memory_for_path_file = load_file_in_memory(module_info.szExePath);
	if (!allocated_memory_for_path_file)
	{
		scan_global::byte_scan_by_process_and_module::Log.AddLog("[-] failed to allocate memory for path file... %X\n", GetLastError());
		CloseHandle(hProcess);
		return;
	}

	DWORD_PTR allocated_memory_for_loaded_module = load_module_from_process_in_memory(hProcess, &module_info);
	if (!allocated_memory_for_loaded_module)
	{
		scan_global::byte_scan_by_process_and_module::Log.AddLog("[-] failed to load_module_from_process_in_memory... %X\n", GetLastError());	
		VirtualFree((void*)allocated_memory_for_path_file, NULL, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}
	
	scan_global::byte_scan_by_process_and_module::Log.AddLog("[+] path module allocated at: %p\n", allocated_memory_for_path_file);
	scan_global::byte_scan_by_process_and_module::Log.AddLog("[+] loaded module allocated at: %p\n", allocated_memory_for_loaded_module);
	
	
	PIMAGE_SECTION_HEADER section_path_image = NULL; 
	PIMAGE_SECTION_HEADER section_process_image = NULL; 

	if (scan_global::byte_scan_by_process_and_module::type_section == 0)
	{
		section_path_image = utils::get_section_by_name(scan_global::byte_scan_by_process_and_module::section_name, allocated_memory_for_path_file);
		section_process_image = utils::get_section_by_name(scan_global::byte_scan_by_process_and_module::section_name, allocated_memory_for_loaded_module);
	}

	if (scan_global::byte_scan_by_process_and_module::type_section == 1)
	{
		section_path_image = get_section_by_index(scan_global::byte_scan_by_process_and_module::section_index, allocated_memory_for_path_file);
		section_process_image = get_section_by_index(scan_global::byte_scan_by_process_and_module::section_index, allocated_memory_for_loaded_module);
	}
	
	if (!section_path_image)
	{
		scan_global::byte_scan_by_process_and_module::Log.AddLog("[-] failed to find .text section in path image... %X\n", GetLastError());
		VirtualFree((void*)allocated_memory_for_path_file, NULL, MEM_RELEASE);
		VirtualFree((void*)allocated_memory_for_loaded_module, NULL, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}
	
	if (!section_process_image)
	{
		scan_global::byte_scan_by_process_and_module::Log.AddLog("[-] failed to find .text section in process image... %X\n", GetLastError());
		VirtualFree((void*)allocated_memory_for_path_file, NULL, MEM_RELEASE);
		VirtualFree((void*)allocated_memory_for_loaded_module, NULL, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}

	if (section_path_image->SizeOfRawData != section_process_image->SizeOfRawData)
	{
		scan_global::byte_scan_by_process_and_module::Log.AddLog("[-] sections sizes are incompible, maybe packed module %X\n", GetLastError());
		VirtualFree((void*)allocated_memory_for_path_file, NULL, MEM_RELEASE);
		VirtualFree((void*)allocated_memory_for_loaded_module, NULL, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}
	
	PVOID address0 = (BYTE*)allocated_memory_for_path_file + section_path_image->VirtualAddress;
	PVOID address1 = (BYTE*)allocated_memory_for_loaded_module + section_process_image->VirtualAddress;


	scan_global::byte_scan_by_process_and_module::Log.AddLog("[+] section path module at: %p\n", address0);
	scan_global::byte_scan_by_process_and_module::Log.AddLog("[+] section loaded module at: %p\n", address1);
	scan_global::byte_scan_by_process_and_module::Log.AddLog("[+] initing scan...\n");	


	if (!memcmp(address0, address1, section_path_image->SizeOfRawData))
	{
		scan_global::byte_scan_by_process_and_module::Log.AddLog("[+] has not found any abnormality %X\n\n", GetLastError());
		VirtualFree((void*)allocated_memory_for_path_file, NULL, MEM_RELEASE);
		VirtualFree((void*)allocated_memory_for_loaded_module, NULL, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}

	scan_global::byte_scan_by_process_and_module::Log.AddLog("[+] found abnormality...\n[+] scannig location\n");

	DWORD_PTR patch_found;
	for (int i = 0; i < section_path_image->SizeOfRawData; i++)
	{
		BYTE check0 = *(BYTE*)((DWORD_PTR)address0 + i);
		BYTE check1 = *(BYTE*)((DWORD_PTR)address1 + i);
		if (check0 != check1)
		{
			scan_global::byte_scan_by_process_and_module::Log.AddLog("[?] patched at address -> %p = %X\n", module_info.modBaseAddr + section_process_image->VirtualAddress + i, *(BYTE*)((DWORD_PTR)address1 + i));
		}
	}
	
	//VirtualFree((void*)allocated_memory_for_path_file, NULL, MEM_RELEASE);	
	//VirtualFree((void*)allocated_memory_for_loaded_module, NULL, MEM_RELEASE);
	CloseHandle(hProcess);

}

void draw_scan_menu()
{
	ImGuiTabBarFlags tab_bar_flags = ImGuiTabBarFlags_None | ImGuiWindowFlags_MenuBar;
	if (ImGui::BeginTabBar("tab_byte_patch", tab_bar_flags))
	{
		if (ImGui::BeginTabItem("byte patch file"))
		{
			ImGui::Text("scan byte patch files\nnote: the file cant be packet(vmp,themida..)\nif you dumped, ok)");
			ImGui::PushItemWidth(300);
			ImGui::InputTextWithHint("##PATCH_FILE_BP0", "input path first arctive", scan_global::byte_scan_by_file::path_file_bp0, sizeof(scan_global::byte_scan_by_file::path_file_bp0));
			ImGui::InputTextWithHint("##PATCH_FILE_BP1", "input path second arctive", scan_global::byte_scan_by_file::path_file_bp1, sizeof(scan_global::byte_scan_by_file::path_file_bp1));
			ImGui::PopItemWidth();

			ImGui::Combo("get section", &scan_global::byte_scan_by_file::type_section, "by section name\00by section index\00\00");

			if (scan_global::byte_scan_by_file::type_section == 0)
				ImGui::InputText("section name", scan_global::byte_scan_by_file::section_name, sizeof(scan_global::byte_scan_by_file::section_name));

			if (scan_global::byte_scan_by_file::type_section == 1)
				ImGui::InputInt("section index", &scan_global::byte_scan_by_file::section_index);


			if (ImGui::Button("scan file patch"))
			{
				scan_global::byte_scan_by_file::open_log = 1;
				scan_byte_patch_file(scan_global::byte_scan_by_file::path_file_bp0, scan_global::byte_scan_by_file::path_file_bp1);
			}

			if (scan_global::byte_scan_by_file::open_log)
				scan_global::byte_scan_by_file::Log.Draw("byte patch file log", &scan_global::byte_scan_by_file::open_log);


			


			ImGui::EndTabItem();
		}

		if (ImGui::BeginTabItem("byte patch process"))
		{
			ImGui::Text("scan byte patch in process\nnote: the file cant be packet(vmp,themida..)\nif you dumped, ok)");
			ImGui::PushItemWidth(300);
			ImGui::InputTextWithHint("##PROCESS_NAME_TO_SCAN", "input process name", scan_global::byte_scan_by_process_and_module::process_name, sizeof(scan_global::byte_scan_by_process_and_module::process_name));
			ImGui::InputTextWithHint("##MODULE_NAME_TO_SCAN", "input module name with will check", scan_global::byte_scan_by_process_and_module::module_name, sizeof(scan_global::byte_scan_by_process_and_module::module_name));
			ImGui::PopItemWidth();

			ImGui::Combo("get section##PROCCESS", &scan_global::byte_scan_by_process_and_module::type_section, "by section name\00by section index\00\00");

			if (scan_global::byte_scan_by_process_and_module::type_section == 0)
				ImGui::InputText("section name##PROCCESS", scan_global::byte_scan_by_process_and_module::section_name, sizeof(scan_global::byte_scan_by_process_and_module::section_name));

			if (scan_global::byte_scan_by_process_and_module::type_section == 1)
				ImGui::InputInt("section index##PROCCESS", &scan_global::byte_scan_by_process_and_module::section_index);

			if (ImGui::Button("scan process patch"))
			{
				scan_global::byte_scan_by_process_and_module::open_log = 1;
				scan_byte_patch_module_in_process(scan_global::byte_scan_by_process_and_module::process_name, scan_global::byte_scan_by_process_and_module::module_name);
			}

			if (scan_global::byte_scan_by_process_and_module::open_log)
				scan_global::byte_scan_by_process_and_module::Log.Draw("byte patch process log", &scan_global::byte_scan_by_process_and_module::open_log);

			ImGui::EndTabItem();
		}


		ImGui::EndTabBar();
	}


	

	

	
}
