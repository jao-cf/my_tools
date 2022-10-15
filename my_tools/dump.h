namespace dump
{
	namespace dump_from_process
	{
		char module_name[256];
		char process_name[256];
	}
}

bool dump_module_from_process(const char* process_name, const char* module_name)
{
	if (!process_name || !module_name || !strlen(process_name) || !strlen(module_name))
	{
		utils::WriteLog("[-] input erro to dump module\n");
		return 0;
	}

	DWORD pid = process::get_pid_process(process_name);
	if (!pid)
	{
		utils::WriteLog("[-] failed to get pid from process\n");
		return 0;
	}

    

	HANDLE hProcess = OpenProcess(GENERIC_ALL, NULL, pid);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		utils::WriteLog("[-] failed to open process %X\n", GetLastError());
		return 0;
	}

    BOOL IsWOW64;
    if (!IsWow64Process(hProcess, &IsWOW64))
    {
        utils::WriteLog("[-] failed to know process arquiteture... %X\n", GetLastError());
        CloseHandle(hProcess);
        return 0;
    }

    MODULEENTRY32 module_info;
    if (!modules::get_module_info_from_process_by_pid(pid, module_name, &module_info, IsWOW64))
    {
        utils::WriteLog("[-] get_module_info_from_process_by_pid failed... %X\n", GetLastError());
        CloseHandle(hProcess);
        return 0;
    }

    if (!module_info.modBaseAddr || !module_info.modBaseSize || !strlen(module_info.szExePath) || !strlen(module_info.szModule))
    {
        utils::WriteLog("[-] failed to get module info from process... %X\n", GetLastError());
        CloseHandle(hProcess);
        return 0;
    }

	BYTE* buf = (BYTE*)VirtualAlloc(NULL, module_info.modBaseSize, MEM_COMMIT, PAGE_READWRITE);

	if (!buf)
	{
		utils::WriteLog("[-] failed to allocate memory to dump... %X\n", GetLastError());
		CloseHandle(hProcess);
		return 0;
	}


    SIZE_T bytes_read = 0;   
    ReadProcessMemory(hProcess, (PVOID)module_info.modBaseAddr, buf, module_info.modBaseSize, &bytes_read);

    if (!bytes_read)
    {
        utils::WriteLog("[-] failed to read memory, bad returned files %X\n", GetLastError());       
        VirtualFree(buf, NULL, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

   
    auto pimage_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buf);
    auto pimage_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(buf + pimage_dos_header->e_lfanew);

    // Este é um PE 64. Utilizar a versão em 64 bits dos nt headers
    //
    if (pimage_nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        // Obter o ponteiro para o primeiro section header
        //
        auto pimage_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(pimage_nt_headers + 1);

        for (WORD i = 0; i < pimage_nt_headers->FileHeader.NumberOfSections; ++i, ++pimage_section_header)
        {
            // Converter as seções deste PE para sua forma "unmapped" ao deixar o file offset igual ao RVA (VirtualAddress), assim como o raw size (SizeOfRawData)
            // igual ao virtual size (VirtualSize). Isso nos permite carregar o binário de maneira limpa em ferramentas para análise estática
            //
            pimage_section_header->PointerToRawData = pimage_section_header->VirtualAddress;
            pimage_section_header->SizeOfRawData = pimage_section_header->Misc.VirtualSize;
        }

        // Arrumar o image base para a base do módulo que será dumpado
        //
        pimage_nt_headers->OptionalHeader.ImageBase = (DWORD_PTR)module_info.modBaseAddr;
    }

    // Este é um PE 32. Utilizar a versão em 32 bits dos nt headers
    //
    else if (pimage_nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        auto pimage_nt_headers32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(pimage_nt_headers);
        auto pimage_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(pimage_nt_headers32 + 1);

        for (WORD i = 0; i < pimage_nt_headers32->FileHeader.NumberOfSections; ++i, ++pimage_section_header)
        {
            // Converter as seções deste PE para sua forma "unmapped" ao deixar o file offset igual ao RVA (VirtualAddress), assim como o raw size (SizeOfRawData)
            // igual ao virtual size (VirtualSize). Isso nos permite carregar o binário de maneira limpa em ferramentas para análise estática
            //
            pimage_section_header->PointerToRawData = pimage_section_header->VirtualAddress;
            pimage_section_header->SizeOfRawData = pimage_section_header->Misc.VirtualSize;
        }

        // Arrumar o image base para a base do módulo que será dumpado
        //
        pimage_nt_headers32->OptionalHeader.ImageBase = (DWORD)module_info.modBaseAddr;
    }

    // Não suportado
    //
    else
    {
        CloseHandle(hProcess);
        VirtualFree(buf, NULL, MEM_RELEASE);
        utils::WriteLog("[-] this image is not suported\n");
        return 0;
    }

    // Montar o nome do módulo dumpado. Exemplo: "dump_kernel32.dll"
    //
    char bufName[MAX_PATH] = { 0 };
    strcpy(bufName, "dump_");
    strcat(bufName, module_name);

    // Criar o arquivo no diretório atual (você pode mudar para outro diretório se quiser)
    //
    HANDLE hFile = CreateFileA(bufName, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        utils::WriteLog("[-] failed to create file %X\n", GetLastError());       
        CloseHandle(hProcess);
        VirtualFree(buf, NULL, MEM_RELEASE);
        return 0;
    }

    DWORD Ip1, Ip2;
    if (!WriteFile(hFile, buf, (DWORD_PTR)bytes_read, &Ip1, nullptr))
    {
        utils::WriteLog("[-] failed to write file %X\n", GetLastError());
        CloseHandle(hFile);
        CloseHandle(hProcess);
        VirtualFree(buf, NULL, MEM_RELEASE);
        return 0;
    }

    CloseHandle(hFile);
    CloseHandle(hProcess);
    VirtualFree(buf, NULL, MEM_RELEASE);

	return 1;
}

void draw_dump_tab()
{
	ImGui::Text("dump module from process\n");
	ImGui::InputTextWithHint("##DUMP_PROCESS_NAME", "process name", dump::dump_from_process::process_name, sizeof(dump::dump_from_process::process_name));
	ImGui::InputTextWithHint("##DUMP_MODULE_NAME", "module name", dump::dump_from_process::module_name, sizeof(dump::dump_from_process::module_name));

	if (ImGui::Button("Dump Module"))
	{
        if (!dump_module_from_process(dump::dump_from_process::process_name, dump::dump_from_process::module_name))        
            MessageBoxA(0,"failed to dump module, see the log", "ERRO", MB_ICONERROR | MB_OK);        
        else
            MessageBoxA(0, "success dumped... see at this app folder", "SUCCESS", MB_ICONINFORMATION | MB_OK);
	}

	ImGui::Separator();
}