//
//uintptr_t	GetAddress(std::string offsetname, std::string szModule, std::string szSignature, int size, bool pointer, int count, int adj_address, bool IsOffset)
//{
//
//    BYTE FirstByte = NULL;
//    DWORD_PTR real_address = NULL;
//    DWORD_PTR start_address = NULL;
//    DWORD_PTR result_address = NULL;
//    DWORD_PTR result_address_sig = NULL;
//
//    int nSize = size;
//
//    start_address = (DWORD_PTR)GetModuleHandleA(szModule.c_str());
//    result_address_sig = FindPattern(start_address, szSignature.c_str(), NULL, count);
//
//    if (!IsOffset)
//    {
//        if (result_address_sig != NULL) {
//
//            result_address_sig += adj_address;
//
//            result_address = *(uint32_t*)(result_address_sig + size);
//            if (result_address) 
//            {
//                if (pointer) 
//                {
//                    hde64s instr;
//                    int len = hde64_disasm((void*)result_address_sig, &instr); // https://github.com/TsudaKageyu/minhook/tree/master/src/hde
//                    real_address = result_address_sig + result_address + len;
//                }
//                else
//                {
//                    real_address = result_address_sig;
//                }
//
//
//            }
//
//            result_address_sig = real_address;
//
//          
//        }
//        else
//        {
//            
//            real_address = NULL;
//        }
//
//        FirstByte = NULL;
//        real_address = NULL;
//        start_address = NULL;
//        result_address = NULL;
//
//        szModule.clear();
//        offsetname.clear();
//        szSignature.clear();
//    }
//
//    return result_address_sig;
//}
//
//uintptr_t	GetOffset(std::string offsetname, std::string moduleName, std::string pattern, int size, eOffset offType, int count, int adj_offset)
//{
//    uintptr_t _ret_address = NULL;
//    uintptr_t _ret_offset = NULL;
//
//    _ret_address = GetAddress(offsetname.c_str(), moduleName.c_str(), pattern.c_str(), 0, false, count, NULL, true);
//    if (_ret_address)
//    {
//        switch (offType)
//        {
//        case eOffset::iByte:
//            _ret_offset = *(BYTE*)(_ret_address + size);
//            break;
//        case eOffset::iWord:
//            _ret_offset = *(WORD*)(_ret_address + size);
//            break;
//        case eOffset::iDword:
//            _ret_offset = *(DWORD*)(_ret_address + size);
//            break;
//        case eOffset::iDWORD64:
//            _ret_offset = *(DWORD64*)(_ret_address + size);
//            break;
//        }
//
//        _ret_offset += adj_offset;
//               
//    }
//    else
//    {
//       
//        return NULL;
//    }
//}   
//uintptr_t m_DeviceGame = GetAddress(_X("m_DeviceGame"), eCrossfire, _X("48 8B 05 ? ? ? ? 4C 8D 44 24 ? BA ? ? ? ? 48 8B 08 48 8B 01 FF 90 ? ? ? ? 48 8D 15"), 3, true);
//void CharToByte(char* chars, byte* bytes, unsigned int count) 
//{
//    
//    for (unsigned int i = 0; i < count; i++)
//        bytes[i] = (byte)chars[i];
//}
//
//void ByteToChar(byte* bytes, char* chars, unsigned int count)
//{
//    for (unsigned int i = 0; i < count; i++)
//        chars[i] = (char)bytes[i];
//}
//
//void convert_aob_to_patt(const char* aob, size_t len, byte* bytes)
//{
//    if (!bytes)
//        return;
//
//    for (int i = 0; i < len; i++)
//    {
//        if (aob[i] == ' ')
//            continue;
//
//        if (aob[i] == '?')
//            continue;
//
//        bytes[i] = (byte)aob[i];
//    }
//
//}

namespace pattern_global
{

	namespace pattern_by_process
	{

        namespace section
        {
            int mode_section = 0;
            char section_name[256] = ".text";
            int section_index = 0;
        }

        char process_name[256] = "crossfire.exe";
        char module_name[256];

        char single_pattern[999] = "48 ff 25 ? ? ? ? 48 89 4c 24";//"40 53 48 83 ec ?";
       
        char path_list_pattern[256] = "C:\\Users\\STEVE\\source\\repos\\my_tools\\x64\\Release\\teste.ini";
        vector<string>patterns;

        MYLOG view_pattern_log;
        bool view_patterns;
       

        
        MYLOG Log;
        bool open_log;
        
        int mode_pattern;

        namespace functions
        {
            void scam_multiple_address_by_path(const char* process_name, const char* path);
            vector<DWORD_PTR>scam_single_address(const char* process_name, const char* module_name, const char* aob, size_t size_temp, int mode , size_t size_offset );
        }

	}

	namespace pattern_by_file
	{
        MYLOG Log;
        bool open_log;

        char path[256] = "C:\\Users\\STEVE\\Desktop\\dumpers\\crossfire\\5371\\dump_crossfire.exe";
        char path_ini[256] = "C:\\Users\\STEVE\\source\\repos\\my_tools\\x64\\Release\\crossfire.ini";
        char pattern_aob[999] = "FF 90 ? ? ? ? FF C3 48 FF C7";
        int mode_pattern = 0;

        namespace section
        {
            int mode_section = 0;
            char section_name[99] = ".text";
            int index_section;
        }

        namespace functions
        {
            vector<DWORD_PTR>scam_single_address(const char* path, const char* pattern_aob, size_t size_temp, int mode , size_t size_offset );
        }

	}

    namespace functions
    {
        uintptr_t FindPattern(DWORD_PTR start_address, DWORD_PTR end_address, std::string sig, int size, int count);
        vector<DWORD_PTR>FindPatternVector(DWORD_PTR start_address, DWORD_PTR end_address, std::string sig);
        void list_of_patterns_by_ini(const char* path);
        vector<std::string>load_pattern_ini(const char* local);
    }

}

#define INRANGE(x,a,b)        (x >= a && x <= b) 
#define getBits( x )        (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )        (getBits(x[0]) << 4 | getBits(x[1]))

bool bdata_compare(const char* pdata, const char* pattern, const char* mask)
{
    for (; *mask; ++mask, ++pdata, ++pattern)
    {
        if (*mask == 'x' && *pdata != *pattern)
            return false;
    }

    return !*mask;
}

uintptr_t findp(const uintptr_t base, const size_t size, const char* pattern, const char* mask)
{
    for (size_t i = 0; i < size; ++i)
        if (bdata_compare(reinterpret_cast<const char*>(base + i), pattern, mask))
            return base + i;

    return 0;
}


vector<std::string> pattern_global::functions::load_pattern_ini(const char *local)
{
    vector<std::string>resultado;
    
    LPTSTR lpszReturnBuffer;
    lpszReturnBuffer = new TCHAR[1024];
    char* pNextSection = NULL;
    GetPrivateProfileSectionNamesA((LPSTR)lpszReturnBuffer, 1024, local);

    pNextSection = (char*)lpszReturnBuffer;
    resultado.push_back(pNextSection);
    CString csAllSections;
    while (*pNextSection != 0x00)
    {
        pNextSection = pNextSection + strlen(pNextSection) + 1;
        if (*pNextSection != 0x00)
        {
            csAllSections += pNextSection;
        }
        resultado.push_back(pNextSection);
    }

    return resultado;
}

uintptr_t pattern_global::functions::FindPattern(DWORD_PTR start_address, DWORD_PTR end_address, std::string sig, int size, int count)
{

    const char* pat = sig.c_str();  
    uintptr_t foundAddress = NULL;
    uintptr_t startAddress = NULL;
    uintptr_t endAddress = NULL;
    uintptr_t firstMatch = NULL;

    DWORD dwCount = NULL;   

    startAddress = start_address;
    endAddress = end_address;

    for (uintptr_t pCur = startAddress; pCur < endAddress; pCur++) 
    {
        if (!*pat) 
            break;

        if (*(PBYTE)pat == ('\?') || *(BYTE*)pCur == getByte(pat)) 
        {
            if (!firstMatch) 
                firstMatch = pCur;
            
            if (!pat[2])
            {
                if (dwCount != count)
                {
                    dwCount++;
                    continue;
                }

                foundAddress = firstMatch;
                break;
            }
            
            if (*(PWORD)pat == ('\?\?') || 
                *(PBYTE)pat != ('\?')) 
                pat += 3;
            else 
                pat += 2;    //one ?
        }
        else
        {
            pat = sig.c_str();
            firstMatch = 0;
        }
    }

    return foundAddress + size;
}

vector<DWORD_PTR>pattern_global::functions::FindPatternVector(DWORD_PTR start_address, DWORD_PTR end_address, std::string sig)
{
    vector<DWORD_PTR>res;
    const char* pat = sig.c_str();
    uintptr_t foundAddress = NULL;
    uintptr_t startAddress = NULL;
    uintptr_t endAddress = NULL;
    uintptr_t firstMatch = NULL;

    DWORD dwCount = NULL;

    startAddress = start_address;
    endAddress = end_address;   

    for (uintptr_t pCur = startAddress; pCur < endAddress; pCur++)
    {
        if (!*pat)
            break;

        if (*(PBYTE)pat == ('\?') || *(BYTE*)pCur == getByte(pat))
        {
           

            if (!firstMatch)
                firstMatch = pCur;

            if (!pat[2])
            {     
                res.push_back(firstMatch);                
                pat = sig.c_str();
                firstMatch = 0;
            }

           

            if (*(PWORD)pat == ('\?\?') ||  *(PBYTE)pat != ('\?'))
                pat += 3;
            else
                pat += 2;    //one ?

            
           

        }
        else
        {
            pat = sig.c_str();
            firstMatch = 0;
        }
    }

  

    return res;
}

void pattern_global::functions::list_of_patterns_by_ini(const char* path)
{
    if (utils::wait(5))
    {
        pattern_global::pattern_by_process::view_pattern_log.Clear();

        if (!path || !strlen(path))
        {
            pattern_global::pattern_by_process::view_pattern_log.AddLog("[-] input failed\n");
            return;
        }

        vector<string> patterns = load_pattern_ini(path);
        if (patterns.empty())
        {
            pattern_global::pattern_by_process::view_pattern_log.AddLog("[-] nothing patterns\n");
            return;
        }

        for (int i = 0; i < patterns.size() - 1; i++)
        {

            pattern_global::pattern_by_process::view_pattern_log.AddLog("[%s]\n", patterns[i].c_str());

            TCHAR module_name[256];
            TCHAR aob_pattern[999];
            TCHAR size_pattern[32];
            TCHAR mode_pattern[32];
            TCHAR size_offset[32];

            if (!GetPrivateProfileStringA(patterns[i].c_str(), "module", NULL, (LPSTR)module_name, sizeof(module_name), path))
                pattern_global::pattern_by_process::view_pattern_log.AddLog("module: [failed to get module]\n");
            else
                pattern_global::pattern_by_process::view_pattern_log.AddLog("module: [%s]\n", module_name);

            if (!GetPrivateProfileStringA(patterns[i].c_str(), "aob", NULL, (LPSTR)aob_pattern, sizeof(aob_pattern), path))
                pattern_global::pattern_by_process::view_pattern_log.AddLog("aob: [failed to get aob_pattern]\n");
            else
                pattern_global::pattern_by_process::view_pattern_log.AddLog("aob: [%s]\n", aob_pattern);

            if (!GetPrivateProfileStringA(patterns[i].c_str(), "size", NULL, (LPSTR)size_pattern, sizeof(size_pattern), path))
                pattern_global::pattern_by_process::view_pattern_log.AddLog("size: [failed to get size]\n");
            else
                pattern_global::pattern_by_process::view_pattern_log.AddLog("size: [%s]\n", size_pattern);

            if (!GetPrivateProfileStringA(patterns[i].c_str(), "mode", NULL, (LPSTR)mode_pattern, sizeof(mode_pattern), path))
                pattern_global::pattern_by_process::view_pattern_log.AddLog("mode: [failed to get size]\n");
            else
                pattern_global::pattern_by_process::view_pattern_log.AddLog("mode: [%s]\n", mode_pattern);

            if (!GetPrivateProfileStringA(patterns[i].c_str(), "size_offset", NULL, (LPSTR)size_offset, sizeof(size_offset), path))
                pattern_global::pattern_by_process::view_pattern_log.AddLog("size_offset: [failed to get size]\n");
            else
                pattern_global::pattern_by_process::view_pattern_log.AddLog("size_offset: [%s]\n", size_offset);



            pattern_global::pattern_by_process::view_pattern_log.AddLog("__________________________________\n");
        }
        return;

    }
}



vector<DWORD_PTR>pattern_global::pattern_by_process::functions::scam_single_address(const char* process_name, const char* module_name, const char* aob, size_t size_temp, int mode = 0, size_t size_offset = NULL)
{
    vector<DWORD_PTR>res;
    if (!process_name || !module_name || !aob || !strlen(process_name) || !strlen(module_name) || !strlen(aob))
    {
        pattern_global::pattern_by_process::Log.AddLog("[-] input erro to scam_single_address\n");
        utils::WriteLog("[-] input erro to scam_single_address\n");
        return res;
    }   
   
    DWORD pid = process::get_pid_process(process_name);
    if (!pid)
    {
        pattern_global::pattern_by_process::Log.AddLog("[-] failed to get pid from process\n");
        utils::WriteLog("[-] failed to get pid from process\n");
        return res;
    }
   
    HANDLE hProcess = OpenProcess(GENERIC_ALL, NULL, pid);
    if (hProcess == INVALID_HANDLE_VALUE)
    {
        pattern_global::pattern_by_process::Log.AddLog("[-] failed to open process %X\n", GetLastError());
        utils::WriteLog("[-] failed to open process %X\n", GetLastError());
        return res;
    }
   
    MODULEENTRY32 module_info;
    if (!modules::get_module_info_from_process_by_pid(pid, module_name, &module_info, NULL))
    {
        pattern_global::pattern_by_process::Log.AddLog("[-] get_module_info_from_process_by_pid failed... %X\n", GetLastError());
        utils::WriteLog("[-] get_module_info_from_process_by_pid failed... %X\n", GetLastError());
        CloseHandle(hProcess);
        return res;
    }

    if (!module_info.modBaseAddr || !module_info.modBaseSize || !strlen(module_info.szExePath) || !strlen(module_info.szModule))
    {
        utils::WriteLog("[-] failed to get module info from process... %X\n", GetLastError());
        pattern_global::pattern_by_process::Log.AddLog("[-] failed to get module info from process... %X\n", GetLastError());
        CloseHandle(hProcess);
        return res;
    }
  
    BYTE* buf = (BYTE*)VirtualAlloc(NULL, module_info.modBaseSize, MEM_COMMIT, PAGE_READWRITE);

    if (!buf)
    {
        utils::WriteLog("[-] failed to allocate memory to dump... %X\n", GetLastError());
        pattern_global::pattern_by_process::Log.AddLog("[-] failed to allocate memory to dump... %X\n", GetLastError());
        CloseHandle(hProcess);
        return res;
    }
   
    SIZE_T bytes_read = 0;
    ReadProcessMemory(hProcess, (PVOID)module_info.modBaseAddr, buf, module_info.modBaseSize, &bytes_read);

    if (!bytes_read)
    {
        utils::WriteLog("[-] failed to read memory, bad returned files %X\n", GetLastError());
        pattern_global::pattern_by_process::Log.AddLog("[-] failed to read memory, bad returned files %X\n", GetLastError());
        VirtualFree(buf, NULL, MEM_RELEASE);
        CloseHandle(hProcess);
        return res;
    }

    PIMAGE_SECTION_HEADER section_process_image = NULL;
   
    if(pattern_global::pattern_by_process::section::mode_section == 0)
        section_process_image = utils::get_section_by_name(pattern_global::pattern_by_process::section::section_name, (DWORD_PTR)buf);

    if (pattern_global::pattern_by_process::section::mode_section == 1)
        section_process_image = get_section_by_index(pattern_global::pattern_by_process::section::section_index, (DWORD_PTR)buf);


    if (!section_process_image)
    {
        pattern_global::pattern_by_process::Log.AddLog("[-] failed to find .text section in path image 0... %X\n", GetLastError());
        VirtualFree(buf, NULL, MEM_RELEASE);    
        CloseHandle(hProcess);
        return res;
    }
    
    BYTE* address = (BYTE*)buf + section_process_image->VirtualAddress;   
    DWORD size_section = section_process_image->SizeOfRawData;
    BYTE* address_end = address + size_section;   
    
    vector<DWORD_PTR>addresses = pattern_global::functions::FindPatternVector((DWORD_PTR)address, (DWORD_PTR)address_end, aob);   
    DWORD_PTR Result = NULL;

    if(!addresses.empty())   
    {
        for (auto item : addresses)
        {           
            item += size_temp;

            //is_pointer_address
            if (mode == 1)
            {                                
                DWORD_PTR pointer_address = (DWORD_PTR)item + *(DWORD*)item + size_offset; //4 size pointer
                DWORD_PTR CalculateRVA = pointer_address - (DWORD_PTR)buf;               
                //Result = (DWORD_PTR)module_info.modBaseAddr + CalculateRVA;
                res.push_back(CalculateRVA);
            }
            //is_offset_address
            else if (mode == 2)
            {
                DWORD OFFSET = *(DWORD*)item;
                res.push_back(OFFSET);
            }
            //normal
            else if(mode == 0)
            {
                DWORD_PTR CalculateRVA = item - (DWORD_PTR)buf;
                Result = (DWORD_PTR)module_info.modBaseAddr + CalculateRVA;
                res.push_back(Result);
            }
            else
                res.push_back(NULL);
        }
    }
    
   
    VirtualFree(buf, NULL, MEM_RELEASE);
    CloseHandle(hProcess);

    return res;
}

void pattern_global::pattern_by_process::functions::scam_multiple_address_by_path(const char* process_name, const char* path)
{
    if (!path || !strlen(path) || !process_name || !strlen(process_name))
    {
        pattern_global::pattern_by_process::Log.AddLog("[-] failed to get input\n");
        utils::WriteLog("[-] failed to get input\n");
        return;
    }

    FILE* ficheiro = fopen(path, "r");
    if (ficheiro == NULL)
    {
        pattern_global::pattern_by_process::Log.AddLog("[-] failed to openfile\n");
        utils::WriteLog("[-] failed to openfile\n");
        return;
    }

    vector<string> patterns = pattern_global::functions::load_pattern_ini(path);
    if (patterns.empty())
    {
        pattern_global::pattern_by_process::Log.AddLog("[-] was not found any pattern or incorect path\n");
        utils::WriteLog("[-] was not found any pattern or incorect path\n");
        return;
    }

    for (int i = 0; i < patterns.size() - 1; i++)
    {
        TCHAR module_name[256];
        TCHAR aob_pattern[999];
        TCHAR size_pattern[32];
        TCHAR mode_pattern[32];
        TCHAR size_offset[32];

        if (!GetPrivateProfileStringA(patterns[i].c_str(), "module", NULL, (LPSTR)module_name, sizeof(module_name), path))
        {
            pattern_global::pattern_by_process::Log.AddLog("[-] failed to get module from %s... skipping\n", patterns[i].c_str());
            utils::WriteLog("[-] failed to get module from %s... skipping\n", patterns[i].c_str());
            continue;
        }

        if (!GetPrivateProfileStringA(patterns[i].c_str(), "aob", NULL, (LPSTR)aob_pattern, sizeof(aob_pattern), path))
        {
            pattern_global::pattern_by_process::Log.AddLog("[-] failed to get aob from %s... skipping\n", patterns[i].c_str());
            utils::WriteLog("[-] failed to get aob from %s... skipping\n", patterns[i].c_str());
            continue;
        }

        if (!GetPrivateProfileStringA(patterns[i].c_str(), "size", NULL, (LPSTR)size_pattern, sizeof(size_pattern), path))
        {
            pattern_global::pattern_by_process::Log.AddLog("[-] failed to get size from %s... skipping\n", patterns[i].c_str());
            utils::WriteLog("[-] failed to get size from %s... skipping\n", patterns[i].c_str());
            continue;
        }

        if (!GetPrivateProfileStringA(patterns[i].c_str(), "mode", NULL, (LPSTR)mode_pattern, sizeof(mode_pattern), path))
        {
            pattern_global::pattern_by_process::Log.AddLog("[-] failed to get mode from %s... skipping\n", patterns[i].c_str());
            utils::WriteLog("[-] failed to get mode from %s... skipping\n", patterns[i].c_str());
            continue;
        }

        if (!GetPrivateProfileStringA(patterns[i].c_str(), "size_offset", NULL, (LPSTR)size_offset, sizeof(size_offset), path))
        {
            pattern_global::pattern_by_process::Log.AddLog("[-] failed to get size_offset from %s... skipping\n", patterns[i].c_str());
            utils::WriteLog("[-] failed to get size_offset from %s... skipping\n", patterns[i].c_str());
            continue;
        }
     
        size_t size = strtoull(size_pattern, NULL, 16);
        int get_mode = atoi(mode_pattern);
        int index_offset = atoi(size_offset);

        vector<DWORD_PTR>address_found = scam_single_address(process_name, module_name, aob_pattern, size, get_mode, index_offset);

        if (address_found.empty())
            pattern_global::pattern_by_process::Log.AddLog("[-] failed to get %s\n", patterns[i].c_str());
        else
        {
            for (auto item : address_found)
            {
                pattern_global::pattern_by_process::Log.AddLog("[+] %s found at %p size %X mode: %i\n", patterns[i].c_str(), item, size, get_mode);               
            }
        }

    }
  

}



vector<DWORD_PTR>pattern_global::pattern_by_file::functions::scam_single_address(const char* path, const char * pattern_aob, size_t size_temp, int mode = 0, size_t size_offset = NULL)
{
    vector<DWORD_PTR>result;
    if (!path || !strlen(path))
    {
        pattern_global::pattern_by_file::Log.AddLog("[-] incorrect input...\n");
        return result;
    }

    //check if file exist
    if (!utils::file_exists(path))
    {
        pattern_global::pattern_by_file::Log.AddLog("[-] this file not exist...\n");
        return result;
    }

    DWORD_PTR file_loaded_address = load_file_in_memory(path);
    if (!file_loaded_address)
    {
        pattern_global::pattern_by_file::Log.AddLog("[-] failed to load file in memory %X... see the log\n", GetLastError());
        return result;
    }

    PIMAGE_SECTION_HEADER section_path = NULL;

    if (pattern_global::pattern_by_file::section::mode_section == 0) //section by name
    {
        section_path = utils::get_section_by_name(pattern_global::pattern_by_file::section::section_name, file_loaded_address);
    }
    else if (pattern_global::pattern_by_file::section::mode_section == 1)
    {
        section_path = get_section_by_index(pattern_global::pattern_by_file::section::index_section, file_loaded_address);
    }
    else
    {       
        pattern_global::pattern_by_file::Log.AddLog("[-] failed to get section mode..\n");
        VirtualFree((void*)file_loaded_address, NULL, MEM_RELEASE);
        return result;
    }

    if (section_path == NULL)
    {
       
        pattern_global::pattern_by_file::Log.AddLog("[-] failed to get section\n");
        VirtualFree((void*)file_loaded_address, NULL, MEM_RELEASE);
        return result;
    }

    if (!section_path->SizeOfRawData || !section_path->VirtualAddress)
    {
        pattern_global::pattern_by_file::Log.AddLog("[-] failed to get section attributes\n");
        VirtualFree((void*)file_loaded_address, NULL, MEM_RELEASE);
        return result;
    }

    DWORD_PTR address_for_pattern = file_loaded_address + section_path->VirtualAddress;
    DWORD size_for_pattern = section_path->SizeOfRawData;

    vector<DWORD_PTR> addresses = pattern_global::functions::FindPatternVector(address_for_pattern, address_for_pattern + size_for_pattern, pattern_aob); 
  

    if (!addresses.empty())
    {
        for (auto item : addresses)
        {
            item += size_temp;

            //is_pointer_address
            if (mode == 1)
            {
                DWORD_PTR pointer_address = (DWORD_PTR)item + *(DWORD*)item + size_offset; //4 size pointer
                DWORD_PTR CalculateRVA = pointer_address - (DWORD_PTR)file_loaded_address;
                result.push_back(CalculateRVA);
            }
            //is_offset_address
            else if (mode == 2)
            {
                DWORD OFFSET = *(DWORD*)item;
                result.push_back(OFFSET);
            }
            //normal
            else if (mode == 0)
            {
                DWORD_PTR CalculateRVA = item - (DWORD_PTR)file_loaded_address;
                result.push_back(CalculateRVA);
            }
            else
                result.push_back(NULL);
        }
    }

    VirtualFree((void*)file_loaded_address, NULL, MEM_RELEASE);
    return result;
}

vector<DWORD_PTR>scam_multiple_address_by_path_1(const char* path, const char* path_to_ini)
{
    vector<DWORD_PTR>res; 
    if (!path || !path_to_ini || !strlen(path) || !strlen(path_to_ini))
    {
        pattern_global::pattern_by_file::Log.AddLog("[-] incorrect input...\n");
        return res;
    }

    if (!utils::file_exists(path))
    {
        pattern_global::pattern_by_file::Log.AddLog("[-] incorrect path file...\n");
        return res;
    }

    if (!utils::file_exists(path_to_ini))
    {
        pattern_global::pattern_by_file::Log.AddLog("[-] incorrect path to ini...\n");
        return res;
    }     

    vector<string> patterns = pattern_global::functions::load_pattern_ini(path_to_ini);
    if (patterns.empty())
    {
        pattern_global::pattern_by_file::Log.AddLog("[-] was not found any pattern or incorect path\n");
        utils::WriteLog("[-] was not found any pattern or incorect path\n");        
        return res;
    }

    for (int i = 0; i < patterns.size() - 1; i++)
    {       
        TCHAR aob_pattern[999];
        TCHAR size_pattern[32];
        TCHAR mode_pattern[32];
        TCHAR size_offset[32];       

        if (!GetPrivateProfileStringA(patterns[i].c_str(), "aob", NULL, (LPSTR)aob_pattern, sizeof(aob_pattern), path_to_ini))
        {
            pattern_global::pattern_by_file::Log.AddLog("[-] failed to get aob from %s... skipping\n", patterns[i].c_str());
            utils::WriteLog("[-] failed to get aob from %s... skipping\n", patterns[i].c_str());
            continue;
        }

        if (!GetPrivateProfileStringA(patterns[i].c_str(), "size", NULL, (LPSTR)size_pattern, sizeof(size_pattern), path_to_ini))
        {
            pattern_global::pattern_by_file::Log.AddLog("[-] failed to get size from %s... skipping\n", patterns[i].c_str());
            utils::WriteLog("[-] failed to get size from %s... skipping\n", patterns[i].c_str());
            continue;
        }

        if (!GetPrivateProfileStringA(patterns[i].c_str(), "mode", NULL, (LPSTR)mode_pattern, sizeof(mode_pattern), path_to_ini))
        {
            pattern_global::pattern_by_file::Log.AddLog("[-] failed to get mode from %s... skipping\n", patterns[i].c_str());
            utils::WriteLog("[-] failed to get mode from %s... skipping\n", patterns[i].c_str());
            continue;
        }

        if (!GetPrivateProfileStringA(patterns[i].c_str(), "size_offset", NULL, (LPSTR)size_offset, sizeof(size_offset), path_to_ini))
        {
            pattern_global::pattern_by_file::Log.AddLog("[-] failed to get size_offset from %s... skipping\n", patterns[i].c_str());
            utils::WriteLog("[-] failed to get size_offset from %s... skipping\n", patterns[i].c_str());
            continue;
        }

        size_t size = strtoull(size_pattern, NULL, 16);
        int get_mode = atoi(mode_pattern);
        int index_offset = atoi(size_offset);

       // vector<DWORD_PTR>address_found = scam_single_address(process_name, module_name, aob_pattern, size, get_mode, index_offset);
        vector<DWORD_PTR>address_found = pattern_global::pattern_by_file::functions::scam_single_address(path, aob_pattern, size, get_mode, index_offset);
        if (address_found.empty())
            pattern_global::pattern_by_file::Log.AddLog("[-] failed to get %s\n", patterns[i].c_str());
        else
        {
            for (auto item : address_found)
            {
                pattern_global::pattern_by_file::Log.AddLog("[+] %s found at %p size %X mode: %i\n", patterns[i].c_str(), item, size, get_mode);
                res.push_back(item);
            }
        }

    }
   
    return res;
}

void draw_pattern_tab()
{

    ImGuiTabBarFlags tab_bar_flags = ImGuiTabBarFlags_None | ImGuiWindowFlags_MenuBar;
    if (ImGui::BeginTabBar("tab_pattern", tab_bar_flags))
    {


        if (ImGui::BeginTabItem("findpattern_by_process"))
        {
            ImGui::InputTextWithHint("##FPBP", "process name", pattern_global::pattern_by_process::process_name, sizeof(pattern_global::pattern_by_process::process_name));

            if(pattern_global::pattern_by_process::section::mode_section == 1)
                ImGui::InputInt("section id", &pattern_global::pattern_by_process::section::section_index);

            if (pattern_global::pattern_by_process::section::mode_section == 0)
                ImGui::InputTextWithHint("##SECTION_TEXT", "section name", pattern_global::pattern_by_process::section::section_name, sizeof(pattern_global::pattern_by_process::section::section_name));

            ImGui::SameLine();

            ImGui::Combo("##SECTIONMODE", &pattern_global::pattern_by_process::section::mode_section, "by text\00by id\00\00");

            ImGui::Combo("mode", &pattern_global::pattern_by_process::mode_pattern, "single pattern\00list pattern\00\00");

            if (pattern_global::pattern_by_process::mode_pattern == 0)
            {
                ImGui::InputTextWithHint("##FPBPMN", "module name", pattern_global::pattern_by_process::module_name, sizeof(pattern_global::pattern_by_process::module_name));
                ImGui::InputTextWithHint("##SINGLEPATTERN", "put your aob", pattern_global::pattern_by_process::single_pattern, sizeof(pattern_global::pattern_by_process::single_pattern));
            }

            if (pattern_global::pattern_by_process::mode_pattern == 1)
            {
                ImGui::InputTextWithHint("##LISTPATTERN", "put your file path", pattern_global::pattern_by_process::path_list_pattern, sizeof(pattern_global::pattern_by_process::path_list_pattern));
                ImGui::SameLine();
                ImGui::Checkbox("View", &pattern_global::pattern_by_process::view_patterns);
                
            }         

            if (ImGui::Button("Scan##SCAM_PROCESS_PATTERN"))
            {
                pattern_global::pattern_by_process::Log.Clear();
                pattern_global::pattern_by_process::open_log = 1;


                if (pattern_global::pattern_by_process::mode_pattern == 0)
                {
                    vector<DWORD_PTR>pattern = pattern_global::pattern_by_process::functions::scam_single_address(pattern_global::pattern_by_process::process_name, pattern_global::pattern_by_process::module_name, pattern_global::pattern_by_process::single_pattern, 0);
                    if (!pattern.empty())
                    {
                        for (auto item : pattern)
                        {
                            pattern_global::pattern_by_process::Log.AddLog("[-] found address at %p\n", item);
                        }
                    }
                    else
                        pattern_global::pattern_by_process::Log.AddLog("[-] sig not found \n");
                }

                if (pattern_global::pattern_by_process::mode_pattern == 1)
                    pattern_global::pattern_by_process::functions::scam_multiple_address_by_path(pattern_global::pattern_by_process::process_name, pattern_global::pattern_by_process::path_list_pattern);


            }

            if (pattern_global::pattern_by_process::open_log)
                pattern_global::pattern_by_process::Log.Draw("pattern scam by process", &pattern_global::pattern_by_process::open_log);

            ImGui::EndTabItem();
        }



        if (ImGui::BeginTabItem("findpattern_by_file"))
        {
            ImGui::InputTextWithHint("##PATHFILEPATTERN", "path to file", pattern_global::pattern_by_file::path, sizeof(pattern_global::pattern_by_file::path));

            if (pattern_global::pattern_by_file::section::mode_section == 1)
                ImGui::InputInt("section id", &pattern_global::pattern_by_file::section::index_section);

            if (pattern_global::pattern_by_file::section::mode_section == 0)
                ImGui::InputTextWithHint("##SECTION_TEXT", "section name", pattern_global::pattern_by_file::section::section_name, sizeof(pattern_global::pattern_by_file::section::section_name));

            ImGui::SameLine();
            
            ImGui::Combo("##SECTIONMODE", &pattern_global::pattern_by_file::section::mode_section, "by text\00by id\00\00");

            ImGui::Combo("mode", &pattern_global::pattern_by_file::mode_pattern, "single pattern\00list pattern\00\00");

            if (pattern_global::pattern_by_file::mode_pattern == 0)
                ImGui::InputTextWithHint("##AOB_SINGLE_FILE", "pattern aob", pattern_global::pattern_by_file::pattern_aob, sizeof(pattern_global::pattern_by_file::pattern_aob));

            if (pattern_global::pattern_by_file::mode_pattern == 1)            
                ImGui::InputTextWithHint("##INIFILE", "path to .ini file", pattern_global::pattern_by_file::path_ini, sizeof(pattern_global::pattern_by_file::path_ini));
            

            if (ImGui::Button("ScanFile"))
            {
                pattern_global::pattern_by_file::open_log = 1;
                pattern_global::pattern_by_file::Log.Clear();

                //Single Pattern
                if (pattern_global::pattern_by_file::mode_pattern == 0)
                {
                    vector<DWORD_PTR>address = pattern_global::pattern_by_file::functions::scam_single_address(pattern_global::pattern_by_file::path, pattern_global::pattern_by_file::pattern_aob, 0);
                    if (address.empty())
                        pattern_global::pattern_by_file::Log.AddLog("[-] no pattern found..\n");
                    else
                    {
                        for (auto item : address)
                        {
                            pattern_global::pattern_by_file::Log.AddLog("[+] pattern found at: %p\n", item);
                        }
                    }
                }

                //Lsit parttern in .ini
                if (pattern_global::pattern_by_file::mode_pattern == 1)
                {
                    scam_multiple_address_by_path_1(pattern_global::pattern_by_file::path, pattern_global::pattern_by_file::path_ini);
                }

            }

            if (pattern_global::pattern_by_file::open_log)
                pattern_global::pattern_by_file::Log.Draw("pattern scam by file", &pattern_global::pattern_by_file::open_log);

            ImGui::EndTabItem();
        }



        if (pattern_global::pattern_by_process::view_patterns)
        {
            pattern_global::pattern_by_process::view_pattern_log.Draw("view patterns file", &pattern_global::pattern_by_process::view_patterns);
            //list_of_patterns(pattern_global::pattern_by_process::path_list_pattern);
            pattern_global::functions::list_of_patterns_by_ini(pattern_global::pattern_by_process::path_list_pattern);
            
        }

        ImGui::EndTabBar();
    }
}