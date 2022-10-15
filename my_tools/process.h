namespace process
{
	DWORD get_pid_process(const char* process);
	string get_my_process_name();


}


DWORD process::get_pid_process(const char* process)
{
	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{		
		utils::WriteLog("[-] CreateToolhelp32Snapshot failed: 0x%X\n", GetLastError());
		return 0;
	}
	BOOL bRet = Process32First(hSnap, &PE32);
	while (bRet)
	{

		if (!strcmp(PE32.szExeFile, process))
		{
			return PE32.th32ProcessID;
			break;
		}
		bRet = Process32Next(hSnap, &PE32);
	}
	CloseHandle(hSnap);
	return NULL;
}

string process::get_my_process_name()
{
	DWORD MyHandle = GetCurrentProcessId();

	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		DWORD Err = GetLastError();
		utils::WriteLog("[get_my_process_name]CreateToolhelp32Snapshot failed: 0x%X\n", Err);
		return 0;
	}
	BOOL bRet = Process32First(hSnap, &PE32);
	while (bRet)
	{
		if (PE32.th32ProcessID == MyHandle)
		{
			string resultado = PE32.szExeFile;
			CloseHandle(hSnap);
			return resultado;
		}

		bRet = Process32Next(hSnap, &PE32);
	}
	CloseHandle(hSnap);

}
