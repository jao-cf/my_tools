namespace threads
{
	vector<DWORD> get_threads_id_by_pid(DWORD PID);
	DWORD get_current_thread_id();
	bool is_thread_valid_by_thread_id(DWORD ThreadID);
	bool suspend_thread(HANDLE hThread);
	bool resume_thread(HANDLE hThread);

	bool get_thread_context(HANDLE hThread, LPCONTEXT context);
	bool set_thread_context(HANDLE hThread, LPCONTEXT context);
}

DWORD threads::get_current_thread_id()
{
	return GetCurrentThreadId();
}

vector<DWORD> threads::get_threads_id_by_pid(DWORD PID)
{
	vector<DWORD> threads_found;
	HANDLE  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return threads_found;

	THREADENTRY32 te32{};
	te32.dwSize = sizeof(te32);

	if (Thread32First(hSnapshot, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == GetCurrentProcessId())
				threads_found.push_back(te32.th32ThreadID);				
			
		} while (Thread32Next(hSnapshot, &te32));
	}

	return threads_found;
}

bool threads::is_thread_valid_by_thread_id(DWORD ThreadID)
{	
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadID);
	if (hThread != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hThread);
		return true;
	}
	else
		return false;	
}

bool threads::suspend_thread(HANDLE hThread)
{
	if (global_vars::mode == 0)
		return SuspendThread(hThread);

	return false;
}

bool threads::resume_thread(HANDLE hThread)
{
	if (global_vars::mode == 0)
		return ResumeThread(hThread);

	return false;
}

bool threads::get_thread_context(HANDLE hThread, LPCONTEXT context)
{
	if (global_vars::mode == 0)
		return GetThreadContext(hThread, context);
	
	return false;
}

bool threads::set_thread_context(HANDLE hThread, LPCONTEXT context)
{
	if (global_vars::mode == 0)
		return SetThreadContext(hThread, context);

	return false;
}