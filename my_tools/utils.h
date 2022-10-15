#define IMAGE_FIRST_SECTION1( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS32, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

string utils::replaceAll(string subject, const string& search, const string& replace)
{
	size_t pos = 0;
	while ((pos = subject.find(search, pos)) != string::npos) {
		subject.replace(pos, search.length(), replace);
		pos += replace.length();
	}
	return subject;
}

inline bool utils::file_exists(const std::string& name)
{
	if (FILE* file = fopen(name.c_str(), "r"))
	{
		fclose(file);
		return true;
	}
	else {
		return false;
	}
}

BOOL utils::DirectoryExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

int utils::strprofit(string string_safe, string local, string* buffer)
{
	string findme = local + "=";

	if (string_safe.find(findme.c_str()) != string::npos)
	{
		int total_length = string_safe.length();
		int length_finded = findme.length();
		int pos_actual = string_safe.find(findme.c_str());
		int pos_start = pos_actual + length_finded;

		string get_buffer = string_safe.substr(pos_start);

		int pos_end_name = get_buffer.find("<br>");
		get_buffer = get_buffer.substr(0, pos_end_name);

		*buffer = get_buffer;
		// printf("Found: %s %i\n", get_buffer.c_str(), pos_end_name);
	}
	else
	{
		//WriteLog("[-] local not found: %s\n", local.c_str());
		return 0;
	}
}

bool utils::strcontain(string local, string findthis)
{
	if (local.find(findthis) != std::string::npos)
		return 1;
	else
		return 0;
}

__forceinline char* utils::Descriptografa(const char* plaintext, int x)
{
	int len = strlen(plaintext);
	char* cyphertext = new char[len + 1];
	for (int i = 0; i < len; ++i)
		cyphertext[i] = plaintext[i] - x;

	cyphertext[len] = 0;
	return cyphertext;
}

inline char* utils::Criptografa(const char* plaintext, int x)
{
	int len = strlen(plaintext);
	char* cyphertext = new char[len + 1];
	for (int i = 0; i < len; ++i)
		cyphertext[i] = plaintext[i] + x;

	cyphertext[len] = 0;
	return cyphertext;
}

bool utils::wait(int seconds)
{
	static int clock_static = seconds;
	if (clock_static < clock())
	{
		clock_static = clock() + seconds * CLOCKS_PER_SEC;
		return 1;
	}
	else
	{
		return 0;
	}
}

DWORD_PTR utils::DecriptFile(DWORD_PTR Address, DWORD Size, int seed)
{
	DWORD_PTR Dll_Decripted = (DWORD_PTR)VirtualAlloc(NULL, Size + 100, MEM_COMMIT, PAGE_READWRITE);
	for (int i = 0; i <= Size; i++)
	{
		BYTE Valor = *(BYTE*)(Address + i);

		if (Valor != 0xFF || Valor != 0x00)
			*(BYTE*)(Dll_Decripted + i) = Valor + seed;
	}

	return Dll_Decripted;
}

void utils::WriteLog(const char* pString, ...)
{
	char pBuffer[512];

	va_list valist;
	va_start(valist, pString);
	_vsnprintf(pBuffer, sizeof(pBuffer) - strlen(pBuffer), pString, valist);

	va_end(valist);

	FILE* pLog_File = fopen(global_vars::LOG_FILE, "a+");

	fprintf(pLog_File, "%s", pBuffer);
	printf(pBuffer);
	fclose(pLog_File);
}

bool utils::has_any_digits(const std::string& s)
{
	return std::any_of(s.begin(), s.end(), ::isdigit);
}

bool utils::has_ilegal_character(const char* name, bool canusespacebar = 1)
{
	char string_to_check[256] = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	if (canusespacebar)
		strcpy(string_to_check, "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ");

	int str = strlen(name);
	for (int x = 0; x < strlen(name); x++)
	{

		for (int i = 0; i < strlen(string_to_check); i++)
		{
			if (name[x] == string_to_check[i])
			{
				str--;
				break;
			}
		}
	}

	if (str)
		return 1;
	else
		return 0;
}


string utils::GetCpuInfo()
{
	// 4 is essentially hardcoded due to the __cpuid function requirements.
	// NOTE: Results are limited to whatever the sizeof(int) * 4 is...
	std::array<int, 4> integerBuffer = {};
	constexpr size_t sizeofIntegerBuffer = sizeof(int) * integerBuffer.size();

	std::array<char, 64> charBuffer = {};

	// The information you wanna query __cpuid for.
	// https://docs.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex?view=vs-2019
	constexpr std::array<int, 3> functionIds = {
		// Manufacturer
		//  EX: "Intel(R) Core(TM"
		0x8000'0002,
		// Model
		//  EX: ") i7-8700K CPU @"
		0x8000'0003,
		// Clockspeed
		//  EX: " 3.70GHz"
		0x8000'0004
	};

	std::string cpu;

	for (int id : functionIds)
	{
		// Get the data for the current ID.
		__cpuid(integerBuffer.data(), id);

		// Copy the raw data from the integer buffer into the character buffer
		std::memcpy(charBuffer.data(), integerBuffer.data(), sizeofIntegerBuffer);

		// Copy that data into a std::string
		cpu += std::string(charBuffer.data());
	}

	return cpu;
}

char* getMyIPV4()
{
	// Init WinSock
	WSADATA wsa_Data;
	int wsa_ReturnCode = WSAStartup(0x101, &wsa_Data);

	// Get the local hostname
	char szHostName[255];
	gethostname(szHostName, sizeof(szHostName));

	struct hostent* host_entry;
	host_entry = gethostbyname(szHostName);

	char* szLocalIP;
	szLocalIP = inet_ntoa(*(struct in_addr*)*host_entry->h_addr_list);
	WSACleanup();

	return szLocalIP;
}

char* GetGatewayIP()
{

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	UINT i;

	/* variables used to print DHCP time info */
	struct tm newtime;
	char buffer[32];
	errno_t error;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL)
	{
		utils::WriteLog("[-] Error allocating memory needed to call GetAdaptersinfo\n");
		return NULL;
	}
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL)
		{
			utils::WriteLog("[-] Error allocating memory needed to call GetAdaptersinfo\n");
			return (char*)"error";
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
	{
		pAdapter = pAdapterInfo;
		while (pAdapter)
		{
			if (pAdapter->Type == MIB_IF_TYPE_ETHERNET)
			{
				if (pAdapterInfo)
					free(pAdapterInfo);

				return pAdapter->GatewayList.IpAddress.String;

				break;
			}

			pAdapter = pAdapter->Next;
		}
	}
	else
		utils::WriteLog("[-] GetAdaptersInfo failed with error: %d\n", dwRetVal);


	if (pAdapterInfo)
		free(pAdapterInfo);
}

void GetWinVersion()
{
	//Versão do windows
	NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW);
	*(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");
	if (NULL != RtlGetVersion)
	{
		global_vars::osInfo.dwOSVersionInfoSize = sizeof(global_vars::osInfo);
		RtlGetVersion(&global_vars::osInfo);
	}

	utils::WriteLog("[+] Windows --> dwBuildNumber: %i, [+] dwMinorVersion: %i, [+] dwMajorVersion: %i", global_vars::osInfo.dwBuildNumber, global_vars::osInfo.dwMinorVersion, global_vars::osInfo.dwMajorVersion);
}

bool utils::StartProcess(const char* path)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// Start the child process. 
	if (!CreateProcessA(NULL, (LPSTR)path, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		WriteLog("CreateProcess failed (%d).\n", GetLastError());
		MessageBoxA(0, "Algo deu errado ao tentar criar o processo", "ERROR", 0);
		return 0;
	}

	return 1;
}

BOOL utils::EnableDebugPrivilege(BOOL bEnable)
{
	HANDLE hToken = nullptr;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		WriteLog("OpenProcessToken error: %d\n", GetLastError());
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
	{
		WriteLog("LookupPrivilegeValue error: %d\n", GetLastError());
		return FALSE;
	}
	TOKEN_PRIVILEGES tokenPriv;
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luid;
	tokenPriv.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		WriteLog("AdjustTokenPrivileges error: %d\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL utils::IsElevated(HANDLE hProcess)
{
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
		{
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken)
	{
		CloseHandle(hToken);
	}
	return fRet;
}

string utils::GetHWID(const wchar_t* driver)
{
	HANDLE deviceHandle = CreateFileW(driver, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);  // Get Handle to device

	if (deviceHandle == INVALID_HANDLE_VALUE) // Check if Handle is valid
		return NULL;

	STORAGE_PROPERTY_QUERY query{};
	query.PropertyId = StorageDeviceProperty;
	query.QueryType = PropertyStandardQuery;

	STORAGE_DESCRIPTOR_HEADER storageDescriptorHeader = { 0 };
	DWORD dwBytesReturned;

	if (!DeviceIoControl(deviceHandle, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(STORAGE_PROPERTY_QUERY), &storageDescriptorHeader, sizeof(STORAGE_DESCRIPTOR_HEADER), &dwBytesReturned, NULL))
	{
		MessageBoxA(0, "Erro adquirido serial(DeviceIoControl0)", "ERRO", MB_ICONERROR | MB_OK);
		ExitProcess(0);
	}

	// Alloc the output buffer
	const DWORD dwOutBufferSize = storageDescriptorHeader.Size;
	std::vector<BYTE> pOutBuffer(dwOutBufferSize, 0);

	if (!DeviceIoControl(deviceHandle, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(STORAGE_PROPERTY_QUERY), pOutBuffer.data(), dwOutBufferSize, &dwBytesReturned, NULL))
	{
		MessageBoxA(0, "Erro adquirido serial1(DeviceIoControl1)", "ERRO", MB_ICONERROR | MB_OK);
		ExitProcess(0);
	}

	STORAGE_DEVICE_DESCRIPTOR* pDeviceDescriptor = (STORAGE_DEVICE_DESCRIPTOR*)pOutBuffer.data();
	const DWORD dwSerialNumberOffset = pDeviceDescriptor->SerialNumberOffset;
	if (dwSerialNumberOffset != 0)
	{
		return (char*)(pOutBuffer.data() + dwSerialNumberOffset);
	}
}

vector<wstring> utils::GetWmic(wstring name, wstring Get, PINT number_of_item)
{
	HRESULT hres;

	vector<wstring> resultado;


	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		WriteLog("Erro! falha ao executar CoInitializeEx %X", hres);
		MessageBoxA(0, "Erro! falha ao executar CoInitializeEx", 0, 0);
		return resultado;
	}

	hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

	if (FAILED(hres))
	{
		WriteLog("Erro! falha ao executar CoInitializeSecurity %X", hres);
		MessageBoxA(0, "Erro! falha ao executar CoInitializeSecurity", 0, 0);
		CoUninitialize();
		return resultado;
	}

	IWbemLocator* pLoc = NULL;

	hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

	if (FAILED(hres))
	{
		WriteLog("Erro! falha ao executar CoCreateInstance %X", hres);
		MessageBoxA(0, "Erro! falha ao executar CoCreateInstance", 0, 0);
		CoUninitialize();
		return resultado;
	}

	IWbemServices* pSvc = NULL;

	hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);

	if (FAILED(hres))
	{
		WriteLog("Erro! falha ao executar ConnectServer %X", hres);
		MessageBoxA(0, "Erro! falha ao executar ConnectServer", 0, 0);
		pLoc->Release();
		CoUninitialize();
		return resultado;
	}

	hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

	if (FAILED(hres))
	{
		WriteLog("Erro! falha ao executar CoSetProxyBlanket %X", hres);
		MessageBoxA(0, "Erro! falha ao executar CoSetProxyBlanket", 0, 0);
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return resultado;
	}

	//////////////////////////////////////


	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(name.c_str()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

	if (FAILED(hres))
	{
		WriteLog("Erro! falha ao executar ExecQuery %X", hres);
		MessageBoxA(0, "Erro! falha ao executar ExecQuery", 0, 0);
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return resultado;
	}

	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;

	wchar_t resultado1[256 * 2];
	int first = 0;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (FAILED(hr))
		{
			WriteLog("Erro! falha ao executar pEnumerator->Next %X", hr);
			MessageBoxA(0, "Erro! falha ao executar pEnumerator->Next", 0, 0);
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return resultado;
		}

		if (uReturn == 0)
			break;

		VARIANT vtProp;

		hr = pclsObj->Get(Get.c_str(), 0, &vtProp, 0, 0);

		if (FAILED(hr))
		{
			WriteLog("Erro! falha ao executar pclsObj->Get %X", hr);
			MessageBoxA(0, "Erro! falha ao executar pclsObj->Get", 0, 0);
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return resultado;
		}

		if (vtProp.bstrVal == NULL)
		{
			wcscpy_s(resultado1, L"Erro adquirindo ");
			wcscat_s(resultado1, name.c_str());
			wcscat_s(resultado1, L" Get -> ");
			wcscat_s(resultado1, Get.c_str());
			WriteLog("[WMIC ERRO] %ws\n", resultado1);
			VariantClear(&vtProp);
			pclsObj->Release();
			break;
		}

		resultado.push_back(vtProp.bstrVal);



		VariantClear(&vtProp);
		pclsObj->Release();
		first++;
	}

	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	if (number_of_item != NULL)
		*number_of_item = first;

	return resultado;
}

//NTSTATUS utils::SetSZRegisterKey(UNICODE_STRING path, UNICODE_STRING key, const wchar_t* value)
//{
//	//0xC0000001 STATUS_UNSUCCESSFUL
//	HANDLE xKey;
//	OBJECT_ATTRIBUTES xObj;
//
//	InitializeObjectAttributes(&xObj, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);
//
//	pfnZwOpenKey ZwOpenKey = (pfnZwOpenKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwOpenKey");
//	pfnZwSetValueKey ZwSetValueKey = (pfnZwSetValueKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwSetValueKey");
//	pfnZwClose ZwClose = (pfnZwClose)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwClose");
//	pfnZwCreateKey ZwCreateKey = (pfnZwCreateKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwCreateKey");
//
//	if (!ZwOpenKey || !ZwSetValueKey || !ZwClose || !ZwCreateKey)
//	{
//		WriteLog("[SetSZRegisterKey] procedure not found");
//		return 0xC0000001;
//	}
//
//	ULONG Disposition;
//	if (ZwOpenKey(&xKey, KEY_ALL_ACCESS, &xObj) != STATUS_SUCCESS)
//	{
//		WriteLog("[SetSZRegisterKey] Erro trying ZwOpenKey... Creating key");
//		if (ZwCreateKey(&xKey, KEY_ALL_ACCESS, &xObj, 0, NULL, REG_OPTION_NON_VOLATILE, &Disposition) != STATUS_SUCCESS)
//		{
//			WriteLog("[SetSZRegisterKey] Erro trying ZwCreateKey... returning");
//			return 0xC0000001;
//		}
//	}
//
//	ULONG ValueLength = (wcslen(value)) * 2;
//
//	if (ZwSetValueKey(xKey, &key, 1, REG_SZ, (PVOID)value, ValueLength) != STATUS_SUCCESS)
//	{
//		WriteLog("[SetSZRegisterKey] erro trying ZwSetValueKey");
//		ZwClose(xKey);
//		return 0xC0000001;
//	}
//
//	ZwClose(xKey);
//
//	return STATUS_SUCCESS;
//}
//
//NTSTATUS utils::SetDWORDRegisterKey(UNICODE_STRING path, UNICODE_STRING key, DWORD Value)
//{
//	//0xC0000001 STATUS_UNSUCCESSFUL
//	HANDLE xKey;
//	OBJECT_ATTRIBUTES xObj;
//
//	InitializeObjectAttributes(&xObj, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);
//
//	pfnZwOpenKey ZwOpenKey = (pfnZwOpenKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwOpenKey");
//	pfnZwSetValueKey ZwSetValueKey = (pfnZwSetValueKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwSetValueKey");
//	pfnZwClose ZwClose = (pfnZwClose)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwClose");
//	pfnZwCreateKey ZwCreateKey = (pfnZwCreateKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwCreateKey");
//
//	if (!ZwOpenKey || !ZwSetValueKey || !ZwClose || !ZwCreateKey)
//	{
//		WriteLog("[SetSZRegisterKey] procedure not found");
//		return 0xC0000001;
//	}
//
//	ULONG Disposition;
//	if (ZwOpenKey(&xKey, KEY_ALL_ACCESS, &xObj) != STATUS_SUCCESS)
//	{
//		WriteLog("[SetSZRegisterKey] Erro trying ZwOpenKey... Creating key");
//		if (ZwCreateKey(&xKey, KEY_ALL_ACCESS, &xObj, 0, NULL, REG_OPTION_NON_VOLATILE, &Disposition) != STATUS_SUCCESS)
//		{
//			WriteLog("[SetSZRegisterKey] Erro trying ZwCreateKey... returning");
//			return 0xC0000001;
//		}
//	}
//
//	if (ZwSetValueKey(xKey, &key, 0, REG_DWORD, &Value, sizeof(DWORD)) != STATUS_SUCCESS)
//	{
//		WriteLog("erro trying ZwSetValueKey");
//		ZwClose(xKey);
//		return 0xC0000001;
//	}
//
//	ZwClose(xKey);
//	return STATUS_SUCCESS;
//}
//
//NTSTATUS utils::DeleteKey(UNICODE_STRING path, UNICODE_STRING key)
//{
//	typedef NTSTATUS(NTAPI* pfnZwOpenKey)(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
//	typedef NTSTATUS(NTAPI* pfnZwSetValueKey)(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);
//	typedef NTSTATUS(NTAPI* pfnZwClose)(HANDLE Handle);
//	typedef NTSTATUS(NTAPI* pfnZwDeleteKey)(HANDLE KeyHandle);
//
//	pfnZwOpenKey ZwOpenKey = (pfnZwOpenKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwOpenKey");
//	pfnZwSetValueKey ZwSetValueKey = (pfnZwSetValueKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwSetValueKey");
//	pfnZwClose ZwClose = (pfnZwClose)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwClose");
//	pfnZwDeleteKey ZwDeleteKey = (pfnZwDeleteKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwDeleteKey");
//
//	wchar_t delete_path[256];
//	wsprintfW(delete_path, L"%ws\\%ws", path.Buffer, key.Buffer);
//	UNICODE_STRING path_to_delete;
//	RtlInitUnicodeString(&path_to_delete, delete_path);
//
//
//	if (!ZwOpenKey || !ZwSetValueKey || !ZwClose || !ZwDeleteKey)
//	{
//		WriteLog("[DeleteKey] procedure not found");
//		return 0xC0000001;
//	}
//
//	HANDLE xKey;
//	OBJECT_ATTRIBUTES xObj;
//
//	InitializeObjectAttributes(&xObj, &path_to_delete, OBJ_CASE_INSENSITIVE, NULL, NULL);
//
//	if (ZwOpenKey(&xKey, KEY_ALL_ACCESS, &xObj) != 0x0)
//	{
//		WriteLog("[DeleteKey] Key não existe");
//		return 0x0;
//	}
//
//	if (ZwDeleteKey(xKey) != 0x0)
//	{
//		WriteLog("[DeleteKey] failed to del keyregister");
//		ZwClose(xKey);
//		return 0xC0000001;
//	}
//
//	ZwClose(xKey);
//}
//
//NTSTATUS utils::GetKeyRegister(UNICODE_STRING path, UNICODE_STRING key, ULONG Type, void* val, size_t lengt = 0)
//{
//	pfnZwOpenKey ZwOpenKey = (pfnZwOpenKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwOpenKey");
//	pfnZwSetValueKey ZwSetValueKey = (pfnZwSetValueKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwSetValueKey");
//	pfnZwClose ZwClose = (pfnZwClose)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwClose");
//	pfnZwQueryValueKey ZwQueryValueKey = (pfnZwQueryValueKey)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryValueKey");
//
//	if (!ZwOpenKey || !ZwSetValueKey || !ZwClose)
//	{
//		WriteLog("[SetSZRegisterKey] procedure not found");
//		return 0xC0000001;
//	}
//
//	HANDLE xKey;
//	OBJECT_ATTRIBUTES xObj;
//	ULONG Lenght;
//
//	InitializeObjectAttributes(&xObj, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//
//	auto status = ZwOpenKey(&xKey, KEY_ALL_ACCESS, &xObj);
//
//	if (status != STATUS_SUCCESS)
//	{
//		WriteLog("[GetSZKeyRegister] ZwOpenKey failed: %p\n", status);
//		return 0xC0000001;
//	}
//
//	status = ZwQueryValueKey(xKey, &key, KeyValueFullInformation, NULL, NULL, &Lenght);
//
//	if ((status == STATUS_BUFFER_TOO_SMALL) || (status == STATUS_BUFFER_OVERFLOW))
//	{
//		if (!Lenght)
//		{
//			WriteLog("[GetSZKeyRegister] length 0\n");
//			return 0xC0000001;
//		}
//
//		PKEY_VALUE_FULL_INFORMATION pvpi = (PKEY_VALUE_FULL_INFORMATION)VirtualAlloc(NULL, Lenght, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//
//		if (!pvpi)
//		{
//			WriteLog("[GetSZKeyRegister] failed to alloc memory\n");
//			return 0xC0000001;
//		}
//
//		status = ZwQueryValueKey(xKey, &key, KeyValueFullInformation, pvpi, Lenght, &Lenght);
//
//		if (status != STATUS_SUCCESS)
//		{
//			WriteLog("[GetSZKeyRegister] ZwQueryValueKey failed: %X", status);
//			VirtualFree((PVOID)pvpi, Lenght, MEM_RELEASE);
//			return 0xC0000001;
//		}
//
//		if (pvpi->Type != Type)
//		{
//			WriteLog("[GetSZKeyRegister] type different... canceling");
//			VirtualFree((PVOID)pvpi, Lenght, MEM_RELEASE);
//			return 0xC0000001;
//		}
//
//		printf("Datalegth: %X\n", pvpi->DataLength);
//
//		if (pvpi->Type == REG_SZ)
//			RtlCopyMemory(val, ((INT8*)pvpi) + pvpi->DataOffset, lengt - 1);
//		else
//			RtlCopyMemory(val, ((INT8*)pvpi) + pvpi->DataOffset, pvpi->DataLength);
//
//		ZwClose(xKey);
//		VirtualFree((PVOID)pvpi, Lenght, MEM_RELEASE);
//
//		return STATUS_SUCCESS;
//	}
//
//	memset(val, 0, lengt);
//	return status;
//}


string utils::RandomString(int len)
{

	string str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	string newstr;
	int pos;
	while (newstr.size() != len)
	{
		int clock1 = clock() + rand();
		pos = ((clock1 % (str.size() - 1)));
		newstr += str.substr(pos, 1);
	}
	return newstr;
}

vector<string> utils::split(string s, string delimiter)
{

	size_t pos_start = 0, pos_end, delim_len = delimiter.length();
	string token;
	vector<string> res;

	while ((pos_end = s.find(delimiter, pos_start)) != string::npos)
	{
		token = s.substr(pos_start, pos_end - pos_start);
		pos_start = pos_end + delim_len;
		res.push_back(token);
	}

	res.push_back(s.substr(pos_start));
	return res;
}

string utils::covert_wstring(wstring w_string)
{
	string converted(w_string.begin(), w_string.end());
	return converted;
}

const wchar_t* utils::convert_to_wchar(const char* c)
{
	const size_t cSize = strlen(c) + 1;
	wchar_t* wc = new wchar_t[cSize];
	mbstowcs(wc, c, cSize);

	return wc;
}

bool utils::isNumber(const string& str)
{
	for (char const& c : str) {
		if (std::isdigit(c) == 0) return false;
	}
	return true;
}

void utils::DeleteAllFiles(string strPath, int log)
{

	WIN32_FIND_DATAA wfd;
	HANDLE hFile;
	DWORD dwFileAttr;
	string strFile;
	string strSpec = strPath + "*.*";
	string strPathFile;

	// find the first file
	hFile = FindFirstFileA(strSpec.c_str(), &wfd);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			strFile = wfd.cFileName;
			strPathFile = strPath + strFile;
			// get the file attributes
			dwFileAttr = GetFileAttributesA(strPathFile.c_str());

			// see if file is read-only : if so unset read-only
			if (dwFileAttr & FILE_ATTRIBUTE_READONLY)
			{
				dwFileAttr &= ~FILE_ATTRIBUTE_READONLY;
				SetFileAttributesA(strPathFile.c_str(), dwFileAttr);
			}

			// see if the file is a directory
			if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				// make sure it isn't current or parent directory
				if (strFile != "." && strFile != "..")
				{
					strPathFile += "\\";
					// recursively delete all files in this folder
					utils::DeleteAllFiles(strPathFile, log);
					// remove the directory

					if (RemoveDirectoryA(strPathFile.c_str()))
					{
						if (log)
							cout << "deleted directory : " << strPathFile.c_str() << endl;
					}
					else
					{
						if (log)
							cout << "could not delete directory : " << strPathFile.c_str() << endl;
					}
				}
			}
			else
			{
				// delete the file
				if (DeleteFileA(strPathFile.c_str()))
				{
					if (log)
						cout << "deleted file : " << strPathFile.c_str() << endl;
				}
				else
				{
					if (log)
						cout << "could not delete file : " << strPathFile.c_str() << endl;
				}

			}

		} while (FindNextFileA(hFile, &wfd));
	}

	FindClose(hFile);
}

bool utils::delete_all_register_key(HKEY Local, const char* key)
{
	HKEY hKey;
	DWORD dwNumValues, dwValueNameLen;
	if (RegOpenKeyExA(Local, key, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
	{
		return 0;
	}

	if (RegQueryInfoKey(hKey, 0, 0, 0, 0, 0, 0, &dwNumValues, &dwValueNameLen, 0, 0, 0) == ERROR_SUCCESS)
	{
		TCHAR* tchValName = new TCHAR[dwValueNameLen + 1];
		for (int i = dwNumValues - 1; i >= 0; --i)
		{
			DWORD dwLen = dwValueNameLen + 1;

			RegEnumValue(hKey, i, tchValName, &dwLen, 0, 0, 0, 0);
			RegDeleteValue(hKey, tchValName);

		}
		delete[] tchValName;
		return 1;
	}
	return 0;

}


PIMAGE_SECTION_HEADER utils::get_section_by_name(const char* name, DWORD_PTR BaseAddress)
{
	
	IMAGE_DOS_HEADER* image_dos_header = (IMAGE_DOS_HEADER*)BaseAddress;
	IMAGE_NT_HEADERS* old_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(BaseAddress + image_dos_header->e_lfanew);
	if (old_nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)//
	{
		printf("[+] get_section_by_name x64\n");
		PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(BaseAddress + ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew);
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
		for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
		{
			if (!_stricmp((char*)section->Name, name))
				return section;
		}
	
	}
	else if(old_nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		printf("[+] get_section_by_name x32\n");
		PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)(BaseAddress + ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew);
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION1(nt);
		for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
		{
			if (!_stricmp((char*)section->Name, name))
				return section;
		}
	}

	
	return nullptr;
}

PIMAGE_SECTION_HEADER get_section_by_index(int index, DWORD_PTR BaseAddress)
{
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(BaseAddress + ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) 
	{
		if(index == i)
			return section;
	}
	return nullptr;
}

DWORD_PTR get_module_info_from_process_by_handle(HANDLE hProcess, const char* module_name)
{
	MODULEINFO module_info;

	//GetModuleInformation(hProcess, )

	return NULL;
}

DWORD_PTR load_file_in_memory(const char* path) //problema x32 ler incorretamente do path
{
	if (!path || !strlen(path))
	{
		utils::WriteLog("[-][load_file_in_memory] input error...\n");
		
		return false;
	}

	printf("path: %s\n", path);

	HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	DWORD FileSize = GetFileSize(hFile, NULL);
	BYTE *pSrcData = (BYTE*)VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	DWORD ReadBytes;
	ReadFile(hFile, pSrcData, FileSize, &ReadBytes, NULL);

	printf("file size: %X\n", FileSize);
	printf("read size: %X\n", ReadBytes);

	//BYTE* pSrcData = new BYTE[(UINT_PTR)FileSize];
	/*std::ifstream File(path, std::ios::binary | std::ios::ate);
	if (File.fail())
	{
		utils::WriteLog("[-] failed to load module %X\n", (DWORD)File.rdstate());
		File.close();
		return false;
	}

	auto FileSize = File.tellg();
	
	if (FileSize < 0x1000)
	{
		utils::WriteLog("[-] invalid size of module \n");
		File.close();
		return false;
	}

	BYTE* pSrcData = new BYTE[(UINT_PTR)FileSize];	
	if (!pSrcData)
	{
		utils::WriteLog("[-] failed to allocate memory %X\n", GetLastError());
		File.close();
		return false;
	}

	

	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	File.close();*/

	

	/*utils::WriteLog("[+] source: %p\n", pSrcData);
	system("pause");*/

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) //"MZ"
	{
		utils::WriteLog("[-] invalid file \n");
		delete[] pSrcData;
		return false;
	}	

	bool is_wow64_file = false;
	IMAGE_DOS_HEADER *image_dos_header = (IMAGE_DOS_HEADER*)pSrcData;
	IMAGE_NT_HEADERS* old_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + image_dos_header->e_lfanew);
	if (old_nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		utils::WriteLog("[-] image x32 detected...\n");
		is_wow64_file = true;
	}


	BYTE* allocated_memory = NULL;

	if (is_wow64_file == 1)
	{

		IMAGE_NT_HEADERS32* pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS32*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
		IMAGE_OPTIONAL_HEADER32* pOldOptHeader = &pOldNtHeader->OptionalHeader;
		IMAGE_FILE_HEADER* pOldFileHeader = &pOldNtHeader->FileHeader;
		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION1(pOldNtHeader);

		allocated_memory = (BYTE*)VirtualAlloc(NULL, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!allocated_memory)
		{
			utils::WriteLog("[-] failed to allocate memory %X\n", GetLastError());
			delete[] pSrcData;
			return false;
		}


		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
		{
			printf("[+] section VirtualAddress: %X\n", pSectionHeader->VirtualAddress);
			if (pSectionHeader->SizeOfRawData)
			{
				if (!memcpy(allocated_memory + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData))
				{
					utils::WriteLog("[-] failed to map section %X\n", GetLastError());
					delete[] pSrcData;
					return false;
				}
			}
		}

		if (!memcpy(allocated_memory, pSrcData, 0x3FF))
		{
			utils::WriteLog("[-] failed to restore headers %X\n", GetLastError());
			delete[] pSrcData;
			return false;
		}
	}
	else if (is_wow64_file == 0)
	{
		IMAGE_NT_HEADERS* pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
		IMAGE_OPTIONAL_HEADER* pOldOptHeader = &pOldNtHeader->OptionalHeader;
		IMAGE_FILE_HEADER* pOldFileHeader = &pOldNtHeader->FileHeader;
		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);

		allocated_memory = (BYTE*)VirtualAlloc(NULL, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!allocated_memory)
		{
			utils::WriteLog("[-] failed to allocate memory %X\n", GetLastError());
			delete[] pSrcData;
			return false;
		}


		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
		{
			if (pSectionHeader->SizeOfRawData)
			{
				if (!memcpy(allocated_memory + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData))
				{
					utils::WriteLog("[-] failed to map section %X\n", GetLastError());
					delete[] pSrcData;
					return false;
				}
			}
		}

		if (!memcpy(allocated_memory, pSrcData, 0x3FF))
		{
			utils::WriteLog("[-] failed to restore headers %X\n", GetLastError());
			delete[] pSrcData;
			return false;
		}
	}


	//delete[] pSrcData;

	return (DWORD_PTR)allocated_memory;
}

DWORD_PTR load_module_from_process_in_memory(HANDLE hProcess, MODULEENTRY32 *module_info)
{

	if (!module_info->modBaseSize || !module_info->modBaseAddr)
	{
		utils::WriteLog("[-] invalid param at load_module_from_process_in_memory... %X\n", GetLastError());
		return NULL;
	}

	utils::WriteLog("[-] size from load_module_from_process_in_memory: %X... %X\n", module_info->modBaseSize , GetLastError());

	DWORD_PTR allocated_memory_for_loaded_module = (DWORD_PTR)VirtualAlloc(NULL, module_info->modBaseSize, MEM_COMMIT, PAGE_READWRITE);
	if (!allocated_memory_for_loaded_module)
	{
		utils::WriteLog("[-] failed to allocate memory for loaded module... %X\n", GetLastError());
		return NULL;
	}

	SIZE_T bytes_read;
	if (!ReadProcessMemory(hProcess, module_info->modBaseAddr, (VOID*)allocated_memory_for_loaded_module, module_info->modBaseSize, &bytes_read))
	{
		utils::WriteLog("[-] failed to read memory from process... %X\n", GetLastError());
		return NULL;
	}
	

	return allocated_memory_for_loaded_module;
}