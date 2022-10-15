//#pragma once
//
//#include <Windows.h>
//#include <TlHelp32.h>
//#include <iostream>
//#include <string_view>
//#include <vector>
//#include <functional>
//#include <optional>
//#include <variant>
//
//#if defined(_DEBUG)
//#define HWBP_DEBUG
//#endif
//
//#if defined(_WIN64)
//#define HWBP_X64
//#else
//#define HWBP_X86
//#endif
//
//
////#include "ScopedHandle.hpp"
////#include "ScopedMemory.hpp"
//
//class ScopedHandle
//{
//	HANDLE m_handle = INVALID_HANDLE_VALUE;
//
//public:
//	ScopedHandle() = default;
//
//
//	ScopedHandle(HANDLE handle) noexcept
//		: m_handle(handle)
//	{
//	}
//
//	~ScopedHandle() noexcept
//	{
//		if (valid())
//			CloseHandle(m_handle);
//	}
//
//	bool valid() const noexcept
//	{
//		return m_handle != INVALID_HANDLE_VALUE;
//	}
//
//	operator HANDLE () {
//		return m_handle;
//	}
//
//	operator LPHANDLE () {
//		return &m_handle;
//	}
//};
//
//class ScopedMemory
//{
//	void* m_mem = nullptr;
//	std::size_t m_size{};
//
//public:
//	ScopedMemory() = default;
//
//	ScopedMemory(std::size_t size, std::uint32_t prot) noexcept
//		: m_mem{ VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, prot) }
//		, m_size(size)
//	{
//	}
//
//	~ScopedMemory() noexcept
//	{
//		if (valid())
//			VirtualFree(m_mem, 0, MEM_RELEASE);
//	}
//
//	bool valid() const noexcept
//	{
//		return m_mem != nullptr;
//	}
//
//	void* buffer() const noexcept
//	{
//		return m_mem;
//	}
//
//	void setup(std::size_t size, std::uint32_t prot) noexcept
//	{
//		if (valid())
//			VirtualFree(m_mem, 0, MEM_RELEASE);
//
//		m_mem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, prot);
//		m_size = size;
//	}
//
//	void copy(const void* data, std::size_t sz) noexcept
//	{
//		if (valid() && sz <= m_size)
//			memcpy(m_mem, data, sz);
//	}
//
//	void copy(std::size_t idx, const void* data, std::size_t sz) noexcept
//	{
//		if (valid() && (idx + sz) <= m_size && sz <= m_size)
//			memcpy(&((std::uint8_t*)m_mem)[idx], data, sz);
//	}
//
//	std::size_t size() const noexcept
//	{
//		return m_size;
//	}
//};
//
//
//enum class BreakpointCondition : std::uint8_t
//{
//	Execute = 0b00,
//	Read = 0b01,
//	ReadWrite = 0b11,
//	IOReadWrite = 0b10 // Not supported
//};
//
//enum class BreakpointLength : std::uint8_t
//{
//	OneByte = 0b00,
//	TwoByte = 0b01, // Address in corresponding DR must be word aligned
//	FourByte = 0b11, // Address must be dword aligned
//	EightByte = 0b10  // Address in corresponding DR must be qword aligned
//};
//
//enum class BreakpointHandlerType : std::uint8_t
//{
//	None = 0,
//	Hook,
//	Notify
//};
//
//struct BreakpointHandler
//{
//	using Notify_t = std::function<void(EXCEPTION_POINTERS*)>;
//	using Hook_t = void*;
//
//	BreakpointHandler() = default;
//	~BreakpointHandler() = default;
//
//	BreakpointHandlerType m_type = BreakpointHandlerType::None;
//	std::variant<Notify_t, Hook_t> m_var;
//};
//
//class HardwareBreakpoint
//{
//	friend LONG WINAPI HwbpVectoredExceptionHandler(EXCEPTION_POINTERS* pException);
//	friend void __fastcall HwbpBaseThreadInitThunk(ULONG ulState, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam);
//
//public:
//	//! No default or copy constructor
//	HardwareBreakpoint(const HardwareBreakpoint&) = delete;
//	HardwareBreakpoint(bool singleThread = false, bool runOnce = false);
//	~HardwareBreakpoint();
//
//	//! Instantiate a Hardware Breakpoint
//	bool Create(void* address, BreakpointLength size, BreakpointCondition cond, std::optional<BreakpointHandler> handler = std::nullopt) noexcept;
//
//	//! Disable this hardware breakpoint
//	void Disable() noexcept;
//
//	//! Get buffer pointer
//	void* GetBuffer() const noexcept
//	{
//		return m_buffer.buffer();
//	}
//
//private:
//	bool ModifyThreadContext(CONTEXT* ctx) noexcept;
//
//	//! Execute a function for each thread
//	template<typename TFunc>
//	void ForEachThread(TFunc f);
//
//private:
//	//! Address to set an exception on
//	std::uintptr_t		m_address{};
//	//! Appropriated size of the breakpoint
//	BreakpointLength	m_size{};
//	//! Condition to break on (r/rw/ex)
//	BreakpointCondition m_cond{};
//	//! Occupied register index (or -1 if none)
//	std::int32_t		m_regIdx{ -1 };
//	//! Memory that holds instruction buffer
//	ScopedMemory		m_buffer{};
//	//! Breakpoint handler for notification/hooks
//	BreakpointHandler	m_handler;
//	//! Run on this thread only, or all?
//	bool				m_singleThread{};
//	//! Disable after the breakpoint is hit once
//	bool				m_runOnce{};
//	//! Currently disabled?
//	bool				m_disabled{};
//};
//
//template<typename TFunc>
//inline void HardwareBreakpoint::ForEachThread(TFunc f)
//{
//	ScopedHandle hSnapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId()) };
//	if (!hSnapshot.valid())
//		return;
//
//	THREADENTRY32 te32{};
//	te32.dwSize = sizeof(te32);
//
//	if (Thread32First(hSnapshot, &te32))
//	{
//		do
//		{
//			if (te32.th32OwnerProcessID == GetCurrentProcessId())
//			{
//				ScopedHandle hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
//				if (hThread.valid())
//					f(hThread);
//			}
//		} while (Thread32Next(hSnapshot, &te32));
//	}
//}
//
//void HwbpTerminate();
//
//static std::vector<HardwareBreakpoint*> s_hwbpList;
//static bool s_addedHandler{ false };
//
//static LONG WINAPI HwbpVectoredExceptionHandler(EXCEPTION_POINTERS* pException);
//
////
//// We need to hook thread creations and modify them
//void(__fastcall* _HwbpBaseThreadInitThunk)(ULONG, LPTHREAD_START_ROUTINE, LPVOID);
//static void __fastcall HwbpBaseThreadInitThunk(ULONG ulState, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam);
//
//#if defined(HWBP_X64)
//static constexpr std::uint8_t _JmpOut[] = { 0x48, 0xB8, 0x0D, 0xD0, 0x0D, 0x60, 0x15, 0xEE, 0xFF, 0xC0, 0xFF, 0xE0 };
//static constexpr auto _JmpOutOffset = 0x2;
//#define SET_INSTRUCTION_PTR(i, p) i->ContextRecord->Rip = (std::uintptr_t)p
//#else
//static constexpr std::uint8_t _JmpOut[] = { 0x68, 0xEF, 0xBE, 0xAD, 0xDE, 0xC3 };
//static constexpr auto _JmpOutOffset = 0x1;
//#define SET_INSTRUCTION_PTR(i, p) i->ContextRecord->Eip = (std::uintptr_t)p
//#endif
//
//HardwareBreakpoint::HardwareBreakpoint(bool singleThread, bool runOnce)
//	: m_singleThread(singleThread)
//	, m_runOnce(runOnce)
//{
//	
//	if (!s_addedHandler)
//	{
//
//		//
//		// Add a VEH
//		AddVectoredExceptionHandler(0, HwbpVectoredExceptionHandler);
//		//
//		// Hook BaseThreadInitThunk
//		if (!HookExportDirect("kernel32", "BaseThreadInitThunk", HwbpBaseThreadInitThunk, (void**)&_HwbpBaseThreadInitThunk))
//			printf/*FormatError*/("[!] Error hooking BaseThreadInitThunk\n");
//
//		s_addedHandler = true;
//	}
//
//
//	s_hwbpList.push_back(this);
//}
//
//HardwareBreakpoint::~HardwareBreakpoint()
//{
//	Disable();
//
//	auto it = std::find(s_hwbpList.begin(), s_hwbpList.end(), this);
//
//	if (it != s_hwbpList.end())
//		s_hwbpList.erase(it);
//}
//
//bool HardwareBreakpoint::Create(void* address, BreakpointLength size, BreakpointCondition cond, std::optional<BreakpointHandler> handler) noexcept
//{
//	if (m_regIdx != -1)
//		return false;
//
//	m_address = (std::uintptr_t)address;
//	m_size = size;
//	m_cond = cond;
//
//	if (handler.has_value())
//	{
//		m_handler = handler.value();
//
//		//
//		// Invalid handler mixture, reset it
//		if (m_handler.m_type == BreakpointHandlerType::Hook && cond != BreakpointCondition::Execute)
//		{
//			m_handler.m_type = BreakpointHandlerType::None;
//			//printf/*FormatError*/("[!] Invalid BreakpointHandlerType (wanted hook in a R/RW breakpoint)\n");
//		}
//	}
//
//
//	if (m_cond == BreakpointCondition::Execute)
//	{
//		//
//		// Force one byte length
//		m_size = BreakpointLength::OneByte;
//
//		//
//		// Calculate entire instruction len
//		hde_t hde{};
//		unsigned int inlen = hde_disasm(address, &hde);
//
//		//
//		// If it is a jmp/call, let's go to the destination
//		switch (hde.opcode)
//		{
//		case 0xe8:
//		case 0xe9:
//			m_address += hde.imm.imm32 + inlen;
//			inlen = hde_disasm((void*)m_address, &hde);
//			break;
//		}
//
//		//
//		// New jmp address
//		std::uintptr_t newOffset = m_address + inlen;
//
//		m_buffer.setup(inlen + sizeof(_JmpOut), PAGE_EXECUTE_READWRITE);
//		m_buffer.copy(0, (void*)m_address, inlen);
//		m_buffer.copy(inlen, &_JmpOut[0], sizeof(_JmpOut));
//		m_buffer.copy(inlen + _JmpOutOffset, &newOffset, sizeof(newOffset));
//	}
//
//
//	//
//	// Setup a context for GetThreadContext
//	CONTEXT ctx{};
//	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
//
//
//	if (m_singleThread)
//	{
//		HANDLE hThisThread = GetCurrentThread();
//
//		if (!GetThreadContext(hThisThread, &ctx))
//		{
//			//printf/*FormatError*/("[!] Error calling GetThreadContext in single thread (err: {})\n", GetLastError());
//			return false;
//		}
//
//		if (!ModifyThreadContext(&ctx))
//		{
//			//printf/*FormatError*/("[!] Error calling ModifyThreadContext in single thread\n");
//			return false;
//		}
//
//		//
//		// Set the new thread context
//		SetThreadContext(hThisThread, &ctx);
//	}
//	else
//	{
//		//
//		// Iterator over all threads in the process
//		ForEachThread(
//			[this, &ctx](HANDLE hThread)
//			{
//				if (!GetThreadContext(hThread, &ctx))
//				{
//					//printf/*FormatError*/("[!] Error calling GetThreadContextin another thread (err: {})\n", GetLastError());
//					return;
//				}
//
//				if (!ModifyThreadContext(&ctx))
//				{
//					//printf/*FormatError*/("[!] Error calling ModifyThreadContext in another thread\n");
//					return;
//				}
//
//				//
//				// Set the new thread context
//				SetThreadContext(hThread, &ctx);
//			});
//	}
//}
//
//void HardwareBreakpoint::Disable() noexcept
//{
//	if (m_regIdx == -1)
//		return;
//
//	m_disabled = true;
//
//	//
//	// Setup a context for GetThreadContext
//	CONTEXT ctx{};
//	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
//
//	//
//	// Clear out the debug registers
//	switch (m_regIdx)
//	{
//	case 0:
//		ctx.Dr0 = 0;
//		break;
//	case 1:
//		ctx.Dr1 = 0;
//		break;
//	case 2:
//		ctx.Dr2 = 0;
//		break;
//	case 3:
//		ctx.Dr3 = 0;
//		break;
//	}
//
//	TBitSet<std::uintptr_t> dr7{ ctx.Dr7 };
//
//	//
//	// Set this slot as disabled
//	dr7.SetBit(m_regIdx * 2, false);
//	//
//	// Clear the condition type of the breakpoint (16-17, 21-20, 24-25, 28-29)
//	dr7.SetBits(16 + (m_regIdx * 2), 0);
//	//
//	// Clear the size of the breakpoint (18-19, 22-23, 26-27, 30-31)
//	dr7.SetBit(18 + (m_regIdx * 2), 0);
//
//	if (m_singleThread)
//	{
//		HANDLE hThisThread = GetCurrentThread();
//
//		if (!GetThreadContext(hThisThread, &ctx))
//		{
//			printf/*FormatError*/("[!] Error calling GetThreadContext (err: {})\n", GetLastError());
//			return;
//		}
//
//		ctx.Dr7 = static_cast<decltype(CONTEXT::Dr7)>(dr7.ToValue());
//
//		// Set the new thread context
//		if (!SetThreadContext(hThisThread, &ctx))
//		{
//			printf/*FormatError*/("[!] Error calling SetThreadContext (err: {})\n", GetLastError());
//		}
//	}
//	else
//	{
//		//
//		// Iterator over all threads in the process
//		ForEachThread(
//			[this, &ctx, dr7](HANDLE hThread)
//			{
//				if (!GetThreadContext(hThread, &ctx))
//				{
//					printf/*FormatError*/("[!] Error calling GetThreadContext (err: {})\n", GetLastError());
//					return;
//				}
//
//				ctx.Dr7 = static_cast<decltype(CONTEXT::Dr7)>(dr7.ToValue());
//
//				//
//				// Set the new thread context
//				if (!SetThreadContext(hThread, &ctx))
//				{
//					printf/*FormatError*/("[!] Error calling SetThreadContext (err: {})\n", GetLastError());
//				}
//			});
//	}
//}
//
//bool HardwareBreakpoint::ModifyThreadContext(CONTEXT* ctx) noexcept
//{
//	TBitSet<std::uintptr_t> dr7{ ctx->Dr7 };
//
//	//
//	// Try to find a free debug register
//
//	if (m_regIdx == -1)
//	{
//		for (int i = 0; i < 4; i++)
//		{
//			if (!dr7.IsBitSet(i * 2))
//			{
//				//printf/*FormatError*/("[+] Found free index at {}\n", i);
//				m_regIdx = i;
//				break;
//			}
//		}
//	}
//
//	//
//	// They're all apparently taken.
//	if (m_regIdx == -1)
//	{
//		//printf/*FormatError*/("[!] No debug register\n");
//		return false;
//	}
//
//	//
//	// Set corresponding DR
//	switch (m_regIdx)
//	{
//	case 0:
//		ctx->Dr0 = m_address;
//		break;
//	case 1:
//		ctx->Dr1 = m_address;
//		break;
//	case 2:
//		ctx->Dr2 = m_address;
//		break;
//	case 3:
//		ctx->Dr3 = m_address;
//		break;
//	}
//
//	//
//	// Note: Each mnemonic is 2 bits in length, so we advance as such
//
//	//
//	// Set this slot as enabled
//	dr7.SetBit(m_regIdx * 2, true);
//	//
//	// Set the condition type of the breakpoint (16-17, 21-20, 24-25, 28-29)
//	dr7.SetBits(16 + (m_regIdx * 2), (uint8_t)m_cond);
//	//
//	// Set the size of the breakpoint (18-19, 22-23, 26-27, 30-31)
//	dr7.SetBit(18 + (m_regIdx * 2), (uint8_t)m_size);
//
//	//
//	// Debug print bits if wanted
//	// dr7.PrintBits();
//
//	ctx->Dr7 = static_cast<decltype(CONTEXT::Dr7)>(dr7.ToValue());
//}
//
//LONG WINAPI HwbpVectoredExceptionHandler(EXCEPTION_POINTERS* pException)
//{
//	for (auto it = s_hwbpList.begin(); it != s_hwbpList.end(); it++)
//	{
//		HardwareBreakpoint* bp = *it;
//
//		if (bp->m_disabled)
//			continue;
//
//		if (bp->m_address == (std::uintptr_t)pException->ExceptionRecord->ExceptionAddress)
//		{
//			if (bp->m_handler.m_type != BreakpointHandlerType::None)
//			{
//				switch (bp->m_handler.m_type)
//				{
//				case BreakpointHandlerType::Hook:
//					SET_INSTRUCTION_PTR(pException, std::get<void*>(bp->m_handler.m_var));
//					break;
//				case BreakpointHandlerType::Notify:
//					std::get<BreakpointHandler::Notify_t>(bp->m_handler.m_var)(pException);
//					SET_INSTRUCTION_PTR(pException, bp->m_buffer.buffer());
//					break;
//				}
//			}
//			else
//			{
//				SET_INSTRUCTION_PTR(pException, bp->m_buffer.buffer());
//			}
//
//			if (bp->m_runOnce)
//			{
//				bp->Disable();
//			}
//
//			return EXCEPTION_CONTINUE_EXECUTION;
//		}
//		else if (pException->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) // Catch single step
//		{
//			if (bp->m_handler.m_type == BreakpointHandlerType::Notify)
//			{
//				std::get<BreakpointHandler::Notify_t>(bp->m_handler.m_var)(pException);
//			}
//
//			if (bp->m_runOnce)
//			{
//				bp->Disable();
//			}
//
//			return EXCEPTION_CONTINUE_EXECUTION;
//		}
//	}
//
//	return EXCEPTION_CONTINUE_SEARCH;
//}
//
//void __fastcall HwbpBaseThreadInitThunk(ULONG ulState, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam)
//{
//	if (ulState == 0)
//	{
//		for (auto it = s_hwbpList.begin(); it != s_hwbpList.end(); it++)
//		{
//			HardwareBreakpoint* bp = *it;
//
//			if (bp->m_disabled)
//				continue;
//
//			if (!bp->m_singleThread)
//			{
//				//
//				// Get the thread we're in
//				HANDLE hThisThread = GetCurrentThread();
//
//				//
//				// Setup a context for GetThreadContext
//				CONTEXT ctx{};
//				ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
//
//				if (!GetThreadContext(hThisThread, &ctx))
//				{
//					printf/*FormatError*/("[!] Error calling GetThreadContext (err: {})\n", GetLastError());
//					continue;
//				}
//
//				//
//				// Try finding and setting debug registers
//				if (!bp->ModifyThreadContext(&ctx))
//				{
//					printf/*FormatError*/("[!] Error calling ModifyThreadContext (err: {})\n", GetLastError());
//					continue;
//				}
//
//				// Set the new thread context
//				if (!SetThreadContext(hThisThread, &ctx))
//				{
//					printf/*FormatError*/("[!] Error calling SetThreadContext (err: {})\n", GetLastError());
//				}
//			}
//		}
//	}
//
//	return _HwbpBaseThreadInitThunk(ulState, lpStartAddress, lpParam);
//}
//
//void HwbpTerminate()
//{
//	if (!s_addedHandler)
//		return;
//
//	//
//	// Unhook kernel32!BaseThreadInitThunk
//	UnHookExportDirect("kernel32", "BaseThreadInitThunk");
//
//	//
//	// Free hook trampoline
//	VirtualFree(_HwbpBaseThreadInitThunk, 0, MEM_RELEASE);
//
//	//
//	// Disable any hardware breakpoints that may still exist
//	for (auto bp : s_hwbpList)
//	{
//		bp->Disable();
//	}
//
//	//
//	// Lastly, remove the VEH
//	RemoveVectoredExceptionHandler(HwbpVectoredExceptionHandler);
//}
//
//bool execute_this()
//{
//	printf("executei...\n");
//	return 1;
//}
//
//std::uintptr_t dummy{};
//
//DWORD WINAPI thread_teste(LPVOID)
//{
//	while (1)
//	{
//		//dummy = 555;
//		//execute_this();
//
//		Sleep(1000);
//	}
//	return 1;
//}
//
//namespace hardware_breakpoint
//{
//	vector<void*>breakpoint_address;
//	LPVOID handle_manipulation = NULL;
//	namespace testing
//	{
//		int life = 100;
//	}
//
//}
//
//enum length_hbp
//{
//	OneByte = 0b00,
//	TwoByte = 0b01, // Address in corresponding DR must be word aligned
//	FourByte = 0b11, // Address must be dword aligned
//	EightByte = 0b10  // Address in corresponding DR must be qword aligned
//};
//
//enum cond_hbp
//{
//	Execute = 0b00,
//	Read = 0b01,
//	ReadWrite = 0b11,
//	IOReadWrite = 0b10 // Not supported
//};
//
//LONG WINAPI hardware_breakpoint_manipulation(EXCEPTION_POINTERS* pException)
//{
//	printf("_____________\n");
//	printf("ExceptionAddress: %p\n", pException->ExceptionRecord->ExceptionAddress);
//	printf("_____________\n");
//
//	while (1)
//		Sleep(100);
//
//	return EXCEPTION_CONTINUE_SEARCH;
//}
//
//bool init_hardware_breakpoint()
//{
//
//
//	hardware_breakpoint::handle_manipulation = AddVectoredExceptionHandler(0, hardware_breakpoint_manipulation);
//	if (hardware_breakpoint::handle_manipulation)
//	{
//		if (!HookExportDirect("kernel32", "BaseThreadInitThunk", HwbpBaseThreadInitThunk, (void**)&_HwbpBaseThreadInitThunk))
//			printf/*FormatError*/("[!] Error hooking BaseThreadInitThunk\n");
//
//		return true;
//	}
//	else 
//		return false;
//}
//
//bool delete_hardware_breakpoint()
//{	
//	//dele thread flags
//	if (RemoveVectoredExceptionHandler(hardware_breakpoint::handle_manipulation))
//		return true;
//	else
//		return false;
//}
//
//bool put_bp(uintptr_t m_address, BreakpointCondition condition, BreakpointLength length, CONTEXT* ctx)
//{
//	TBitSet<std::uintptr_t> dr7{ ctx->Dr7 };
//
//	int m_regIdx = 0;
//
//	if (m_regIdx == -1)
//	{
//		for (int i = 0; i < 4; i++)
//		{
//			if (!dr7.IsBitSet(i * 2))
//			{
//				//printf/*FormatError*/("[+] Found free index at {}\n", i);
//				m_regIdx = i;
//				break;
//			}
//		}
//	}
//
//	//
//	// They're all apparently taken.
//	if (m_regIdx == -1)
//	{
//		//printf/*FormatError*/("[!] No debug register\n");
//		return false;
//	}
//
//	//
//	// Set corresponding DR
//	switch (m_regIdx)
//	{
//	case 0:
//		ctx->Dr0 = m_address;
//		break;
//	case 1:
//		ctx->Dr1 = m_address;
//		break;
//	case 2:
//		ctx->Dr2 = m_address;
//		break;
//	case 3:
//		ctx->Dr3 = m_address;
//		break;
//	}
//
//	//
//	// Note: Each mnemonic is 2 bits in length, so we advance as such
//
//	//
//	// Set this slot as enabled
//	dr7.SetBit(m_regIdx * 2, true);
//	//
//	// Set the condition type of the breakpoint (16-17, 21-20, 24-25, 28-29)
//	dr7.SetBits(16 + (m_regIdx * 2), (uint8_t)condition);
//	//
//	// Set the size of the breakpoint (18-19, 22-23, 26-27, 30-31)
//	dr7.SetBit(18 + (m_regIdx * 2), (uint8_t)length);
//
//	//
//	// Debug print bits if wanted
//	// dr7.PrintBits();
//
//	ctx->Dr7 = static_cast<decltype(CONTEXT::Dr7)>(dr7.ToValue());
//
//}
//
//bool create_hardware_breakpoint(void* address, BreakpointCondition condition, BreakpointLength length)
//{
//	if (condition == BreakpointCondition::Execute && length != BreakpointLength::OneByte)
//	{
//		printf("[-] execute condition desaligment with length...\n");
//		return false;
//	}	
//
//	vector<DWORD>get_thread_tids = threads::get_threads_id_by_pid(GetCurrentProcessId());
//	if (get_thread_tids.empty())
//	{
//		printf("[-] failed to get threads running in this process...\n");
//		return false;
//	}
//
//	for (auto threadId : get_thread_tids )
//	{
//
//		if (threadId == GetCurrentThreadId())
//			continue;
//
//		CONTEXT ctx{0};
//		ctx.ContextFlags = /*CONTEXT_FULL*/CONTEXT_DEBUG_REGISTERS;
//
//		if (!threads::is_thread_valid_by_thread_id(threadId))
//		{
//			printf("[-] thread %X is bad thread...\n", threadId);
//			continue;
//		}
//
//		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
//		if (hThread == INVALID_HANDLE_VALUE)
//		{
//			printf("[-] thread %X is bad thread...\n", threadId);
//			continue;
//		}
//
//		//threads::suspend_thread(hThread);
//
//		if (/*!threads::get_thread_context*/!GetThreadContext(hThread, &ctx))
//		{
//			printf("[-] ThreadId %X(%X) Error calling GetThreadContext in another thread (err: %X)\n", threadId, hThread, GetLastError());
//			CloseHandle(hThread);
//			continue;
//		}
//		
//		//Modify		
//		put_bp((uintptr_t)address, condition, length, &ctx);
//
//		//ctx.Dr0 = (DWORD64)address; //Dr0 - Dr3 contain the address you want to break at
//		//ctx.Dr1 = 0; //You dont have to set them all
//		//ctx.Dr2 = 0;
//		//ctx.Dr3 = 0;
//		//
//		//ctx.Dr7 = (1 << 0) | (1 << 2) | (1 << 4);
//
//		if(/*!threads::set_thread_context*/!SetThreadContext(hThread, &ctx))
//		{
//			printf("[-] thread %X failed to setthreadcontext...\n", threadId);
//			CloseHandle(hThread);
//			continue;
//		}
//
//		//threads::resume_thread(hThread);
//
//		CloseHandle(hThread);
//
//	}
//
//
//
//	return true;
//}
//
//
//void draw_hardware_breakpoint()
//{
//	
//	ImGui::Text("testing hardware breakpoint");
//	ImGui::Text("My Health: %i", dummy);
//	ImGui::Text("Address: %p", &dummy);
//
//	
//
//	if (ImGui::Button("HitMe"))	
//		dummy -= 1;
//
//	if (ImGui::Button("HealthMe"))
//		dummy += 1;
//
//	ImGui::Separator();
//
//	if (ImGui::Button("Enable"))
//	{
//		printf("address: %p %p\n", execute_this, &execute_this);
//		CreateThread(0, 0, thread_teste, 0, 0, 0);
//
//		/*init_hardware_breakpoint();
//		create_hardware_breakpoint(execute_this, BreakpointCondition::Execute, BreakpointLength::OneByte);
//		
//		dummy = 5454;*/
//
//
//
//
//#if defined(HWBP_X64)
//		BreakpointLength bplen = BreakpointLength::OneByte;
//#else
//		BreakpointLength bplen = BreakpointLength::FourByte;
//#endif
//		
//		
//
//		HardwareBreakpoint breakpoint;
//		BreakpointHandler handler{};
//		handler.m_type = BreakpointHandlerType::Notify;
//		handler.m_var = [](EXCEPTION_POINTERS* p)
//		{
//#if defined(HWBP_X64)
//			printf("$ Dummy was read/written - current RIP: 0x%p\n", p->ContextRecord->Rip);
//#else
//			printf("$ Dummy was read/written - current EIP: 0x%p\n", p->ContextRecord->Eip);
//#endif
//		};
//
//		breakpoint.Create(&dummy, bplen, BreakpointCondition::Execute, handler);
////		printf("dsa");
////		dummy = 1337;
////		//
//		// Invoke the breakpoint
//		
//	}
//
//	if (ImGui::Button("teste"))
//	{
//		
//		dummy = 5454;
//	}
//	
//	
//
//}