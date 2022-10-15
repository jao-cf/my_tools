#define _CRT_SECURE_NO_WARNINGS
#define NMD_ASSEMBLY_IMPLEMENTATION
#define _WIN32_DCOM
#include "main.h"

IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

void CleanupDeviceD3D()
{
    if (menu_cfg::g_pd3dDevice) { menu_cfg::g_pd3dDevice->Release(); menu_cfg::g_pd3dDevice = NULL; }
    if (menu_cfg::g_pD3D) { menu_cfg::g_pD3D->Release(); menu_cfg::g_pD3D = NULL; }
}

void ResetDevice()
{
    ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = menu_cfg::g_pd3dDevice->Reset(&menu_cfg::g_d3dpp);
    if (hr == D3DERR_INVALIDCALL)
        IM_ASSERT(0);
    ImGui_ImplDX9_CreateDeviceObjects();
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (menu_cfg::g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
        {
            menu_cfg::g_d3dpp.BackBufferWidth = LOWORD(lParam);
            menu_cfg::g_d3dpp.BackBufferHeight = HIWORD(lParam);
            ResetDevice();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

bool CreateDeviceD3D(HWND hWnd)
{
    if ((menu_cfg::g_pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == NULL)
        return false;

    // Create the D3DDevice
    ZeroMemory(&menu_cfg::g_d3dpp, sizeof(menu_cfg::g_d3dpp));
    menu_cfg::g_d3dpp.Windowed = TRUE;
    menu_cfg::g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    menu_cfg::g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
    menu_cfg::g_d3dpp.EnableAutoDepthStencil = TRUE;
    menu_cfg::g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    menu_cfg::g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;           // Present with vsync
    //g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;   // Present without vsync, maximum unthrottled framerate
    if (menu_cfg::g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &menu_cfg::g_d3dpp, &menu_cfg::g_pd3dDevice) < 0)
        return false;
    return true;
}


// Main code
int APIENTRY WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{   

    DeleteFileA(global_vars::LOG_FILE);

    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    SetConsoleTitleA("bieljtvz console");
    
    utils::WriteLog("[+] iniciando...\n");

    //nmd example
   /* const uint8_t buffer[] = { 0x33, 0xC0, 0x40, 0xC3, 0x8B, 0x65, 0xE8 };
    const uint8_t* const buffer_end = buffer + sizeof(buffer);

    nmd_x86_instruction instruction;
    char formatted_instruction[128];

    size_t i = 0;
    for (; i < sizeof(buffer); i += instruction.length)
    {
        if (!nmd_x86_decode(buffer + i, buffer_end - (buffer + i), &instruction, NMD_X86_MODE_32, NMD_X86_DECODER_FLAGS_MINIMAL))
            break;

        nmd_x86_format(&instruction, formatted_instruction, NMD_X86_INVALID_RUNTIME_ADDRESS, NMD_X86_FORMAT_FLAGS_DEFAULT);

        printf("%s\n", formatted_instruction);
    }

    system("pause");*/


    //EnableDebugPrivilege
#pragma region enable_debug_privilege

    if (!utils::EnableDebugPrivilege(1))
    {       
        MessageBoxA(0, "Falha ao setar privilegios", "ERRO", MB_ICONERROR | MB_OK);
        return 0;
    }   

#pragma endregion

    //inicio as strings para registros
#pragma region init_unicode

    RtlInitUnicodeString(&registers::path, L"\\Registry\\Machine\\Software\\Astaehcmy");
    RtlInitUnicodeString(&registers::CallBack, L"CallBacks");
    RtlInitUnicodeString(&registers::usuario, L"usuario");
    RtlInitUnicodeString(&registers::Cumunication, L"Comunication");
    RtlInitUnicodeString(&registers::Versao, L"Versao");
    RtlInitUnicodeString(&registers::spoofer_serial, L"spoofer_serial");
    RtlInitUnicodeString(&registers::spoofer_status, L"spoofer_status");
    RtlInitUnicodeString(&registers::driver_status, L"status");
    RtlInitUnicodeString(&registers::ld_process_name, L"ld_process_name");
    RtlInitUnicodeString(&registers::process_name, L"process_name");
    RtlInitUnicodeString(&registers::driver_name, L"driver_name");   

#pragma endregion       


    // Create application window
    HICON hIcon = (HICON)(HICON)LoadImageA(NULL, "icon1.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE);

    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), hIcon, NULL, NULL, NULL, menu_cfg::name_menu, NULL };
    RegisterClassEx(&wc);
    menu_cfg::main_hwnd = CreateWindowA(wc.lpszClassName, menu_cfg::name_menu, WS_POPUP, 0, 0, 5, 5, NULL, NULL, wc.hInstance, NULL);

    // Initialize Direct3D
    if (!CreateDeviceD3D(menu_cfg::main_hwnd))
    {
        utils::WriteLog("[-] failed to create d3ddevice\n");
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    // Show the window 
    ShowWindow(menu_cfg::main_hwnd, SW_HIDE);
    UpdateWindow(menu_cfg::main_hwnd);

    // Setup Dear ImGui context
    ImGui::CreateContext();

    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

    ImGui_ImplWin32_Init(menu_cfg::main_hwnd);
    ImGui_ImplDX9_Init(menu_cfg::g_pd3dDevice);   

   

    menu_cfg::window_flags =/* ImGuiWindowFlags_NoResize |*/ ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoCollapse/* | ImGuiWindowFlags_NoScrollbar*/;

    RECT screen_rect;
    GetWindowRect(GetDesktopWindow(), &screen_rect);
    menu_cfg::x = float(screen_rect.right - menu_cfg::WINDOW_WIDTH) / 2.f;
    menu_cfg::y = float(screen_rect.bottom - menu_cfg::WINDOW_HEIGHT) / 2.f;

    // Main loop
    MSG msg;
    ZeroMemory(&msg, sizeof(msg));

    utils::WriteLog("[+] iniciando draw...\n");
    while (msg.message != WM_QUIT)
    {
        if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();


        ImGui::NewFrame();
        {

            //ImGui::ShowDemoWindow();

            //login
            if (menu_cfg::loader_active)
            {

                static bool uma_vez = 1;
                if (uma_vez)
                {
                    ImGui::SetNextWindowPos(ImVec2(menu_cfg::x, menu_cfg::y), ImGuiCond_Once);
                    ImGui::SetNextWindowSize(ImVec2(menu_cfg::WINDOW_WIDTH + 40, menu_cfg::WINDOW_HEIGHT + 125));
                    ImGui::SetNextWindowBgAlpha(1.0f);
                    uma_vez = 0;
                }

               
                if (ImGui::Begin("MYTOOLS", &menu_cfg::loader_active, menu_cfg::window_flags))
                {             
                    ImGuiTabBarFlags tab_bar_flags = ImGuiTabBarFlags_None | ImGuiWindowFlags_MenuBar;
                    if (ImGui::BeginTabBar("maintabs", tab_bar_flags))
                    {
                        if (ImGui::BeginTabItem("byte patch"))
                        {
                            draw_scan_menu();
                            ImGui::EndTabItem();
                        }  

                        if (ImGui::BeginTabItem("dump"))
                        {
                            draw_dump_tab();
                            ImGui::EndTabItem();
                        }

                        if (ImGui::BeginTabItem("pattern"))
                        {
                            draw_pattern_tab();
                            ImGui::EndTabItem();
                        }

                        if (ImGui::BeginTabItem("drivers"))
                        {
                            draw_drivers_tab();
                            ImGui::EndTabItem();
                        }

                        if (ImGui::BeginTabItem("teste"))
                        {
                            static char name_module[256] = "crossfire1.exe";
                            static char module_name[256];
                            ImGui::InputText("process", name_module, sizeof(name_module));
                            if (ImGui::Button("cada"))
                            {
                                DWORD PID = process::get_pid_process(name_module);
                                if (!PID)
                                {
                                    utils::WriteLog("[-] failed to find pid...\n");
                                    continue;
                                }

                                HANDLE hProcess = OpenProcess(GENERIC_ALL, NULL, PID);
                                if (hProcess == INVALID_HANDLE_VALUE)
                                {
                                    utils::WriteLog("[-] failed to find pid...\n");
                                    continue;
                                }

                                MODULEINFO lll = modules::get_module_info_by_name(hProcess, "KERNEL32.DLL");
                                printf("money: %p\n", lll.lpBaseOfDll);


                            }


                            ImGui::EndTabItem();
                        }


                        ImGui::EndTabBar();
                    }

                    ImGui::End();
                }
            }        

        }

        ImGui::EndFrame();



        menu_cfg::g_pd3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, 0, 1.0f, 0);
        if (menu_cfg::g_pd3dDevice->BeginScene() >= 0)
        {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            menu_cfg::g_pd3dDevice->EndScene();
        }

        // Update and Render additional Platform Windows
        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        HRESULT result = menu_cfg::g_pd3dDevice->Present(NULL, NULL, NULL, NULL);

        // Handle loss of D3D9 device
        if (result == D3DERR_DEVICELOST && menu_cfg::g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET)
            ResetDevice();


        if (!menu_cfg::loader_active )
        {
            msg.message = WM_QUIT;
        }
        else if (menu_cfg::exit)
        {
            msg.message = WM_QUIT;
        }
    }

    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(menu_cfg::main_hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);

   

    return 0;
}

