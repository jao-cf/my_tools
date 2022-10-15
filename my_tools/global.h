namespace global_vars
{
	char LOG_FILE[] = "MYTOOLS_LOG.txt";
    OSVERSIONINFOEXW osInfo;

    bool mode = 0;
	
}

namespace menu_cfg
{
	
	char name_menu[] = "MYTOOLS BY BIELJTVZ";


    float x;
    float y; 
    
    bool loader_active = 1;   
    bool exit = 0; 

    DWORD window_flags;

    int WINDOW_WIDTH = 300;
    int WINDOW_HEIGHT = 100;
    HWND main_hwnd = nullptr;
    LPDIRECT3DDEVICE9        g_pd3dDevice;
    D3DPRESENT_PARAMETERS    g_d3dpp;
    LPDIRECT3D9              g_pD3D;
}

namespace utils
{

    string replaceAll(string subject, const string& search, const string& replace);
    bool strcontain(string local, string findthis);
    int strprofit(string string_safe, string local, string* buffer);
    BOOL DirectoryExists(LPCTSTR szPath);
    char* Descriptografa(const char* plaintext, int x);
    char* Criptografa(const char* plaintext, int x);
    DWORD_PTR DecriptFile(DWORD_PTR Address, DWORD Size, int seed);
    
    BOOL EnableDebugPrivilege(BOOL bEnable);
    BOOL IsElevated(HANDLE hProcess);
    string GetHWID(const wchar_t* driver);
    bool wait(int seconds);
    bool has_any_digits(const std::string& s);
    bool has_ilegal_character(const char* name, bool canusespacebar);
    void WriteLog(const char* pString, ...);

    NTSTATUS SetSZRegisterKey(UNICODE_STRING path, UNICODE_STRING key, const wchar_t* value);
    NTSTATUS SetDWORDRegisterKey(UNICODE_STRING path, UNICODE_STRING key, DWORD Value);
    NTSTATUS DeleteKey(UNICODE_STRING path, UNICODE_STRING key);
    NTSTATUS GetKeyRegister(UNICODE_STRING path, UNICODE_STRING key, ULONG Type, void* val, size_t len);

    vector<wstring> GetWmic(wstring name, wstring Get, PINT number_of_item);
    string RandomString(int len);
    vector<string> split(string s, string delimiter);
    string covert_wstring(wstring w_string);
    inline bool file_exists(const std::string& name);
    const wchar_t* convert_to_wchar(const char* c);
    bool isNumber(const string& str);
    string GetCpuInfo();
    string check_correct_hwid(string hwid);
    bool StartProcess(const char* path);
    PIMAGE_SECTION_HEADER get_section_by_name(const char* name, DWORD_PTR BaseAddress);

    void DeleteAllFiles(string strPath, int log);
    bool delete_all_register_key(HKEY Local, const char* key);
    void delete_bagda_infos();

    void send_screenshot_to_server(const char* name, const char* uploaded_file_name, bool log_discord);


};

namespace registers
{
    UNICODE_STRING path;
    UNICODE_STRING usuario;
    UNICODE_STRING CallBack;
    UNICODE_STRING driver_status;
    UNICODE_STRING process_name;
    UNICODE_STRING ld_process_name;
    UNICODE_STRING driver_name;
    UNICODE_STRING Cumunication;
    UNICODE_STRING Versao;
    UNICODE_STRING spoofer_serial;
    UNICODE_STRING spoofer_status;
    UNICODE_STRING original_serial;
}


struct MYLOG
{
    ImGuiTextBuffer     Buf;
    ImGuiTextFilter     Filter;
    ImVector<int>       LineOffsets; // Index to lines offset. We maintain this with AddLog() calls.
    bool                AutoScroll;  // Keep scrolling if already at the bottom.

    MYLOG()
    {
        AutoScroll = true;
        Clear();
    }

    void Clear()
    {
        Buf.clear();
        LineOffsets.clear();
        LineOffsets.push_back(0);
    }

    void    AddLog(const char* fmt, ...) IM_FMTARGS(2)
    {
        int old_size = Buf.size();
        va_list args;
        va_start(args, fmt);
        Buf.appendfv(fmt, args);
        va_end(args);
        for (int new_size = Buf.size(); old_size < new_size; old_size++)
            if (Buf[old_size] == '\n')
                LineOffsets.push_back(old_size + 1);
    }

    void    Draw(const char* title, bool* p_open = NULL)
    {
        if (!ImGui::Begin(title, p_open))
        {
            ImGui::End();
            return;
        }

        // Options menu
        if (ImGui::BeginPopup("Options"))
        {
            ImGui::Checkbox("Auto-scroll", &AutoScroll);
            ImGui::EndPopup();
        }

        // Main window
        if (ImGui::Button("Options"))
            ImGui::OpenPopup("Options");
        ImGui::SameLine();
        bool clear = ImGui::Button("Clear");
        ImGui::SameLine();
        bool copy = ImGui::Button("Copy");
        ImGui::SameLine();
        Filter.Draw("Filter", -100.0f);

        ImGui::Separator();
        ImGui::BeginChild("scrolling", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

        if (clear)
            Clear();
        if (copy)
            ImGui::LogToClipboard();

        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
        const char* buf = Buf.begin();
        const char* buf_end = Buf.end();
        if (Filter.IsActive())
        {
            // In this example we don't use the clipper when Filter is enabled.
            // This is because we don't have a random access on the result on our filter.
            // A real application processing logs with ten of thousands of entries may want to store the result of
            // search/filter.. especially if the filtering function is not trivial (e.g. reg-exp).
            for (int line_no = 0; line_no < LineOffsets.Size; line_no++)
            {
                const char* line_start = buf + LineOffsets[line_no];
                const char* line_end = (line_no + 1 < LineOffsets.Size) ? (buf + LineOffsets[line_no + 1] - 1) : buf_end;
                if (Filter.PassFilter(line_start, line_end))
                    ImGui::TextUnformatted(line_start, line_end);
            }
        }
        else
        {
            // The simplest and easy way to display the entire buffer:
            //   ImGui::TextUnformatted(buf_begin, buf_end);
            // And it'll just work. TextUnformatted() has specialization for large blob of text and will fast-forward
            // to skip non-visible lines. Here we instead demonstrate using the clipper to only process lines that are
            // within the visible area.
            // If you have tens of thousands of items and their processing cost is non-negligible, coarse clipping them
            // on your side is recommended. Using ImGuiListClipper requires
            // - A) random access into your data
            // - B) items all being the  same height,
            // both of which we can handle since we an array pointing to the beginning of each line of text.
            // When using the filter (in the block of code above) we don't have random access into the data to display
            // anymore, which is why we don't use the clipper. Storing or skimming through the search result would make
            // it possible (and would be recommended if you want to search through tens of thousands of entries).
            ImGuiListClipper clipper;
            clipper.Begin(LineOffsets.Size);
            while (clipper.Step())
            {
                for (int line_no = clipper.DisplayStart; line_no < clipper.DisplayEnd; line_no++)
                {
                    const char* line_start = buf + LineOffsets[line_no];
                    const char* line_end = (line_no + 1 < LineOffsets.Size) ? (buf + LineOffsets[line_no + 1] - 1) : buf_end;
                    ImGui::TextUnformatted(line_start, line_end);
                }
            }
            clipper.End();
        }
        ImGui::PopStyleVar();

        if (AutoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            ImGui::SetScrollHereY(1.0f);

        ImGui::EndChild();
        ImGui::End();
    }
};
