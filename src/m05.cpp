// SPDX-License-Identifier: Apache-2.0
#define NOMINMAX
#include <windows.h>
#include "m05.hpp"
#include "m04.hpp"
#include <commdlg.h>
#include <iterator>
#include <memory>
#include <sstream>
#include <thread>
#include <windowsx.h>

namespace q001 {
namespace {
constexpr wchar_t kClassName[] = L"NativeUtilityWindow";
constexpr UINT WM_JOB_DONE = WM_APP + 41;
constexpr int ID_PATH = 1001, ID_BROWSE = 1002, ID_INSPECT = 1003, ID_SUMMARY = 1004, ID_STATUS = 1005,
              ID_SAVE = 1006;
struct JobResult {
    bool save = false;
    fs::path destination;
    json value;
    std::wstring error;
};
struct State {
    HWND window{}, path{}, browse{}, inspect{}, summary{}, status{}, save{}, input_label{}, summary_label{};
    bool busy = false, smoke = false;
    fs::path reviewed_path;
    std::string reviewed_hash;
};
std::wstring wide(const std::string &s) {
    if (s.empty())
        return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring r(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), r.data(), n);
    return r;
}
std::wstring get_text(HWND h) {
    int n = GetWindowTextLengthW(h);
    std::wstring s(n + 1, L'\0');
    GetWindowTextW(h, s.data(), n + 1);
    s.resize(n);
    return s;
}
void set_text(HWND h, const std::wstring &s) { SetWindowTextW(h, s.c_str()); }
void clear_review(State *s) {
    s->reviewed_path.clear();
    s->reviewed_hash.clear();
    EnableWindow(s->save, FALSE);
}
void set_busy(State *s, bool b, const std::wstring &label) {
    s->busy = b;
    EnableWindow(s->path, !b);
    EnableWindow(s->browse, !b);
    EnableWindow(s->inspect, !b);
    EnableWindow(s->save, !b && !s->reviewed_hash.empty());
    set_text(s->status, label);
}
std::wstring json_text(const json &j) { return wide(j.dump(2, ' ', false, json::error_handler_t::replace)); }
std::wstring format_inspection(const json &private_report) {
    const auto j = q029(private_report);
    std::wostringstream o;
    o << L"Inspection\r\n";
    for (const char *k :
         {"file", "filename", "architecture", "machine", "version", "status", "reason", "message"})
        if (j.contains(k) && !j[k].is_structured())
            o << wide(k) << L": " << wide(j[k].is_string() ? j[k].get<std::string>() : j[k].dump())
              << L"\r\n";
    for (auto it = j.begin(); it != j.end(); ++it)
        if (it.key() != "features" && it.key() != "patches" && it.key() != "input_sha256" &&
            it.key() != "file" && it.key() != "filename" && it.key() != "architecture" &&
            it.key() != "machine" && it.key() != "version" && it.key() != "status" && it.key() != "reason" &&
            it.key() != "message")
            o << wide(it.key()) << L": " << wide(it.value().dump()) << L"\r\n";
    if (j.contains("features") && j["features"].is_array()) {
        o << L"\r\nDetected features:\r\n";
        for (auto &f : j["features"]) {
            o << L"  " << wide(f.value("name", std::string("(unnamed feature)"))) << L": "
              << wide(f.value("status", std::string("unknown")));
            if (f.contains("patches"))
                o << L" (" << wide(f["patches"].dump()) << L" patches)";
            o << L"\r\n";
        }
    }
    auto patches = j.value("patches", json::array());
    size_t count = j.value("patch_count", patches.is_array() ? patches.size() : 0);
    o << L"\r\nProposed patches (" << count << L"):\r\n";
    if (patches.is_array() && !patches.empty()) {
        size_t i = 1;
        for (auto &p : patches) {
            auto name = p.value("name", p.value("feature", std::string("patch ") + std::to_string(i)));
            o << L"  " << i++ << L". " << wide(name) << L": " << p.value("size", size_t(0)) << L" bytes\r\n";
        }
    } else
        o << L"  None\r\n";
    return o.str();
}
void layout(State *s, int w, int h) {
    int m = 12, row = 27;
    MoveWindow(s->input_label, m, m, 120, 20, TRUE);
    MoveWindow(s->path, m, m + 20, w - 3 * m - 190, row, TRUE);
    MoveWindow(s->browse, w - 2 * m - 180, m + 20, 85, row, TRUE);
    MoveWindow(s->inspect, w - m - 87, m + 20, 87, row, TRUE);
    int top = m + 20 + row + 8;
    MoveWindow(s->summary_label, m, top, w - 2 * m, 20, TRUE);
    top += 20;
    MoveWindow(s->summary, m, top, w - 2 * m, h - top - 72, TRUE);
    MoveWindow(s->status, m, h - 54, w - 2 * m - 190, 24, TRUE);
    MoveWindow(s->save, w - m - 180, h - 58, 180, 30, TRUE);
}
void start_job(State *s, bool save, const fs::path &src, const fs::path &dst = {}) {
    set_busy(s, true, save ? L"Writing patched copy…" : L"Inspecting file…");
    auto expected = s->reviewed_hash;
    HWND hwnd = s->window;
    std::thread([hwnd, save, src, dst, expected]() {
        auto *r = new JobResult;
        r->save = save;
        r->destination = dst;
        try {
            r->value = save ? q02b(src, dst, expected) : q02a(src);
        } catch (const std::exception &e) {
            r->error = L"Operation failed. Check the selected files.";
        } catch (...) {
            r->error = L"Unknown engine error.";
        }
        if (!PostMessageW(hwnd, WM_JOB_DONE, 0, (LPARAM)r))
            delete r;
    }).detach();
}
void choose(State *s, bool save) {
    wchar_t file[32768] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = s->window;
    ofn.lpstrFile = file;
    ofn.nMaxFile = (DWORD)std::size(file);
    ofn.lpstrFilter = save ? L"All files\0*.*\0\0" : L"Addon files\0*.addon\0All files\0*.*\0\0";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | (save ? OFN_OVERWRITEPROMPT : OFN_FILEMUSTEXIST);
    ofn.lpstrTitle = save ? L"Save patched copy" : L"Select input file";
    std::wstring initial_dir;
    if (save) {
        auto src = fs::path(get_text(s->path));
        auto def = src;
        def += L".patched";
        wcscpy_s(file, std::size(file), def.filename().c_str());
        initial_dir = src.parent_path().wstring();
        ofn.lpstrInitialDir = initial_dir.c_str();
    }
    if ((save ? GetSaveFileNameW(&ofn) : GetOpenFileNameW(&ofn))) {
        fs::path p(file);
        if (save) {
            if (p == s->reviewed_path) {
                MessageBoxW(s->window, L"The output path must not overwrite the input file.",
                            L"Choose another file", MB_ICONERROR);
                return;
            }
            if (_wcsicmp(p.filename().c_str(), L"dxgi.dll") == 0) {
                MessageBoxW(s->window, L"The output basename cannot be dxgi.dll.", L"Unsupported output name",
                            MB_ICONERROR);
                return;
            }
            start_job(s, true, s->reviewed_path, p);
        } else {
            set_text(s->path, p.wstring());
            clear_review(s);
            SendMessageW(s->window, WM_COMMAND, MAKEWPARAM(ID_INSPECT, BN_CLICKED), (LPARAM)s->inspect);
        }
    }
}
LRESULT CALLBACK wndproc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    State *s = (State *)GetWindowLongPtrW(h, GWLP_USERDATA);
    if (msg == WM_NCCREATE) {
        s = (State *)((CREATESTRUCTW *)lp)->lpCreateParams;
        s->window = h;
        SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)s);
    }
    if (!s)
        return DefWindowProcW(h, msg, wp, lp);
    switch (msg) {
    case WM_CREATE: {
        HFONT f = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        auto make = [&](const wchar_t *c, const wchar_t *t, DWORD st, int id) {
            HWND x = CreateWindowExW(0, c, t, WS_CHILD | WS_VISIBLE | st, 0, 0, 0, 0, h, (HMENU)(INT_PTR)id,
                                     GetModuleHandleW(nullptr), nullptr);
            SendMessageW(x, WM_SETFONT, (WPARAM)f, TRUE);
            return x;
        };
        s->input_label = make(L"STATIC", L"Input file", SS_LEFT, 0);
        s->summary_label = make(L"STATIC", L"Inspection and proposed patches", SS_LEFT, 0);
        s->path = make(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, ID_PATH);
        s->browse = make(L"BUTTON", L"Browse…", BS_PUSHBUTTON | WS_TABSTOP, ID_BROWSE);
        s->inspect = make(L"BUTTON", L"Inspect", BS_DEFPUSHBUTTON | WS_TABSTOP, ID_INSPECT);
        s->summary = make(L"EDIT", L"",
                          WS_BORDER | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_HSCROLL |
                              ES_NOHIDESEL | WS_TABSTOP,
                          ID_SUMMARY);
        s->status = make(L"STATIC", L"Choose a supported file to inspect it.", SS_LEFT, ID_STATUS);
        s->save = make(L"BUTTON", L"Save patched copy…", BS_PUSHBUTTON | WS_TABSTOP, ID_SAVE);
        set_text(s->path, s->reviewed_path.wstring());
        EnableWindow(s->save, FALSE);
        return 0;
    }
    case WM_GETMINMAXINFO: {
        auto *limits = (MINMAXINFO *)lp;
        limits->ptMinTrackSize.x = 700;
        limits->ptMinTrackSize.y = 480;
        return 0;
    }
    case WM_SIZE:
        layout(s, LOWORD(lp), HIWORD(lp));
        return 0;
    case WM_COMMAND: {
        if (HIWORD(wp) == EN_CHANGE && LOWORD(wp) == ID_PATH) {
            clear_review(s);
            return 0;
        }
        if (HIWORD(wp) == BN_CLICKED) {
            if (LOWORD(wp) == ID_BROWSE) {
                choose(s, false);
                return 0;
            }
            if (LOWORD(wp) == ID_SAVE) {
                choose(s, true);
                return 0;
            }
            if (LOWORD(wp) == ID_INSPECT && !s->busy) {
                auto raw = get_text(s->path);
                if (raw.empty()) {
                    if (!s->smoke)
                        MessageBoxW(h, L"Choose an input file first.", L"Select a file", MB_ICONERROR);
                    return 0;
                }
                fs::path p(raw);
                if (_wcsicmp(p.filename().c_str(), L"dxgi.dll") == 0) {
                    if (!s->smoke)
                        MessageBoxW(h, L"dxgi.dll is not a supported input file.", L"Cannot inspect file",
                                    MB_ICONERROR);
                    return 0;
                }
                clear_review(s);
                start_job(s, false, p);
            }
            return 0;
        }
        break;
    }
    case WM_JOB_DONE: {
        std::unique_ptr<JobResult> r((JobResult *)lp);
        set_busy(s, false, r->save ? L"Patch complete." : L"Inspection complete.");
        if (!r->error.empty()) {
            set_text(s->status, r->save ? L"Patch failed." : L"Inspection failed.");
            set_text(s->summary, r->error);
            if (!s->smoke)
                MessageBoxW(h, r->error.c_str(), r->save ? L"Patch failed" : L"Inspection failed",
                            MB_ICONERROR);
            return 0;
        }
        if (r->save) {
            set_text(s->summary, L"Patch manifest\r\n" + json_text(q029(r->value)));
            set_text(s->status, L"Patched copy saved.");
            if (!s->smoke) {
                auto msg = L"Patched copy saved to:\r\n" + r->destination.wstring();
                MessageBoxW(h, msg.c_str(), L"Patch complete", MB_ICONINFORMATION);
            }
            return 0;
        }
        set_text(s->summary, format_inspection(r->value));
        bool supported = r->value.value("supported", false);
        set_text(s->status, supported ? L"Inspection complete." : L"File is not supported for patching.");
        if (!supported && r->value.contains("reason") && !s->smoke) {
            auto why = wide(r->value.value("reason", std::string("Unsupported input.")));
            MessageBoxW(h, why.c_str(), L"Unsupported file", MB_ICONINFORMATION);
        }
        if (supported && r->value.value("patch_count", size_t(0)) > 0 && r->value.contains("input_sha256") &&
            r->value["input_sha256"].is_string()) {
            auto file = r->value.find("file");
            s->reviewed_path = (file != r->value.end() && file->is_string())
                                   ? fs::path(wide(file->get<std::string>()))
                                   : fs::path(get_text(s->path));
            s->reviewed_hash = r->value["input_sha256"].get<std::string>();
            EnableWindow(s->save, TRUE);
        }
        return 0;
    }
    case WM_CLOSE:
        if (s->busy)
            return 0;
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        if (!s->smoke)
            PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}
bool register_class() {
    static bool done = false;
    if (done)
        return true;
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = wndproc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hIcon = static_cast<HICON>(LoadImageW(wc.hInstance, MAKEINTRESOURCEW(101), IMAGE_ICON,
                                           GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON),
                                           LR_SHARED));
    wc.hIconSm = static_cast<HICON>(LoadImageW(wc.hInstance, MAKEINTRESOURCEW(101), IMAGE_ICON,
                                             GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                             LR_SHARED));
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = kClassName;
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        return false;
    done = true;
    return true;
}
} // namespace
int run_gui(const fs::path &initial_input) {
    if (!register_class())
        return 1;
    State s;
    s.reviewed_path = initial_input;
    HWND h = CreateWindowExW(0, kClassName, L"Native Utility", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                             CW_USEDEFAULT, 820, 600, nullptr, nullptr, GetModuleHandleW(nullptr), &s);
    if (!h)
        return 1;
    ShowWindow(h, SW_SHOW);
    UpdateWindow(h);
    if (!initial_input.empty())
        SendMessageW(h, WM_COMMAND, MAKEWPARAM(ID_INSPECT, BN_CLICKED), 0);
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(h, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return (int)msg.wParam;
}
} // namespace q001
