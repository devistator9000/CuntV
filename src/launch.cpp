// SPDX-License-Identifier: Apache-2.0
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "m04.hpp"
#include "m02.hpp"
#include "m05.hpp"
#include <shellapi.h>
namespace {
void output(const std::string &text, bool error = false) {
    DWORD which = error ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE;
    HANDLE handle = GetStdHandle(which);
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        AttachConsole(ATTACH_PARENT_PROCESS);
        handle = GetStdHandle(which);
    }
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE)
        return;
    size_t offset = 0;
    while (offset < text.size()) {
        DWORD written = 0;
        DWORD length = static_cast<DWORD>(std::min<size_t>(text.size() - offset, 1024 * 1024));
        if (!WriteFile(handle, text.data() + offset, length, &written, nullptr) || !written)
            break;
        offset += written;
    }
}
int command_line(const std::vector<std::wstring> &args) {
    bool inspect = false, gui = false, help = false;
    std::optional<q001::fs::path> source, destination;
    for (size_t n = 0; n < args.size(); ++n) {
        const auto &arg = args[n];
        if (arg == L"--inspect") {
            if (inspect)
                throw std::runtime_error("Duplicate --inspect.");
            inspect = true;
        } else if (arg == L"--gui")
            gui = true;
        else if (arg == L"--help" || arg == L"-h")
            help = true;
        else if (arg == L"--output") {
            if (destination || n + 1 == args.size())
                throw std::runtime_error("--output requires one destination.");
            destination = q001::fs::path(args[++n]);
        } else if (arg.starts_with(L"--"))
            throw std::runtime_error("Unknown option.");
        else {
            if (source)
                throw std::runtime_error("Only one input file is accepted.");
            source = q001::fs::path(arg);
        }
    }
    if (help) {
        output("Native utility\n  Native-Utility.exe [input] --gui\n  Native-Utility.exe "
               "input --inspect\n  Native-Utility.exe input --output copy.addon.patched\n");
        return 0;
    }
    if ((inspect && destination) || (gui && (inspect || destination)))
        throw std::runtime_error("Choose one mode: --gui, --inspect, or --output.");
    if (gui || args.empty() || (source && !inspect && !destination))
        return q001::run_gui(source.value_or(q001::fs::path{}));
    if (!source)
        throw std::runtime_error("Input is required with --inspect or --output.");
    if (inspect) {
        auto report = q001::q02a(*source);
        bool supported = report.value("supported", false);
        output(q001::q029(report).dump(2) + "\n");
        return supported ? 0 : 2;
    }
    if (destination) {
        auto report = q001::q02b(*source, *destination);
        output(q001::q029(report).dump(2) + "\n");
        return 0;
    }
    throw std::runtime_error("Choose --inspect, --output, or --gui.");
}
} // namespace
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    SetProcessDPIAware();
    int count = 0;
    auto raw = CommandLineToArgvW(GetCommandLineW(), &count);
    if (!raw)
        return 1;
    std::vector<std::wstring> args;
    for (int n = 1; n < count; ++n)
        args.emplace_back(raw[n]);
    LocalFree(raw);
    try {
        return command_line(args);
    } catch (const std::exception &e) {
        output("error: operation failed.\n", true);
        return 1;
    }
}
