// SPDX-License-Identifier: Apache-2.0
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "m02.hpp"
#include <bcrypt.h>
#include <cwctype>
#include <fstream>
#include <sstream>
namespace q001 {
std::string q027(const Bytes &data) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (auto value : data) {
        result += digits[value >> 4];
        result += digits[value & 15];
    }
    return result;
}
std::string q028(uint64_t value) {
    std::ostringstream s;
    s << "0x" << std::hex << value;
    return s.str();
}
std::string path_utf8(const fs::path &path) {
    auto u = path.u8string();
    return std::string(u.begin(), u.end());
}
std::wstring from_utf8(const std::string &text) {
    if (text.empty())
        return {};
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                                nullptr, 0);
    require(n > 0, "Invalid UTF-8 text.");
    std::wstring result(n, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                        result.data(), n);
    return result;
}
static bool excluded(const fs::path &path) {
    auto name = path.filename().wstring();
    for (auto &c : name)
        c = std::towlower(c);
    return name == L"dxgi.dll";
}
fs::path checked_path(const fs::path &path) {
    require(!path.empty(), "A file path is required.");
    require(!excluded(path), "dxgi.dll is excluded.");
    auto result = fs::weakly_canonical(fs::absolute(path));
    require(!excluded(result), "dxgi.dll is excluded.");
    return result;
}
Bytes read_input(const fs::path &input) {
    auto path = checked_path(input);
    require(fs::is_regular_file(path), "Input file does not exist.");
    auto size = fs::file_size(path);
    require(size >= 1024 && size <= 128 * 1024 * 1024, "File size is outside the supported range.");
    std::ifstream stream(path, std::ios::binary);
    require(bool(stream), "Cannot open input file.");
    Bytes result(static_cast<size_t>(size));
    stream.read(reinterpret_cast<char *>(result.data()), static_cast<std::streamsize>(size));
    require(stream.gcount() == static_cast<std::streamsize>(size),
            "Input changed or could not be read completely.");
    char extra;
    require(!stream.get(extra), "Input grew during reading.");
    return result;
}
std::string sha256(const Bytes &data) {
    struct Context {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        Bytes state;
        ~Context() {
            if (hash)
                BCryptDestroyHash(hash);
            if (algorithm)
                BCryptCloseAlgorithmProvider(algorithm, 0);
        }
    } context;
    auto &algorithm = context.algorithm;
    auto &hash = context.hash;
    require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0,
            "Cannot initialize SHA-256.");
    DWORD size = 0, count = 0;
    require(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&size), sizeof(size),
                              &count, 0) >= 0,
            "Cannot query SHA-256 state.");
    context.state.resize(size);
    Bytes result(32);
    require(BCryptCreateHash(algorithm, &hash, context.state.data(), size, nullptr, 0, 0) >= 0,
            "Cannot create SHA-256 state.");
    require(data.size() <= UINT32_MAX, "Hash input is too large.");
    if (!data.empty())
        require(BCryptHashData(hash, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0) >=
                    0,
                "SHA-256 update failed.");
    require(BCryptFinishHash(hash, result.data(), static_cast<ULONG>(result.size()), 0) >= 0,
            "SHA-256 finish failed.");
    return q027(result);
}
void write_exclusive(const fs::path &input, const Bytes &data) {
    auto path = checked_path(input);
    HANDLE file =
        CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    require(file != INVALID_HANDLE_VALUE, "Cannot create output; it may already exist or access is denied.");
    try {
        size_t offset = 0;
        while (offset < data.size()) {
            DWORD written = 0;
            DWORD part = static_cast<DWORD>(std::min<size_t>(data.size() - offset, 1024 * 1024));
            require(WriteFile(file, data.data() + offset, part, &written, nullptr) && written > 0,
                    "Output write failed.");
            offset += written;
        }
        require(FlushFileBuffers(file) != 0, "Output flush failed.");
        require(CloseHandle(file) != 0, "Output close failed.");
        file = INVALID_HANDLE_VALUE;
    } catch (...) {
        if (file != INVALID_HANDLE_VALUE)
            CloseHandle(file);
        std::error_code error;
        fs::remove(path, error);
        throw;
    }
}
} // namespace q001
