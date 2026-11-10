// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
namespace q001 {
namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;
using VA = uint64_t;
using json = nlohmann::json;
inline void require(bool condition, const std::string &message) {
    if (!condition)
        throw std::runtime_error(message);
}
template <class T> T read_le(const Bytes &data, size_t offset) {
    require(offset <= data.size() && sizeof(T) <= data.size() - offset, "Truncated binary field.");
    T value;
    std::memcpy(&value, data.data() + offset, sizeof(T));
    return value;
}
std::string q027(const Bytes &data);
std::string q028(uint64_t value);
std::string path_utf8(const fs::path &path);
std::wstring from_utf8(const std::string &text);
} // namespace q001
