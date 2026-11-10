// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "base.hpp"
namespace q001 {
fs::path checked_path(const fs::path &path);
Bytes read_input(const fs::path &path);
std::string sha256(const Bytes &data);
void write_exclusive(const fs::path &path, const Bytes &data);
} // namespace q001
