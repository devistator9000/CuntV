// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "base.hpp"
namespace q001 {
json q029(const json &input);
json q02a(const fs::path &path);
json q02b(const fs::path &input, const fs::path &output,
          const std::optional<std::string> &expected_input_sha256 = std::nullopt);
} // namespace q001
