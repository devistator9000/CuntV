// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "base.hpp"

namespace q001 {
struct q006 {
    std::string name;
    uint32_t q041{}, q042{}, q043{}, q044{}, characteristics{};
    uint64_t q045() const { return std::max<uint64_t>(q042, q044); }
    bool operator==(const q006 &) const = default;
};
struct q007 {
    uint32_t q036{}, q037{}, q038{};
    bool operator==(const q007 &) const = default;
};
struct q008 {
    std::string dll, name;
    std::optional<uint16_t> ordinal;
    uint32_t q046{};
    bool delayed{};
    bool operator==(const q008 &) const = default;
};
class q005 {
  public:
    explicit q005(const Bytes &data);
    const Bytes &data;
    uint64_t q03e{};
    uint32_t q03f{}, q040{};
    std::vector<q006> sections;
    std::vector<std::pair<uint32_t, uint32_t>> directories;
    size_t q03c(uint64_t rva, size_t size = 1) const;
    uint64_t q03d(size_t offset, size_t size = 1) const;
    std::vector<q008> imports(bool include_delay = true) const;
    std::vector<q007> q03b() const;
    q007 q039(const q007 &, size_t max_depth = 64) const;
    std::optional<q007> q03a(uint64_t va) const;

  private:
    void need(uint64_t off, uint64_t size, const char *what = "data") const;
    uint16_t u16(uint64_t off) const;
    uint32_t u32(uint64_t off) const;
    uint64_t u64(uint64_t off) const;
    std::pair<uint32_t, uint32_t> directory(size_t index) const;
    std::string cstring(uint64_t rva, size_t limit = 4096) const;
};
} // namespace q001
