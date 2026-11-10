// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "m01.hpp"
#include <capstone/capstone.h>
#include <unordered_map>
namespace q001 {
struct q002 {
    VA address{};
    uint16_t size{};
    unsigned id{};
    std::string mnemonic, op_str;
    Bytes bytes;
    cs_x86 x86{};
    std::vector<uint16_t> written;
    bool jump{}, ret{};
    const cs_x86_op &op(size_t n) const {
        static const cs_x86_op empty{};
        return n < x86.op_count ? x86.operands[n] : empty;
    }
};
struct q003 {
    csh handle{};
    q003();
    ~q003();
    q003(const q003 &) = delete;
    std::vector<q002> decode(const uint8_t *, size_t, VA) const;
    std::string reg_name(unsigned reg) const;
};
class q004 {
  public:
    Bytes data;
    q005 pe;
    VA base;
    q003 md;
    std::vector<q002> instructions;
    std::vector<q007> runtime;
    std::unordered_map<VA, size_t> index;
    std::map<VA, VA> q04b;
    std::map<VA, std::vector<size_t>> groups, q04a;
    std::map<VA, std::string> imports;
    std::map<std::string, std::vector<size_t>> calls;
    explicit q004(const Bytes &bytes);
    VA root(VA address) const;
    const q002 &at(VA address) const;
    bool contains(VA address) const { return index.count(address) != 0; }
    const std::vector<size_t> &group(VA address) const;
    std::vector<size_t> nearby(VA address, size_t before = 0, size_t after = 0) const;
    const std::vector<size_t> &q047(const std::string &name) const;
    const std::vector<size_t> &refs(VA address) const;
    bool q048(const q002 &ins, const std::string &name) const;
    bool writable(VA address) const;
    Bytes read(VA address, size_t size) const;
    std::vector<size_t> q049(VA address) const;
};
std::optional<VA> q023(const q002 &ins, size_t operand = 0);
std::optional<int64_t> q024(const q002 &ins, size_t operand = 1);
std::optional<VA> q025(const q002 &ins);
bool q026(const q004 &, const q002 &, size_t, std::initializer_list<const char *>);
std::string q022(const std::string &name);
bool q020(const q004 &, const q002 &, size_t operand = 1);
const q002 *q021(const q004 &, const q002 &);
template <class T> T unique(const std::vector<T> &values, const std::string &label) {
    require(values.size() == 1, label + ": expected one match, found " + std::to_string(values.size()) + ".");
    return values.front();
}
} // namespace q001
