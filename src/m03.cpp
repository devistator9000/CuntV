// SPDX-License-Identifier: Apache-2.0
#include "m03.hpp"
namespace q001 {
q003::q003() {
    require(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK, "Cannot initialize AMD64 disassembler.");
    require(cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK, "Cannot enable instruction details.");
    require(cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON) == CS_ERR_OK, "Cannot enable skip-data decoding.");
}
q003::~q003() {
    if (handle)
        cs_close(&handle);
}
std::string q003::reg_name(unsigned reg) const {
    const char *name = cs_reg_name(handle, reg);
    return name ? name : "";
}
std::vector<q002> q003::decode(const uint8_t *data, size_t size, VA address) const {
    cs_insn *decoded = nullptr;
    size_t count = cs_disasm(handle, data, size, address, 0, &decoded);
    struct Cleanup {
        cs_insn *p;
        size_t n;
        ~Cleanup() { cs_free(p, n); }
    } cleanup{decoded, count};
    std::vector<q002> result;
    result.reserve(count);
    for (size_t n = 0; n < count; ++n) {
        const auto &in = decoded[n];
        if (!in.id)
            continue;
        require(in.detail != nullptr, "Missing instruction details.");
        q002 ins;
        ins.address = in.address;
        ins.size = in.size;
        ins.id = in.id;
        ins.mnemonic = in.mnemonic;
        ins.op_str = in.op_str;
        ins.bytes.assign(in.bytes, in.bytes + in.size);
        ins.x86 = in.detail->x86;
        ins.jump = cs_insn_group(handle, &in, CS_GRP_JUMP);
        ins.ret = cs_insn_group(handle, &in, CS_GRP_RET);
        cs_regs reads{}, writes{};
        uint8_t read_count = 0, write_count = 0;
        require(cs_regs_access(handle, &in, reads, &read_count, writes, &write_count) == CS_ERR_OK,
                "Cannot decode register accesses.");
        ins.written.assign(writes, writes + write_count);
        result.push_back(std::move(ins));
    }
    return result;
}
std::optional<VA> q023(const q002 &ins, size_t operand) {
    const auto &op = ins.op(operand);
    if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP)
        return ins.address + ins.size + op.mem.disp;
    return std::nullopt;
}
std::optional<int64_t> q024(const q002 &ins, size_t operand) {
    if (ins.op(operand).type == X86_OP_IMM)
        return ins.op(operand).imm;
    return std::nullopt;
}
std::optional<VA> q025(const q002 &ins) {
    auto target = q024(ins, 0);
    if (ins.jump && target)
        return static_cast<VA>(*target);
    return std::nullopt;
}
bool q026(const q004 &code, const q002 &ins, size_t n, std::initializer_list<const char *> names) {
    if (ins.op(n).type != X86_OP_REG)
        return false;
    auto name = code.md.reg_name(ins.op(n).reg);
    for (const auto *candidate : names)
        if (name == candidate)
            return true;
    return false;
}
std::string q022(const std::string &name) {
    static const std::vector<std::vector<std::string>> families = {
        {"rax", "eax", "ax", "al", "ah"}, {"rbx", "ebx", "bx", "bl", "bh"}, {"rcx", "ecx", "cx", "cl", "ch"},
        {"rdx", "edx", "dx", "dl", "dh"}, {"rsi", "esi", "si", "sil"},      {"rdi", "edi", "di", "dil"},
        {"rbp", "ebp", "bp", "bpl"},      {"rsp", "esp", "sp", "spl"}};
    for (const auto &family : families)
        if (std::find(family.begin(), family.end(), name) != family.end())
            return family.front();
    for (unsigned n = 8; n < 16; ++n) {
        auto stem = "r" + std::to_string(n);
        if (name == stem || name == stem + "d" || name == stem + "w" || name == stem + "b")
            return stem;
    }
    return name;
}
q004::q004(const Bytes &bytes) : data(bytes), pe(data), base(pe.q03e) {
    require(data.size() >= 1024 && data.size() <= 128 * 1024 * 1024,
            "File size is outside the supported range.");
    for (const auto &symbol : pe.imports())
        imports[base + symbol.q046] = symbol.name;
    for (const auto &section : pe.sections)
        if (section.characteristics & 536870912) {
            auto decoded = md.decode(data.data() + section.q043, section.q044, base + section.q041);
            instructions.insert(instructions.end(), std::make_move_iterator(decoded.begin()),
                                std::make_move_iterator(decoded.end()));
        }
    std::sort(instructions.begin(), instructions.end(),
              [](const auto &a, const auto &b) { return a.address < b.address; });
    for (size_t n = 0; n < instructions.size(); ++n)
        require(index.emplace(instructions[n].address, n).second, "Overlapping instruction addresses.");
    runtime = pe.q03b();
    for (const auto &entry : runtime)
        q04b[entry.q036] = base + pe.q039(entry).q036;
    for (size_t n = 0; n < instructions.size(); ++n) {
        const auto &ins = instructions[n];
        VA owner = root(ins.address);
        if (owner)
            groups[owner].push_back(n);
        for (size_t op = 0; op < ins.x86.op_count; ++op)
            if (auto target = q023(ins, op))
                q04a[*target].push_back(n);
        if (ins.mnemonic == "call")
            if (auto target = q023(ins, 0)) {
                auto found = imports.find(*target);
                if (found != imports.end() && !found->second.empty())
                    calls[found->second].push_back(n);
            }
    }
}
VA q004::root(VA address) const {
    if (address < base)
        return 0;
    auto rva = address - base;
    auto it = std::upper_bound(runtime.begin(), runtime.end(), rva,
                               [](uint64_t value, const q007 &entry) { return value < entry.q036; });
    if (it == runtime.begin())
        return 0;
    --it;
    if (rva >= it->q037)
        return 0;
    auto found = q04b.find(it->q036);
    return found == q04b.end() ? 0 : found->second;
}
const q002 &q004::at(VA address) const {
    auto it = index.find(address);
    require(it != index.end(), "Incomplete instruction map.");
    return instructions[it->second];
}
const std::vector<size_t> &q004::group(VA address) const {
    auto owner = root(address);
    require(owner != 0, "Incomplete function map.");
    auto found = groups.find(owner);
    require(found != groups.end(), "Empty owning function.");
    return found->second;
}
std::vector<size_t> q004::nearby(VA address, size_t before, size_t after) const {
    auto it = index.find(address);
    require(it != index.end(), "Missing nearby instruction.");
    size_t n = it->second;
    std::vector<size_t> result;
    size_t end = std::min(instructions.size(), n + after + 1);
    for (size_t pos = n > before ? n - before : 0; pos < end; ++pos)
        result.push_back(pos);
    return result;
}
const std::vector<size_t> &q004::q047(const std::string &name) const {
    static const std::vector<size_t> empty;
    auto it = calls.find(name);
    return it == calls.end() ? empty : it->second;
}
const std::vector<size_t> &q004::refs(VA address) const {
    static const std::vector<size_t> empty;
    auto it = q04a.find(address);
    return it == q04a.end() ? empty : it->second;
}
bool q004::q048(const q002 &ins, const std::string &name) const {
    if (ins.mnemonic != "call")
        return false;
    auto target = q023(ins, 0);
    if (!target)
        return false;
    auto it = imports.find(*target);
    return it != imports.end() && it->second == name;
}
bool q004::writable(VA address) const {
    if (address < base)
        return false;
    auto rva = address - base;
    for (const auto &s : pe.sections)
        if (s.q041 <= rva && rva - s.q041 < s.q045() && (s.characteristics & 2147483648) &&
            !(s.characteristics & 536870912))
            return true;
    return false;
}
Bytes q004::read(VA address, size_t size) const {
    require(address >= base, "VA below image base.");
    auto off = pe.q03c(address - base, size);
    return Bytes(data.begin() + off, data.begin() + off + size);
}
std::vector<size_t> q004::q049(VA address) const {
    std::vector<size_t> result;
    for (auto n : refs(address)) {
        const auto &ins = instructions[n];
        if (q023(ins, 0) == address && ins.op(0).size == 1 &&
            ((ins.op(0).access & CS_AC_WRITE) || ins.mnemonic == "mov" || ins.mnemonic == "xchg"))
            result.push_back(n);
    }
    return result;
}
bool q020(const q004 &code, const q002 &at, size_t operand) {
    if (q024(at, operand) == 0)
        return true;
    if (at.op(operand).type != X86_OP_REG)
        return false;
    auto family = q022(code.md.reg_name(at.op(operand).reg));
    bool volatile_reg = family == "rax" || family == "rcx" || family == "rdx" || family == "r8" ||
                        family == "r9" || family == "r10" || family == "r11";
    const auto &sequence = code.group(at.address);
    for (auto it = sequence.rbegin(); it != sequence.rend(); ++it) {
        const auto &ins = code.instructions[*it];
        if (ins.address >= at.address)
            continue;
        if (ins.mnemonic == "call" && volatile_reg)
            return false;
        bool writes = false;
        for (auto reg : ins.written)
            if (q022(code.md.reg_name(reg)) == family)
                writes = true;
        if (!writes)
            continue;
        if ((ins.mnemonic == "xor" || ins.mnemonic == "sub") && ins.x86.op_count == 2 &&
            ins.op(0).type == X86_OP_REG && ins.op(1).type == X86_OP_REG && ins.op(0).reg == ins.op(1).reg)
            return true;
        return ins.mnemonic == "mov" && q024(ins) == 0;
    }
    return false;
}
const q002 *q021(const q004 &code, const q002 &branch) {

    constexpr uint64_t writes = 574348599054305279ULL;
    auto sequence = code.nearby(branch.address, 32, 0);
    if (!sequence.empty())
        sequence.pop_back();
    for (auto it = sequence.rbegin(); it != sequence.rend(); ++it) {
        const auto &ins = code.instructions[*it];
        if (code.root(ins.address) != code.root(branch.address) || ins.mnemonic == "call")
            return nullptr;
        if (ins.x86.eflags & writes)
            return &ins;
    }
    return nullptr;
}
} // namespace q001
