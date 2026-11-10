// SPDX-License-Identifier: Apache-2.0
#include "m04.hpp"
#include "m03.hpp"
#include "m02.hpp"
#include <unordered_set>
namespace q001 {
namespace {
constexpr const char *version = "1.0.0";
struct q009 {
    VA anchor, jump, exit, q02c, q02d, q02e, q02f, root;
    int64_t size1, size2;
};
struct q00a {
    VA call, q030, q031, q032, root;
    std::vector<VA> q033;
};
struct q00b {
    bool helper;
    VA site, exit, root, filetime, ticks, q034;
};
struct q00c {
    VA site, read;
};
struct q00d {
    VA flag;
    std::vector<VA> sites;
    VA guard;
};
struct q00e {
    VA site, root;
};
struct q00f {
    VA site, exit, q035;
};
bool q017(const q002 &ins, int64_t value) {
    for (size_t n = 0; n < ins.x86.op_count; ++n)
        if (q024(ins, n) == value)
            return true;
    return false;
}
Bytes q018(const std::string &text) {
    require(text.size() % 2 == 0, "Invalid hexadecimal bytes.");
    Bytes result;
    auto nibble = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        throw std::runtime_error("Invalid hexadecimal digit.");
    };
    for (size_t n = 0; n < text.size(); n += 2)
        result.push_back(static_cast<uint8_t>((nibble(text[n]) << 4) | nibble(text[n + 1])));
    return result;
}
bool q019(const Bytes &bytes, const Bytes &needle) {
    return std::search(bytes.begin(), bytes.end(), needle.begin(), needle.end()) != bytes.end();
}
q009 q010(const q004 &code) {
    std::vector<q009> matches;
    for (const auto &ins : code.instructions) {
        if (ins.mnemonic != "mov" || !q026(code, ins, 0, {"edx"}) || !q024(ins))
            continue;
        VA owner = code.root(ins.address);
        bool clock = false;
        for (auto n : code.q047("GetSystemTime"))
            if (code.root(code.instructions[n].address) == owner)
                clock = true;
        if (!owner || !clock)
            continue;
        auto seq = code.nearby(ins.address, 4, 18);
        auto pos = std::find(seq.begin(), seq.end(), code.index.at(ins.address)) - seq.begin();
        if (pos < 2)
            continue;
        const auto &compare = code.instructions[seq[pos - 2]];
        const auto &jump = code.instructions[seq[pos - 1]];
        if (compare.mnemonic != "cmp" || jump.mnemonic != "je" || compare.op(0).size != 1 ||
            !q020(code, compare))
            continue;
        auto failure = q023(compare, 0);
        if (!failure || !code.writable(*failure))
            continue;
        std::vector<size_t> after(seq.begin() + pos, seq.end()), calls;
        for (size_t n = 0; n < after.size(); ++n)
            if (code.instructions[after[n]].mnemonic == "call")
                calls.push_back(n);
        if (calls.size() < 2)
            continue;
        size_t one = calls[0], two = calls[1];
        std::vector<VA> buf1, buf2;
        std::vector<int64_t> sizes1, sizes2;
        bool zero_fill = false;
        for (size_t n = 0; n < two; ++n) {
            const auto &i = code.instructions[after[n]];
            if (n == one)
                continue;
            bool first = n < one;
            if (i.mnemonic == "lea" && q026(code, i, 0, {"rcx"}))
                (first ? buf1 : buf2).push_back(q023(i, 1).value_or(0));
            if (i.mnemonic == "mov" && q026(code, i, 0, {"r8d"}) && q024(i))
                (first ? sizes1 : sizes2).push_back(*q024(i));
            if (n > one && i.mnemonic == "xor" && q026(code, i, 0, {"edx"}) && q026(code, i, 1, {"edx"}))
                zero_fill = true;
        }
        if (buf1.size() != 1 || buf2.size() != 1 || sizes1.size() != 1 || sizes2.size() != 1)
            continue;
        if (sizes1[0] < 256 || sizes1[0] > 65536 || sizes2[0] < 64 || sizes2[0] > 4096 || sizes1[0] % 16 ||
            sizes2[0] % 16)
            continue;
        if (code.instructions[after[one]].op_str != code.instructions[after[two]].op_str)
            continue;
        std::vector<size_t> writes;
        for (size_t n = two + 1; n < after.size(); ++n) {
            const auto &i = code.instructions[after[n]];
            if (i.mnemonic == "mov" && q023(i, 0) && i.op(0).size == 1)
                writes.push_back(after[n]);
        }
        if (writes.size() < 2)
            continue;
        if (!q020(code, code.instructions[writes[0]]) || q024(code.instructions[writes[1]]) != 1 ||
            !zero_fill)
            continue;
        auto enabled = q023(code.instructions[writes[0]], 0);
        auto target = q025(jump);
        if (!target || *target <= code.instructions[writes.back()].address || !code.contains(*target))
            continue;
        if (!code.writable(*enabled) || !code.writable(buf1[0]) || !code.writable(buf2[0]))
            continue;
        matches.push_back({ins.address, jump.address, *target, *failure, *enabled, buf1[0], buf2[0], owner,
                           sizes1[0], sizes2[0]});
    }
    return unique(matches, "Check group 3");
}
q00a q011(const q004 &code) {
    std::vector<q00a> candidates;
    for (auto call_index : code.q047("LoadLibraryW")) {
        const auto &call = code.instructions[call_index];
        const auto &seq = code.group(call.address);
        auto near = code.nearby(call.address, 0, 6);
        std::vector<std::pair<size_t, size_t>> tests;
        for (size_t n = 1; n + 1 < near.size(); ++n) {
            const auto &i = code.instructions[near[n]];
            if (i.mnemonic == "test" && q026(code, i, 0, {"rax", "eax"}) &&
                q026(code, i, 1, {"rax", "eax"}) && code.instructions[near[n + 1]].mnemonic == "je")
                tests.emplace_back(near[n], near[n + 1]);
        }
        if (tests.size() != 1)
            continue;
        const auto &test = code.instructions[tests[0].first];
        const auto &jump = code.instructions[tests[0].second];
        auto end = q025(jump);
        if (!end || !code.contains(*end))
            continue;
        std::vector<VA> resolvers;
        bool frees = false, flags = false, clobbered = false;
        for (auto n : seq) {
            const auto &i = code.instructions[n];
            if (i.address <= call.address)
                continue;
            if (i.address < *end) {
                if (code.q048(i, "GetProcAddress"))
                    resolvers.push_back(i.address);
                if (code.q048(i, "FreeLibrary"))
                    frees = true;
                if (q017(i, 2214592768))
                    flags = true;
            }
            if (i.address < test.address) {
                if (i.mnemonic != "mov")
                    clobbered = true;
                for (auto r : i.written)
                    if (q022(code.md.reg_name(r)) == "rax")
                        clobbered = true;
            }
        }
        if (resolvers.size() != 4 || !frees || !flags || clobbered)
            continue;
        if (!q019(code.data, q018("00000000963007772c610eeeba51099919c46d078ff46a7035a563e9a395649e")))
            continue;
        candidates.push_back(
            {call.address, test.address, jump.address, *end, code.root(call.address), resolvers});
    }
    return unique(candidates, "WinINet/CRC lookup");
}
q00b q012(const q004 &code, const q009 &enforcement) {
    std::set<VA> linked_roots{enforcement.root};
    for (auto n : code.group(enforcement.root)) {
        const auto &i = code.instructions[n];
        auto target = q024(i, 0);
        if (i.mnemonic == "call" && target && code.groups.count(static_cast<VA>(*target)))
            linked_roots.insert(static_cast<VA>(*target));
    }
    std::vector<VA> filetimes, tick_calls;
    for (auto n : code.q047("GetFileTime"))
        if (linked_roots.count(code.root(code.instructions[n].address)))
            filetimes.push_back(code.instructions[n].address);
    VA filetime = unique(filetimes, "GetFileTime anchor");
    VA owner = code.root(filetime);
    for (auto n : code.q047("_Xtime_get_ticks"))
        if (code.root(code.instructions[n].address) == owner)
            tick_calls.push_back(code.instructions[n].address);
    VA ticks = unique(tick_calls, "Clock anchor");
    const auto &seq = code.group(filetime);
    std::set<std::string> imported;
    bool pe_magic = false, optional_magic = false;
    for (auto n : seq) {
        const auto &i = code.instructions[n];
        for (const auto *name : {"CreateFileW", "ReadFile", "SetFilePointer", "GetSystemTimeAsFileTime"})
            if (code.q048(i, name))
                imported.insert(name);
        if (q017(i, 17744))
            pe_magic = true;
        if (q017(i, 523))
            optional_magic = true;
    }
    require(imported.size() == 4, "Self-file audit API relationships are incomplete.");
    require(pe_magic && optional_magic, "Self-file audit lacks its PE32+ parsing anchors.");
    if (owner != enforcement.root) {
        std::vector<VA> callers;
        for (const auto &i : code.instructions)
            if (i.mnemonic == "call" && q024(i, 0) == owner)
                callers.push_back(i.address);
        VA call = unique(callers, "Standalone self-audit caller");
        require(code.root(call) == enforcement.root, "Audit helper has an unexpected caller.");
        std::vector<VA> stores;
        for (auto n : code.nearby(call, 0, 4)) {
            const auto &i = code.instructions[n];
            if (i.address != call && i.mnemonic == "mov" && q023(i, 0) == enforcement.q02c &&
                q026(code, i, 1, {"al"}))
                stores.push_back(i.address);
        }
        require(stores.size() == 1 && code.at(call).size == 5,
                "Unsupported audit-helper result propagation.");
        return {true, call, 0, owner, filetime, ticks, stores[0]};
    }
    std::vector<VA> creators;
    for (auto n : seq) {
        const auto &i = code.instructions[n];
        if (i.address < filetime && code.q048(i, "CreateFileW"))
            creators.push_back(i.address);
    }
    VA creator = unique(creators, "Inline self-file open");
    std::vector<q00b> candidates;
    for (auto n : seq) {
        const auto &jump = code.instructions[n];
        if (jump.address >= creator || creator - jump.address >= 1024 || jump.mnemonic != "jne")
            continue;
        const auto *compare = q021(code, jump);
        if (!compare)
            continue;
        auto target = q025(jump);
        if (compare->mnemonic == "cmp" && q023(*compare, 0) && compare->op(0).size == 1 &&
            q020(code, *compare) && target && ticks < *target && *target <= enforcement.anchor &&
            code.contains(*target))
            candidates.push_back({false, jump.address, *target, owner, filetime, ticks, 0});
    }
    auto result = unique(candidates, "Inline self-audit skip guard");
    std::vector<VA> stores;
    for (auto n : code.q049(enforcement.q02c)) {
        const auto &i = code.instructions[n];
        if (ticks < i.address && i.address < result.exit && code.root(i.address) == owner)
            stores.push_back(i.address);
    }
    result.q034 = unique(stores, "Inline audit failure propagation");
    return result;
}
std::optional<q00c> q013(const q004 &code, const q00a &network, const q009 &enforcement) {
    std::vector<VA> reads;
    for (auto n : code.q047("GetPrivateProfileStringW"))
        if (code.root(code.instructions[n].address) == network.root)
            reads.push_back(code.instructions[n].address);
    if (reads.empty())
        return std::nullopt;
    VA read = unique(reads, "Protection configuration read");
    std::vector<VA> stores;
    for (auto n : code.q049(enforcement.q02d)) {
        const auto &i = code.instructions[n];
        if (read < i.address && i.address - read < 1024 && code.root(i.address) == network.root &&
            i.mnemonic == "mov" && q024(i) == 0)
            stores.push_back(i.address);
    }
    VA store = unique(stores, "Persistent-marker feature-disable write");
    bool writer = false;
    for (auto n : code.q047("WritePrivateProfileStringW")) {
        VA address = code.instructions[n].address;
        uint64_t distance = address > read ? address - read : read - address;
        if (code.root(address) == network.root && distance < 1024)
            writer = true;
    }
    require(writer, "Persistent marker lacks the expected configuration writer.");
    return q00c{store, read};
}
std::optional<q00d> q014(const q004 &code, const q00a &network, const q009 &enforcement) {
    std::map<VA, std::vector<VA>> writes;
    for (auto n : code.group(network.root)) {
        const auto &i = code.instructions[n];
        auto target = q023(i, 0);
        if (i.address < network.call && i.mnemonic == "mov" && target && i.op(0).size == 1 && q024(i) == 1 &&
            code.writable(*target))
            writes[*target].push_back(i.address);
    }
    std::vector<q00d> candidates;
    for (const auto &[target, stores] : writes) {
        std::vector<VA> related;
        for (auto n : code.refs(target)) {
            const auto &ref = code.instructions[n];
            if (code.root(ref.address) != network.root || ref.mnemonic != "cmp" || q024(ref) != 0)
                continue;
            auto near = code.nearby(ref.address, 0, 2);
            if (near.size() != 3)
                continue;
            const auto &jump = code.instructions[near[1]];
            const auto &store = code.instructions[near[2]];
            if (jump.mnemonic == "je" && store.mnemonic == "mov" && q023(store, 0) == enforcement.q02d &&
                q024(store) == 0)
                related.push_back(ref.address);
        }
        require(related.size() <= 1, "Ambiguous shader-marker enforcement guards.");
        if (related.size() == 1)
            candidates.push_back({target, stores, related[0]});
    }
    require(candidates.size() <= 1, "Ambiguous shader-marker flags.");
    return candidates.empty() ? std::nullopt : std::optional<q00d>(candidates[0]);
}
std::optional<q00e> q015(const q004 &code, const q009 &enforcement, const q00b &audit) {
    std::vector<VA> stores;
    for (auto n : code.q049(enforcement.q02c)) {
        const auto &i = code.instructions[n];
        if (i.mnemonic == "mov" && q024(i) == 1)
            stores.push_back(i.address);
    }
    if (stores.empty())
        return std::nullopt;
    VA store = unique(stores, "All-zero failure setter");
    size_t compares = 0;
    for (auto n : code.nearby(store, 24, 0)) {
        const auto &i = code.instructions[n];
        if (code.root(i.address) == code.root(store) && (i.mnemonic == "ucomiss" || i.mnemonic == "comiss"))
            ++compares;
    }
    require(compares >= 4, "Unrecognized additional failure-flag setter; refusing this build.");
    require(code.root(store) != audit.root, "Sentinel setter overlaps the file-audit function.");
    return q00e{store, code.root(store)};
}
std::optional<q00f> q016(const q004 &code, const q009 &enforcement) {
    std::vector<q00f> candidates;
    for (const auto &ins : code.instructions) {
        if (ins.mnemonic != "cmp" || ins.x86.op_count != 2 || ins.op(0).type != X86_OP_MEM ||
            ins.op(0).mem.disp != 80 || q024(ins) != code.pe.q03f)
            continue;
        auto seq = code.nearby(ins.address, 24, 30);
        bool dos = false, checksum = false;
        std::vector<VA> clear1, clear2;
        for (auto n : seq) {
            const auto &i = code.instructions[n];
            if (i.mnemonic == "movsxd" && i.op(1).type == X86_OP_MEM && i.op(1).mem.disp == 60)
                dos = true;
            if (i.mnemonic == "cmp" && i.op(0).type == X86_OP_MEM && i.op(0).mem.disp == 88 && q024(i) == 0)
                checksum = true;
            if (i.mnemonic == "lea" && q026(code, i, 0, {"rcx"})) {
                auto target = q023(i, 1);
                if (target == enforcement.q02e)
                    clear1.push_back(i.address);
                if (target == enforcement.q02f)
                    clear2.push_back(i.address);
            }
        }
        if (!dos || !checksum || clear1.size() != 1 || clear2.size() != 1)
            continue;
        std::vector<std::pair<VA, VA>> guards;
        for (size_t n = 0; n + 1 < seq.size(); ++n) {
            const auto &compare = code.instructions[seq[n]];
            const auto &jump = code.instructions[seq[n + 1]];
            auto target = q025(jump);
            if (compare.address < ins.address && compare.mnemonic == "cmp" && q023(compare, 0) &&
                compare.op(0).size == 1 && q024(compare) == 0 && jump.mnemonic == "jne" && target &&
                clear2[0] < *target && *target - clear2[0] < 64 && code.contains(*target))
                guards.emplace_back(jump.address, *target);
        }
        require(guards.size() == 1,
                "A PE integrity block was found but its skip guard is unsupported or ambiguous.");
        candidates.push_back({guards[0].first, guards[0].second, ins.address});
    }
    require(candidates.size() <= 1, "Ambiguous in-memory PE integrity checks.");
    return candidates.empty() ? std::nullopt : std::optional<q00f>(candidates[0]);
}
Bytes q01a(const q002 &ins, VA target) {
    require(ins.mnemonic == "je" || ins.mnemonic == "jne", "Expected a supported conditional jump.");
    if (ins.size == 2) {
        int64_t delta = static_cast<int64_t>(target) - static_cast<int64_t>(ins.address + 2);
        require(delta >= -128 && delta <= 127, "Short jump is out of range.");
        return {235, static_cast<uint8_t>(delta)};
    }
    require(ins.size == 6, "Unsupported conditional-jump encoding.");
    int64_t delta = static_cast<int64_t>(target) - static_cast<int64_t>(ins.address + 5);
    require(delta >= INT32_MIN && delta <= INT32_MAX, "Near jump is out of range.");
    Bytes result{233, 0, 0, 0, 0, 144};
    int32_t relative = static_cast<int32_t>(delta);
    std::memcpy(result.data() + 1, &relative, 4);
    return result;
}
json q01b(const q004 &code, const std::string &name, VA address, const Bytes &replacement) {
    const auto &ins = code.at(address);
    require(replacement.size() == ins.size, "Patch would split or resize an instruction.");
    require(address >= code.base, "Patch is below image base.");
    auto rva = address - code.base;
    size_t off = code.pe.q03c(rva, ins.size);
    bool executable = false;
    for (const auto &s : code.pe.sections)
        if ((s.characteristics & 536870912) && s.q041 <= rva && rva + ins.size <= uint64_t(s.q041) + s.q044)
            executable = true;
    require(executable, "Patch is outside a file-backed executable section.");
    auto decoded = code.md.decode(replacement.data(), replacement.size(), address);
    size_t total = 0;
    for (const auto &i : decoded)
        total += i.size;
    require(!decoded.empty() && total == ins.size, "Replacement is not a complete instruction sequence.");
    return {{"name", name},
            {"offset", off},
            {"rva", rva},
            {"original", q027(ins.bytes)},
            {"replacement", q027(replacement)},
            {"instruction", ins.mnemonic + " " + ins.op_str}};
}
bool q01c(const q004 &code, VA address) {
    require(code.writable(address), "A protection flag is outside writable data.");
    auto rva = address - code.base;
    for (const auto &s : code.pe.sections)
        if (s.q041 <= rva && rva - s.q041 < s.q045())
            return rva - s.q041 >= s.q044 || code.read(address, 1) == Bytes{0};
    throw std::runtime_error("Protection flag section is missing.");
}
std::unordered_set<VA> q01d(const q004 &code, VA start, VA root,
                            const std::map<VA, std::vector<VA>> &forced = {}) {
    std::unordered_set<VA> seen;
    std::vector<VA> todo{start};
    while (!todo.empty()) {
        VA address = todo.back();
        todo.pop_back();
        if (seen.count(address) || !code.contains(address) || code.root(address) != root)
            continue;
        seen.insert(address);
        require(seen.size() <= 250000, "Control-flow validation exceeded its limit.");
        const auto &ins = code.at(address);
        if (auto it = forced.find(address); it != forced.end()) {
            todo.insert(todo.end(), it->second.begin(), it->second.end());
            continue;
        }
        if (ins.ret || ins.mnemonic == "int3" || ins.mnemonic == "ud2" || ins.mnemonic == "int" ||
            ins.mnemonic == "hlt")
            continue;
        if (ins.jump) {
            if (auto target = q025(ins))
                todo.push_back(*target);
            if (ins.mnemonic == "jmp")
                continue;
        }
        todo.push_back(address + ins.size);
    }
    return seen;
}
json q01e(const q004 &code, const Bytes &patched, const json &patches, const q00a &network, const q00b &audit,
          const q009 &enforcement, const std::optional<q00f> &memory) {
    require(patched.size() == code.data.size(), "Output size changed.");
    std::set<size_t> allowed;
    for (const auto &p : patches) {
        size_t off = p.at("offset").get<size_t>();
        auto old = q018(p.at("original"));
        auto replacement = q018(p.at("replacement"));
        require(off <= patched.size() && replacement.size() <= patched.size() - off &&
                    old.size() == replacement.size(),
                "Invalid patch span.");
        require(std::equal(old.begin(), old.end(), code.data.begin() + off), "Source instruction changed.");
        require(std::equal(replacement.begin(), replacement.end(), patched.begin() + off),
                "Output does not match its patch plan.");
        for (size_t n = off; n < off + old.size(); ++n)
            require(allowed.insert(n).second, "Overlapping patches are unsupported.");
    }
    for (size_t n = 0; n < patched.size(); ++n)
        require(patched[n] == code.data[n] || allowed.count(n),
                "Bytes outside the declared patch spans changed.");
    q004 after(patched);
    require(after.pe.imports() == code.pe.imports(), "Import declarations changed.");
    require(after.pe.directories == code.pe.directories && after.pe.sections == code.pe.sections,
            "PE structure changed.");
    require(std::equal(patched.begin(), patched.begin() + code.pe.q040, code.data.begin()),
            "PE headers changed.");
    auto seen = q01d(after, network.call, network.root, {{network.q031, {network.q032}}});
    require(seen.count(network.q031), "The null-library branch is unreachable after replacement.");
    for (auto resolver : network.q033)
        require(!seen.count(resolver),
                "A WinINet API resolver remains reachable through normal direct flow.");
    if (!audit.helper) {
        seen = q01d(after, audit.site, audit.root);
        require(!seen.count(audit.filetime) && !seen.count(audit.ticks),
                "The self-file audit remains reachable through its skip path.");
    } else {
        const auto &first = after.at(audit.site);
        require(first.mnemonic == "xor" && first.op_str == "eax, eax",
                "The self-audit helper replacement does not return false.");
    }
    seen = q01d(after, enforcement.jump, enforcement.root);
    require(!seen.count(enforcement.anchor), "Delayed enforcement remains reachable through its guard.");
    if (memory) {
        seen = q01d(after, memory->site, after.root(memory->site));
        require(!seen.count(memory->q035), "The memory audit remains reachable through its guard.");
    }
    for (const auto &p : patches) {
        std::string name = p.at("name");
        if (name == "Check group 2" || name == "Check group 3" || name == "Check group 7") {
            VA address = code.base + p.at("rva").get<VA>();
            const auto &ins = after.at(address);
            if (ins.mnemonic == "jmp")
                require(q025(ins) == q025(code.at(address)), "A skip destination changed.");
        }
    }
    return {{"instruction_spans", true},
            {"only_declared_executable_bytes_changed", true},
            {"pe_headers_and_directories_preserved", true},
            {"imports_preserved", true},
            {"normal_direct_skip_paths", true},
            {"scope", "Static analysis; no exception/indirect-target proof or in-game execution."}};
}
std::pair<json, Bytes> q01f(const Bytes &data) {
    q004 code(data);
    const char anchor[] = "ReShadeRegisterAddon";
    require(q019(data, Bytes(anchor, anchor + sizeof(anchor))),
            "Expected add-on registration import is absent.");
    auto enforcement = q010(code);
    auto network = q011(code);
    auto audit = q012(code, enforcement);
    auto persistent = q013(code, network, enforcement);
    auto markers = q014(code, network, enforcement);
    auto sentinel = q015(code, enforcement, audit);
    auto memory = q016(code, enforcement);
    require(q01c(code, enforcement.q02c), "The initial failure flag is not zero.");
    std::set<VA> known{audit.q034}, actual;
    if (sentinel)
        known.insert(sentinel->site);
    for (auto n : code.q049(enforcement.q02c))
        actual.insert(code.instructions[n].address);
    require(actual == known, "Unrecognized failure-flag writer; refusing a partial patch.");
    if (markers) {
        require(q01c(code, markers->flag), "The initial shader-marker flag is not zero.");
        actual.clear();
        for (auto n : code.q049(markers->flag))
            actual.insert(code.instructions[n].address);
        require(actual == std::set<VA>(markers->sites.begin(), markers->sites.end()),
                "Unrecognized shader-marker writer.");
    }
    json patches = json::array(), features = json::array();
    auto add = [&](const std::string &name, const std::vector<VA> &sites,
                   const std::vector<Bytes> &replacements, bool optional = false) {
        require(sites.size() == replacements.size(), "Internal patch-plan length mismatch.");
        for (size_t n = 0; n < sites.size(); ++n)
            patches.push_back(q01b(code, name, sites[n], replacements[n]));
        features.push_back({{"name", name},
                            {"status", sites.empty() ? "not detected" : "matched"},
                            {"patches", sites.size()},
                            {"optional", optional}});
    };
    auto zero_return = [&](VA address) {
        require(code.at(address).size >= 2, "Unsupported library-call encoding.");
        Bytes replacement(code.at(address).size, 144);
        replacement[0] = 49;
        replacement[1] = 192;
        return replacement;
    };
    add("Check group 1", {network.call}, {zero_return(network.call)});
    add("Check group 2", {audit.site},
        {audit.helper ? zero_return(audit.site) : q01a(code.at(audit.site), audit.exit)});
    add("Check group 3", {enforcement.jump}, {q01a(code.at(enforcement.jump), enforcement.exit)});
    if (persistent)
        add("Check group 4", {persistent->site}, {Bytes(code.at(persistent->site).size, 144)}, true);
    else
        add("Check group 4", {}, {}, true);
    auto marker_replacements = [&](const std::vector<VA> &sites) {
        std::vector<Bytes> replacements;
        for (auto site : sites) {
            const auto &ins = code.at(site);
            require(ins.mnemonic == "mov" && q024(ins) == 1 && ins.x86.encoding.imm_size == 1,
                    "Unsupported marker-store encoding.");
            auto replacement = ins.bytes;
            require(ins.x86.encoding.imm_offset < replacement.size(), "Invalid marker immediate offset.");
            replacement[ins.x86.encoding.imm_offset] = 0;
            replacements.push_back(std::move(replacement));
        }
        return replacements;
    };
    auto sites = markers ? markers->sites : std::vector<VA>{};
    add("Check group 5", sites, marker_replacements(sites), true);
    sites = sentinel ? std::vector<VA>{sentinel->site} : std::vector<VA>{};
    add("Check group 6", sites, marker_replacements(sites), true);
    if (memory)
        add("Check group 7", {memory->site}, {q01a(code.at(memory->site), memory->exit)}, true);
    else
        add("Check group 7", {}, {}, true);
    std::sort(patches.begin(), patches.end(), [](const json &a, const json &b) {
        return a.at("offset").get<size_t>() < b.at("offset").get<size_t>();
    });
    Bytes patched = data;
    for (const auto &p : patches) {
        auto off = p.at("offset").get<size_t>();
        auto replacement = q018(p.at("replacement"));
        std::copy(replacement.begin(), replacement.end(), patched.begin() + off);
    }
    auto verification = q01e(code, patched, patches, network, audit, enforcement, memory);
    size_t changed = 0;
    for (size_t n = 0; n < data.size(); ++n)
        if (data[n] != patched[n])
            ++changed;
    json result = {{"engine_version", version},
                   {"implementation", "native C++"},
                   {"supported", true},
                   {"architecture", "AMD64 PE32+"},
                   {"input_sha256", sha256(data)},
                   {"input_size", data.size()},
                   {"patch_count", patches.size()},
                   {"changed_byte_count", changed},
                   {"features", features},
                   {"patches", patches},
                   {"audit_form", audit.helper ? "helper" : "inline"},
                   {"verification", verification}};
    return {std::move(result), std::move(patched)};
}
} // namespace

json q029(const json &input) {
    json output = json::object();
    for (const char *key : {"engine_version", "implementation", "supported", "architecture", "input_size",
                            "patch_count", "changed_byte_count", "original_unchanged"})
        if (input.contains(key))
            output[key] = input[key];
    if (input.contains("verification"))
        output["verification"] = input["verification"];
    if (input.contains("reason"))
        output["reason"] = "Input could not be accepted.";
    output["features"] = input.value("features", json::array());
    output["patches"] = json::array();
    size_t index = 0;
    for (const auto &item : input.value("patches", json::array())) {
        output["patches"].push_back({{"name", "Change " + std::to_string(++index)},
                                     {"size", item.value("original", std::string{}).size() / 2}});
    }
    return output;
}

json q02a(const fs::path &path) {
    Bytes data;
    bool loaded = false;
    try {
        auto source = checked_path(path);
        data = read_input(source);
        loaded = true;
        auto [result, patched] = q01f(data);
        result["file"] = path_utf8(source);
        return result;
    } catch (const std::exception &e) {
        return {{"engine_version", version},
                {"implementation", "native C++"},
                {"supported", false},
                {"file", path_utf8(path)},
                {"reason", e.what()},
                {"patch_count", 0},
                {"features", json::array()},
                {"patches", json::array()},
                {"input_sha256", loaded ? json(sha256(data)) : json(nullptr)}};
    }
}
json q02b(const fs::path &input, const fs::path &output, const std::optional<std::string> &expected) {
    auto source = checked_path(input), destination = checked_path(output);
    require(source != destination, "Output must not overwrite the input.");
    fs::path manifest_path = destination;
    manifest_path += L".patch.json";
    require(!fs::exists(destination), "Output already exists; choose a new filename.");
    require(!fs::exists(manifest_path), "Manifest already exists; choose a new filename.");
    require(fs::is_directory(destination.parent_path()), "Output directory does not exist.");
    auto data = read_input(source);
    if (expected)
        require(sha256(data) == *expected, "Input changed since inspection; inspect it again.");
    auto [result, patched] = q01f(data);
    require(read_input(source) == data, "Input changed during analysis; no output was written.");
    result["file"] = path_utf8(source);
    result["output"] = path_utf8(destination);
    result["output_sha256"] = sha256(patched);
    result["manifest_path"] = path_utf8(manifest_path);
    result["original_unchanged"] = true;
    auto encoded = q029(result).dump(2) + "\n";
    bool created_output = false, created_manifest = false;
    try {
        write_exclusive(destination, patched);
        created_output = true;
        write_exclusive(manifest_path, Bytes(encoded.begin(), encoded.end()));
        created_manifest = true;
        require(sha256(read_input(destination)) == result.at("output_sha256").get<std::string>(),
                "Output read-back verification failed.");
    } catch (...) {
        std::error_code error;
        if (created_manifest)
            fs::remove(manifest_path, error);
        if (created_output)
            fs::remove(destination, error);
        throw;
    }
    return result;
}
} // namespace q001
