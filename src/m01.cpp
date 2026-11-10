// SPDX-License-Identifier: Apache-2.0
#include "m01.hpp"
#include <tuple>

namespace q001 {
void q005::need(uint64_t off, uint64_t size, const char *what) const {
    require(off <= data.size() && size <= data.size() - static_cast<size_t>(off),
            std::string(what) + " exceeds file bounds");
}
uint16_t q005::u16(uint64_t off) const {
    need(off, 2);
    return read_le<uint16_t>(data, static_cast<size_t>(off));
}
uint32_t q005::u32(uint64_t off) const {
    need(off, 4);
    return read_le<uint32_t>(data, static_cast<size_t>(off));
}
uint64_t q005::u64(uint64_t off) const {
    need(off, 8);
    return read_le<uint64_t>(data, static_cast<size_t>(off));
}
std::pair<uint32_t, uint32_t> q005::directory(size_t i) const {
    return i < directories.size() ? directories[i] : std::pair<uint32_t, uint32_t>{0, 0};
}

q005::q005(const Bytes &input) : data(input) {
    need(0, 64, "DOS header");
    require(data[0] == 'M' && data[1] == 'Z', "missing DOS MZ signature");
    uint64_t pe = u32(60);
    need(pe, 24, "PE/COFF headers");
    require(u32(pe) == 17744, "missing PE signature");
    uint64_t coff = pe + 4;
    uint16_t machine = u16(coff), nsects = u16(coff + 2), opt_size = u16(coff + 16);
    require(machine == 34404, "unsupported machine; expected AMD64");
    uint64_t opt = coff + 20;
    need(opt, opt_size, "optional header");
    require(opt_size >= 112 && u16(opt) == 523, "expected a complete PE32+ optional header");
    q03e = u64(opt + 24);
    q03f = u32(opt + 56);
    q040 = u32(opt + 60);
    uint32_t ndirs = u32(opt + 108);
    require(ndirs <= (opt_size - 112) / 8, "data-directory count exceeds optional header");
    for (uint32_t i = 0; i < ndirs; ++i)
        directories.emplace_back(u32(opt + 112 + uint64_t(i) * 8), u32(opt + 116 + uint64_t(i) * 8));
    require(q03f != 0 && q040 <= data.size(), "invalid image/header size");
    require(q03e <= UINT64_MAX - q03f, "image VA range overflows");
    uint64_t st = opt + opt_size;
    need(st, uint64_t(nsects) * 40, "section table");
    require(st + uint64_t(nsects) * 40 <= q040, "section table exceeds SizeOfHeaders");
    for (uint32_t i = 0; i < nsects; ++i) {
        uint64_t off = st + uint64_t(i) * 40;
        std::string name;
        for (size_t j = 0; j < 8 && data[off + j]; ++j) {
            unsigned char c = data[off + j];
            name.push_back(c < 128 ? static_cast<char>(c) : '?');
        }
        q006 s{name, u32(off + 12), u32(off + 8), u32(off + 20), u32(off + 16), u32(off + 36)};
        if (s.q044)
            require(s.q043 <= data.size() && s.q044 <= data.size() - s.q043,
                    "section raw data exceeds file bounds");
        if (s.q044)
            require(s.q043 >= q040, "section raw data overlaps PE headers");
        if (s.q045())
            require(s.q041 >= q040, "section virtual range overlaps PE headers");
        require(s.q041 <= q03f && s.q045() <= q03f - s.q041, "section exceeds SizeOfImage");
        sections.push_back(std::move(s));
    }
    auto validate = [](std::vector<std::tuple<uint64_t, uint64_t, std::string>> ranges) {
        std::sort(ranges.begin(), ranges.end());
        for (size_t i = 1; i < ranges.size(); ++i)
            require(std::get<0>(ranges[i]) >= std::get<1>(ranges[i - 1]),
                    "overlapping section ranges: '" + std::get<2>(ranges[i - 1]) + "' and '" +
                        std::get<2>(ranges[i]) + "'");
    };
    std::vector<std::tuple<uint64_t, uint64_t, std::string>> vr, rr;
    for (const auto &s : sections) {
        if (s.q045())
            vr.emplace_back(s.q041, uint64_t(s.q041) + s.q045(), s.name);
        if (s.q044)
            rr.emplace_back(s.q043, uint64_t(s.q043) + s.q044, s.name);
    }
    validate(std::move(vr));
    validate(std::move(rr));
}
size_t q005::q03c(uint64_t rva, size_t size) const {
    require(rva <= q03f && size <= uint64_t(q03f) - rva, "RVA range exceeds image bounds");
    if (rva < q040) {
        require(size <= uint64_t(q040) - rva, "RVA range crosses header boundary");
        need(rva, size, "header RVA");
        return static_cast<size_t>(rva);
    }
    const q006 *found = nullptr;
    for (const auto &s : sections)
        if (rva >= s.q041 && rva - s.q041 < s.q044) {
            require(!found, "RVA is unmapped or ambiguous");
            found = &s;
        }
    require(found, "RVA is unmapped or ambiguous");
    uint64_t delta = rva - found->q041;
    require(size <= uint64_t(found->q044) - delta, "RVA range is not backed by file data");
    uint64_t off = uint64_t(found->q043) + delta;
    need(off, size, "mapped RVA");
    return static_cast<size_t>(off);
}
uint64_t q005::q03d(size_t offset, size_t size) const {
    require(offset <= data.size() && size <= data.size() - offset, "file range exceeds bounds");
    if (offset < q040) {
        require(size <= uint64_t(q040) - offset, "file range crosses header boundary");
        return offset;
    }
    const q006 *found = nullptr;
    for (const auto &s : sections)
        if (offset >= s.q043 && offset - s.q043 < s.q044) {
            require(!found, "file offset is unmapped or ambiguous");
            found = &s;
        }
    require(found, "file offset is unmapped or ambiguous");
    uint64_t delta = offset - found->q043;
    require(size <= uint64_t(found->q044) - delta, "file range crosses section boundary");
    return uint64_t(found->q041) + delta;
}
std::string q005::cstring(uint64_t rva, size_t limit) const {
    size_t off = q03c(rva, 1);
    uint64_t span;
    if (rva < q040)
        span = q040 - rva;
    else {
        const q006 *s = nullptr;
        for (const auto &x : sections)
            if (rva >= x.q041 && rva - x.q041 < x.q044) {
                s = &x;
                break;
            }
        require(s, "RVA is unmapped or ambiguous");
        span = s->q044 - (rva - s->q041);
    }
    size_t n = static_cast<size_t>(std::min<uint64_t>(limit, span));
    auto it = std::find(data.begin() + off, data.begin() + off + n, uint8_t(0));
    require(it != data.begin() + off + n, "unterminated string");
    std::string out;
    for (auto p = data.begin() + off; p != it; ++p)
        out.push_back(*p < 128 ? static_cast<char>(*p) : '?');
    return out;
}
std::vector<q008> q005::imports(bool include_delay) const {
    std::vector<q008> out;
    for (bool delayed : {false, true}) {
        if (delayed && !include_delay)
            continue;
        auto [rva, size] = directory(delayed ? 13 : 1);
        if (!rva || !size)
            continue;
        uint32_t ds = delayed ? 32 : 20;
        uint32_t count = size / ds;
        bool terminated = false;
        for (uint32_t i = 0; i < count; ++i) {
            uint64_t desc = uint64_t(rva) + uint64_t(i) * ds;
            size_t off = q03c(desc, ds);
            uint32_t name_rva, iat, thunk;
            if (delayed) {
                uint32_t attrs = u32(off), nm = u32(off + 4);
                iat = u32(off + 12);
                uint32_t it = u32(off + 16);
                if (!(attrs | nm | iat | it)) {
                    terminated = true;
                    break;
                }
                require(attrs & 1, "VA-based delay import descriptors are unsupported");
                name_rva = nm;
                thunk = it ? it : iat;
            } else {
                uint32_t original = u32(off), nm = u32(off + 12);
                iat = u32(off + 16);
                if (!(original | nm | iat)) {
                    terminated = true;
                    break;
                }
                name_rva = nm;
                thunk = original ? original : iat;
            }
            std::string dll = cstring(name_rva);
            bool thunk_end = false;
            for (uint32_t j = 0; j < 65536; ++j) {
                uint64_t tr = uint64_t(thunk) + uint64_t(j) * 8;
                uint64_t value = u64(q03c(tr, 8));
                if (!value) {
                    thunk_end = true;
                    break;
                }
                uint64_t slot = uint64_t(iat) + uint64_t(j) * 8;
                require(slot <= UINT32_MAX, "IAT RVA overflow");
                q03c(slot, 8);
                if (value & (uint64_t(1) << 63))
                    out.push_back({dll, "", static_cast<uint16_t>(value & 65535), static_cast<uint32_t>(slot),
                                   delayed});
                else {
                    require(value <= UINT64_MAX - 2, "import name RVA overflow");
                    out.push_back(
                        {dll, cstring(value + 2), std::nullopt, static_cast<uint32_t>(slot), delayed});
                }
            }
            require(thunk_end, "unterminated import thunk table");
        }
        require(terminated, "unterminated import descriptor table");
    }
    return out;
}
std::vector<q007> q005::q03b() const {
    auto [rva, size] = directory(3);
    if (!rva || !size)
        return {};
    require(size % 12 == 0, ".pdata size is not a multiple of RUNTIME_FUNCTION size");
    size_t off = q03c(rva, size);
    std::vector<q007> out;
    uint32_t last = 0;
    bool have = false;
    for (uint64_t p = off; p < uint64_t(off) + size; p += 12) {
        q007 f{u32(p), u32(p + 4), u32(p + 8)};
        if (!f.q036 && !f.q037 && !f.q038)
            continue;
        require(f.q036 < f.q037 && f.q037 <= q03f && f.q038 < q03f, "invalid RUNTIME_FUNCTION range");
        require(!have || f.q036 >= last, "RUNTIME_FUNCTION entries overlap or are not sorted");
        last = f.q037;
        have = true;
        out.push_back(f);
    }
    return out;
}
std::optional<q007> q005::q03a(uint64_t va) const {
    require(va >= q03e, "VA is outside image");
    uint64_t rva = va - q03e;
    require(rva < q03f, "VA is outside image");
    auto e = q03b();
    size_t lo = 0, hi = e.size();
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (e[mid].q036 <= rva)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo && rva < e[lo - 1].q037)
        return e[lo - 1];
    return std::nullopt;
}
q007 q005::q039(const q007 &entry, size_t max_depth) const {
    require(max_depth > 0, "max_depth must be positive");
    q007 cur = entry;
    std::set<std::tuple<uint32_t, uint32_t, uint32_t>> seen;
    for (size_t depth = 0; depth < max_depth; ++depth) {
        auto key = std::make_tuple(cur.q036, cur.q037, cur.q038);
        require(seen.insert(key).second, "cycle in chained unwind information");
        size_t off = q03c(cur.q038, 4);
        uint8_t vf = data[off], count = data[off + 2];
        uint8_t version = vf & 7, flags = vf >> 3;
        require(version == 1 || version == 2, "unsupported UNWIND_INFO version");
        require(!(flags & ~7) && !((flags & 4) && (flags & 3)), "invalid UNWIND_INFO flags");
        if (!(flags & 4))
            return cur;
        uint64_t chain = uint64_t(cur.q038) + 4 + ((uint64_t(count) + 1) & ~uint64_t(1)) * 2;
        size_t co = q03c(chain, 12);
        q007 next{u32(co), u32(co + 4), u32(co + 8)};
        require(next.q036 < next.q037 && next.q037 <= q03f && next.q038 < q03f,
                "invalid chained RUNTIME_FUNCTION");
        cur = next;
    }
    require(false, "chained unwind depth limit exceeded");
    return cur;
}
} // namespace q001
