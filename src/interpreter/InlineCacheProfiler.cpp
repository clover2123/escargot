/*
 * Copyright (c) 2026-present Samsung Electronics Co., Ltd
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 */

#if defined(ESCARGOT_IC_PROFILE)

#include "Escargot.h"
#include "InlineCacheProfiler.h"
#include "ByteCode.h"
#include "parser/CodeBlock.h"
#include "parser/Script.h"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace Escargot {

namespace {

struct SiteStats {
    // identity (copied out of GC memory at first sight; safe to read at process exit)
    InlineCacheProfiler::SiteKind kind;
    const void* blockPtr; // only for detecting instruction-address reuse; never dereferenced
    std::string src;
    std::string function;
    size_t offset;
    std::string property;

    uint64_t events[InlineCacheProfiler::EventCount];

    uint64_t exec() const
    {
        uint64_t sum = 0;
        for (size_t i = 0; i < InlineCacheProfiler::EventCount; i++) {
            sum += events[i];
        }
        return sum;
    }

    uint64_t hits() const
    {
        return events[InlineCacheProfiler::HitSimple] + events[InlineCacheProfiler::HitComplex];
    }

    uint64_t fills() const
    {
        return events[InlineCacheProfiler::MissFillSimple] + events[InlineCacheProfiler::MissFillComplex];
    }

    uint64_t misses() const
    {
        return exec() - hits() - events[InlineCacheProfiler::LengthFastPath];
    }
};

struct Registry {
    std::mutex mutex;
    // keyed by instruction address; identity strings are captured eagerly.
    // if GC frees a ByteCodeBlock and a new block reuses the same instruction address,
    // the old entry is moved to retiredSites and the slot restarts (blockPtr mismatch)
    std::unordered_map<void*, SiteStats> sites;
    std::vector<SiteStats> retiredSites;
    bool dumpRegistered{ false };
    bool dumped{ false };
};

Registry& registry()
{
    static Registry r;
    return r;
}

std::string toStdString(String* s)
{
    if (!s) {
        return std::string("<null>");
    }
    auto data = s->toUTF8StringData();
    return std::string(data.data(), data.length());
}

const char* eventName(size_t e)
{
    switch (e) {
    case InlineCacheProfiler::HitSimple:
        return "hit_simple";
    case InlineCacheProfiler::HitComplex:
        return "hit_complex";
    case InlineCacheProfiler::MissWarmup:
        return "miss_warmup";
    case InlineCacheProfiler::MissFillSimple:
        return "fill_simple";
    case InlineCacheProfiler::MissFillComplex:
        return "fill_complex";
    case InlineCacheProfiler::MissMegamorphic:
        return "miss_megamorphic";
    case InlineCacheProfiler::MissUncacheable:
        return "miss_uncacheable";
    case InlineCacheProfiler::MissGiveUp:
        return "miss_giveup";
    case InlineCacheProfiler::LengthFastPath:
        return "length_fastpath";
    default:
        return "unknown";
    }
}

std::string csvEscape(const std::string& s)
{
    if (s.find_first_of(",\"\n") == std::string::npos) {
        return s;
    }
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') {
            out += "\"\"";
        } else {
            out += c;
        }
    }
    out += "\"";
    return out;
}

} // namespace

void InlineCacheProfiler::record(SiteKind kind, void* codePtr, ByteCodeBlock* block, String* propertyName, Event event)
{
    Registry& r = registry();
    std::lock_guard<std::mutex> guard(r.mutex);

    if (!r.dumpRegistered) {
        r.dumpRegistered = true;
        std::atexit(InlineCacheProfiler::dump);
    }

    auto it = r.sites.find(codePtr);
    if (it != r.sites.end() && UNLIKELY(it->second.blockPtr != block)) {
        r.retiredSites.push_back(std::move(it->second));
        r.sites.erase(it);
        it = r.sites.end();
    }
    if (it == r.sites.end()) {
        SiteStats stats;
        stats.kind = kind;
        stats.blockPtr = block;
        stats.offset = 0;
        memset(stats.events, 0, sizeof(stats.events));

        InterpretedCodeBlock* cb = block ? block->codeBlock() : nullptr;
        if (cb) {
            stats.function = toStdString(cb->functionName().string());
            if (stats.function.empty()) {
                stats.function = "<anonymous>";
            }
            if (cb->script()) {
                stats.src = toStdString(cb->script()->srcName());
            }
        }
        if (block) {
            stats.offset = (size_t)((uint8_t*)codePtr - block->m_code.data());
        }
        stats.property = toStdString(propertyName);
        it = r.sites.emplace(codePtr, std::move(stats)).first;
    }
    it->second.events[event]++;
}

void InlineCacheProfiler::dump()
{
    Registry& r = registry();
    std::lock_guard<std::mutex> guard(r.mutex);
    if (r.dumped || (r.sites.empty() && r.retiredSites.empty())) {
        return;
    }
    r.dumped = true;

    FILE* out = stderr;
    bool needClose = false;
    const char* path = getenv("ESCARGOT_IC_PROFILE_OUT");
    if (path && *path) {
        FILE* f = fopen(path, "a");
        if (f) {
            out = f;
            needClose = true;
        }
    }

    std::vector<const SiteStats*> sorted;
    sorted.reserve(r.sites.size() + r.retiredSites.size());
    for (const auto& kv : r.sites) {
        sorted.push_back(&kv.second);
    }
    for (const auto& s : r.retiredSites) {
        sorted.push_back(&s);
    }
    std::sort(sorted.begin(), sorted.end(), [](const SiteStats* a, const SiteStats* b) {
        if (a->misses() != b->misses()) {
            return a->misses() > b->misses();
        }
        return a->exec() > b->exec();
    });

    uint64_t totals[EventCount];
    memset(totals, 0, sizeof(totals));
    uint64_t totalExec = 0;
    size_t getSites = 0, setSites = 0;
    // Stage 1 upper bound: warm-up generic lookups at sites that eventually filled a cache
    // (a policy hint would have let them fill on the first miss instead)
    uint64_t warmupAtCachedSites = 0, warmupAtNeverCachedSites = 0;
    // Stage 1 secondary target: fills/lookups wasted at sites that ended up megamorphic or gave up
    size_t megamorphicSites = 0;
    uint64_t wastedFillsAtMegamorphicSites = 0;

    // execution-count histogram over sites: bucket i holds sites with exec in [2^i, 2^(i+1))
    constexpr size_t bucketCount = 20;
    size_t histSites[bucketCount];
    uint64_t histWarmup[bucketCount];
    memset(histSites, 0, sizeof(histSites));
    memset(histWarmup, 0, sizeof(histWarmup));

    for (const SiteStats* s : sorted) {
        uint64_t exec = s->exec();
        totalExec += exec;
        for (size_t i = 0; i < EventCount; i++) {
            totals[i] += s->events[i];
        }
        if (s->kind == GetSite) {
            getSites++;
        } else {
            setSites++;
        }
        if (s->fills() > 0) {
            warmupAtCachedSites += s->events[MissWarmup];
        } else {
            warmupAtNeverCachedSites += s->events[MissWarmup];
        }
        if (s->events[MissMegamorphic] > 0 || s->events[MissGiveUp] > 0 || s->events[MissUncacheable] > 0) {
            megamorphicSites++;
            wastedFillsAtMegamorphicSites += s->fills();
        }

        size_t bucket = 0;
        uint64_t v = exec;
        while (v > 1 && bucket < bucketCount - 1) {
            v >>= 1;
            bucket++;
        }
        histSites[bucket]++;
        histWarmup[bucket] += s->events[MissWarmup];
    }

    uint64_t totalHits = totals[HitSimple] + totals[HitComplex];
    uint64_t totalMisses = totalExec - totalHits - totals[LengthFastPath];

    fprintf(out, "\n=== Escargot IC profile (pid %d) ===\n", (int)getpid());
    fprintf(out, "sites: %zu (get %zu, set %zu)\n", sorted.size(), getSites, setSites);
    fprintf(out, "executions: %" PRIu64 " | hits: %" PRIu64 " (%.2f%%) | misses: %" PRIu64 " (%.2f%%) | length fastpath: %" PRIu64 "\n",
            totalExec, totalHits, totalExec ? totalHits * 100.0 / totalExec : 0.0,
            totalMisses, totalExec ? totalMisses * 100.0 / totalExec : 0.0, totals[LengthFastPath]);
    for (size_t i = 0; i < EventCount; i++) {
        fprintf(out, "  %-16s : %" PRIu64 "\n", eventName(i), totals[i]);
    }
    fprintf(out, "[stage1 upper bound] warm-up generic lookups at eventually-cached sites: %" PRIu64 "\n", warmupAtCachedSites);
    fprintf(out, "[stage1 upper bound] warm-up generic lookups at never-cached sites: %" PRIu64 "\n", warmupAtNeverCachedSites);
    fprintf(out, "[stage1 upper bound] megamorphic/giveup/uncacheable sites: %zu (fills wasted there: %" PRIu64 ")\n",
            megamorphicSites, wastedFillsAtMegamorphicSites);

    fprintf(out, "site execution-count histogram (bucket: site count / warm-up lookups in bucket):\n");
    for (size_t i = 0; i < bucketCount; i++) {
        if (!histSites[i]) {
            continue;
        }
        uint64_t lo = (uint64_t)1 << i;
        uint64_t hi = ((uint64_t)1 << (i + 1)) - 1;
        if (i == bucketCount - 1) {
            fprintf(out, "  exec >= %-10" PRIu64 " : %zu sites, %" PRIu64 " warm-up lookups\n", lo, histSites[i], histWarmup[i]);
        } else {
            fprintf(out, "  exec %6" PRIu64 " - %-6" PRIu64 " : %zu sites, %" PRIu64 " warm-up lookups\n", lo, hi, histSites[i], histWarmup[i]);
        }
    }

    fprintf(out, "--- per-site CSV (sorted by miss count) ---\n");
    fprintf(out, "kind,src,function,offset,property,exec,hit_simple,hit_complex,miss_warmup,fill_simple,fill_complex,miss_megamorphic,miss_uncacheable,miss_giveup,length_fastpath\n");
    for (const SiteStats* s : sorted) {
        fprintf(out, "%s,%s,%s,%zu,%s,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
                s->kind == GetSite ? "get" : "set",
                csvEscape(s->src).c_str(), csvEscape(s->function).c_str(), s->offset, csvEscape(s->property).c_str(),
                s->exec(),
                s->events[HitSimple], s->events[HitComplex], s->events[MissWarmup],
                s->events[MissFillSimple], s->events[MissFillComplex], s->events[MissMegamorphic],
                s->events[MissUncacheable], s->events[MissGiveUp], s->events[LengthFastPath]);
    }
    fprintf(out, "=== end of IC profile ===\n");

    if (needClose) {
        fclose(out);
    } else {
        fflush(out);
    }
}

} // namespace Escargot

#endif // ESCARGOT_IC_PROFILE
