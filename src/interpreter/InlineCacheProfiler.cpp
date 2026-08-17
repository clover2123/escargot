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
    bool isLength;

    uint64_t events[InlineCacheProfiler::EventCount];

    // === baseline mode (IC disabled): per-access property-lookup profile ===
    static constexpr size_t DepthBuckets = 9; // depth 1..8, last bucket = 9+
    // distinct receiver structures tracked exactly up to this cap; a site that
    // reaches the cap is reported as "33+" (aligned with MaxCacheMissCount=32)
    static constexpr uint32_t PolyCap = 33;

    uint64_t accessCount;
    // found accesses (property present somewhere on the chain)
    uint64_t foundCount;
    uint64_t foundIndexLE255; // holder slot index fits the Simple tier's uint8 field
    uint64_t depthSum; // found accesses only
    uint64_t depthMax; // found accesses only
    uint64_t depthHist[DepthBuckets]; // found accesses only
    // absent accesses (get: undefined read / set: property add)
    uint64_t notFoundCount;
    uint64_t notFoundChainSum; // whole-chain length examined on absent accesses
    // polymorphism (receiver structure identity; pointers never dereferenced)
    const void* structuresSeen[PolyCap];
    uint32_t structureCount;
    bool polyOverflow; // more than PolyCap distinct structures observed
    const void* lastStructure;
    uint64_t sameAsLastCount; // accesses whose receiver structure equals the previous access's

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

// polymorphism buckets: 1 / 2 / 3-4 / 5-8 / 9-16 / 17-32 / 33+
constexpr size_t PolyBuckets = 7;
const char* const polyBucketLabel[PolyBuckets] = { "1", "2", "3-4", "5-8", "9-16", "17-32", "33+" };

size_t polyBucketOf(const SiteStats& s)
{
    uint32_t n = s.structureCount;
    if (s.polyOverflow || n >= 33) {
        return 6;
    }
    if (n <= 1) {
        return 0;
    }
    if (n == 2) {
        return 1;
    }
    if (n <= 4) {
        return 2;
    }
    if (n <= 8) {
        return 3;
    }
    if (n <= 16) {
        return 4;
    }
    return 5;
}

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
        return std::string("<symbol-or-null>");
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

double pct(uint64_t part, uint64_t whole)
{
    return whole ? part * 100.0 / whole : 0.0;
}

SiteStats& siteFor(Registry& r, InlineCacheProfiler::SiteKind kind, void* codePtr, ByteCodeBlock* block, String* propertyName)
{
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
        stats.isLength = false;
        memset(stats.events, 0, sizeof(stats.events));
        stats.accessCount = 0;
        stats.foundCount = 0;
        stats.foundIndexLE255 = 0;
        stats.depthSum = 0;
        stats.depthMax = 0;
        memset(stats.depthHist, 0, sizeof(stats.depthHist));
        stats.notFoundCount = 0;
        stats.notFoundChainSum = 0;
        memset(stats.structuresSeen, 0, sizeof(stats.structuresSeen));
        stats.structureCount = 0;
        stats.polyOverflow = false;
        stats.lastStructure = nullptr;
        stats.sameAsLastCount = 0;

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
    return it->second;
}

// === aggregation over one site kind (get and set are reported fully separately) ===

struct KindSummary {
    size_t sites = 0;
    uint64_t accesses = 0;
    uint64_t found = 0;
    uint64_t foundIndexLE255 = 0;
    uint64_t depthSum = 0;
    uint64_t depthHist[SiteStats::DepthBuckets] = {};
    uint64_t notFound = 0;
    uint64_t notFoundChainSum = 0;
    uint64_t lengthAccesses = 0;
    size_t lengthSites = 0;
    uint64_t sameAsLast = 0;
    uint64_t sameAsLastDenominator = 0; // accesses - 1 per site (first access has no predecessor)

    // polymorphism histograms (site-weighted and access-weighted)
    size_t polySites[PolyBuckets] = {};
    uint64_t polyAccesses[PolyBuckets] = {};

    // joint distribution: rows = poly bucket, cols = depth 1 / depth 2 / depth >= 3 / absent
    static constexpr size_t JointCols = 4;
    uint64_t joint[PolyBuckets][JointCols] = {};

    // site access-count histogram: bucket i = sites with accessCount in [2^i, 2^(i+1))
    static constexpr size_t ExecBuckets = 20;
    size_t execHistSites[ExecBuckets] = {};
    uint64_t execHistAccesses[ExecBuckets] = {};
    size_t sitesLE2 = 0; // sites with <= 2 accesses (warm-up gate evidence)
    uint64_t accessesAtSitesLE2 = 0;

    void add(const SiteStats& s)
    {
        sites++;
        accesses += s.accessCount;
        if (s.isLength) {
            // "length" sites are served by the dedicated Length opcode outside the IC;
            // keep them out of the IC-design metrics (depth/poly/joint) and report
            // them only as the separate length share below.
            lengthSites++;
            lengthAccesses += s.accessCount;
            return;
        }
        found += s.foundCount;
        foundIndexLE255 += s.foundIndexLE255;
        depthSum += s.depthSum;
        notFound += s.notFoundCount;
        notFoundChainSum += s.notFoundChainSum;
        sameAsLast += s.sameAsLastCount;
        sameAsLastDenominator += s.accessCount ? s.accessCount - 1 : 0;

        size_t pb = polyBucketOf(s);
        polySites[pb]++;
        polyAccesses[pb] += s.accessCount;

        for (size_t i = 0; i < SiteStats::DepthBuckets; i++) {
            depthHist[i] += s.depthHist[i];
            size_t col = (i == 0) ? 0 : ((i == 1) ? 1 : 2);
            joint[pb][col] += s.depthHist[i];
        }
        joint[pb][3] += s.notFoundCount;

        size_t bucket = 0;
        uint64_t v = s.accessCount;
        while (v > 1 && bucket < ExecBuckets - 1) {
            v >>= 1;
            bucket++;
        }
        execHistSites[bucket]++;
        execHistAccesses[bucket] += s.accessCount;
        if (s.accessCount <= 2) {
            sitesLE2++;
            accessesAtSitesLE2 += s.accessCount;
        }
    }
};

void dumpKindSummary(FILE* out, const char* kindName, const KindSummary& k)
{
    fprintf(out, "\n--- %s ---\n", kindName);
    fprintf(out, "sites: %zu | accesses: %" PRIu64 "\n", k.sites, k.accesses);
    if (!k.sites) {
        return;
    }
    fprintf(out, "'length' sites: %zu | 'length' accesses: %" PRIu64 " (%.2f%% of accesses; served by the dedicated Length opcode, excluded from the IC metrics below)\n",
            k.lengthSites, k.lengthAccesses, pct(k.lengthAccesses, k.accesses));
    const size_t icSites = k.sites - k.lengthSites;
    const uint64_t icAccesses = k.accesses - k.lengthAccesses;

    // (2) lookup depth — found accesses
    fprintf(out, "found accesses: %" PRIu64 " (%.2f%%) | avg lookup depth: %.3f (1 = own property)\n",
            k.found, pct(k.found, icAccesses), k.found ? (double)k.depthSum / k.found : 0.0);
    fprintf(out, "lookup depth histogram over found accesses:\n");
    for (size_t i = 0; i < SiteStats::DepthBuckets; i++) {
        if (!k.depthHist[i]) {
            continue;
        }
        if (i == SiteStats::DepthBuckets - 1) {
            fprintf(out, "  depth >= %zu : %" PRIu64 " (%.2f%%)\n", i + 1, k.depthHist[i], pct(k.depthHist[i], k.found));
        } else {
            fprintf(out, "  depth %zu    : %" PRIu64 " (%.2f%%)\n", i + 1, k.depthHist[i], pct(k.depthHist[i], k.found));
        }
    }
    uint64_t depthLE1 = k.depthHist[0];
    uint64_t depthLE2 = k.depthHist[0] + k.depthHist[1];
    fprintf(out, "depth <= 1: %.2f%% | depth <= 2: %.2f%% of found accesses\n", pct(depthLE1, k.found), pct(depthLE2, k.found));
    fprintf(out, "absent on whole chain: %" PRIu64 " (%.2f%% of accesses; avg chain length examined %.3f)\n",
            k.notFound, pct(k.notFound, icAccesses), k.notFound ? (double)k.notFoundChainSum / k.notFound : 0.0);
    fprintf(out, "holder slot index <= 255: %" PRIu64 " (%.2f%% of found accesses)\n",
            k.foundIndexLE255, pct(k.foundIndexLE255, k.found));

    // (1) polymorphism
    fprintf(out, "polymorphism (distinct receiver structures per site; site-weighted / access-weighted):\n");
    for (size_t i = 0; i < PolyBuckets; i++) {
        if (!k.polySites[i]) {
            continue;
        }
        fprintf(out, "  poly %-5s : %zu sites (%.2f%%) / %" PRIu64 " accesses (%.2f%%)\n",
                polyBucketLabel[i], k.polySites[i], pct(k.polySites[i], icSites),
                k.polyAccesses[i], pct(k.polyAccesses[i], icAccesses));
    }
    fprintf(out, "consecutive-same-structure ratio: %.2f%% (temporal locality; MRU evidence)\n",
            pct(k.sameAsLast, k.sameAsLastDenominator));

    // (4) joint distribution
    fprintf(out, "joint access distribution (rows: poly bucket, cols: lookup depth; %% of all accesses):\n");
    fprintf(out, "  %-10s %14s %14s %14s %14s\n", "poly\\depth", "d1", "d2", "d3+", "absent");
    for (size_t i = 0; i < PolyBuckets; i++) {
        uint64_t rowSum = 0;
        for (size_t c = 0; c < KindSummary::JointCols; c++) {
            rowSum += k.joint[i][c];
        }
        if (!rowSum) {
            continue;
        }
        fprintf(out, "  %-10s", polyBucketLabel[i]);
        for (size_t c = 0; c < KindSummary::JointCols; c++) {
            char cell[32];
            snprintf(cell, sizeof(cell), "%" PRIu64 " (%.1f%%)", k.joint[i][c], pct(k.joint[i][c], icAccesses));
            fprintf(out, " %14s", cell);
        }
        fprintf(out, "\n");
    }
    uint64_t sweetSpot = k.joint[0][0] + k.joint[0][1] + k.joint[1][0] + k.joint[1][1]
        + k.joint[2][0] + k.joint[2][1] + k.joint[3][0] + k.joint[3][1];
    fprintf(out, "accesses within (poly <= 8) x (depth <= 2): %" PRIu64 " (%.2f%%)  <- Simple-tier design target\n",
            sweetSpot, pct(sweetSpot, icAccesses));

    // (3) site access-count distribution
    fprintf(out, "sites with <= 2 accesses: %zu (%.2f%% of sites; %.2f%% of accesses)  <- warm-up gate evidence\n",
            k.sitesLE2, pct(k.sitesLE2, icSites), pct(k.accessesAtSitesLE2, icAccesses));
    fprintf(out, "site access-count histogram:\n");
    for (size_t i = 0; i < KindSummary::ExecBuckets; i++) {
        if (!k.execHistSites[i]) {
            continue;
        }
        uint64_t lo = (uint64_t)1 << i;
        uint64_t hi = ((uint64_t)1 << (i + 1)) - 1;
        if (i == KindSummary::ExecBuckets - 1) {
            fprintf(out, "  accesses >= %-10" PRIu64 " : %zu sites, %" PRIu64 " accesses\n", lo, k.execHistSites[i], k.execHistAccesses[i]);
        } else {
            fprintf(out, "  accesses %6" PRIu64 " - %-6" PRIu64 " : %zu sites, %" PRIu64 " accesses\n", lo, hi, k.execHistSites[i], k.execHistAccesses[i]);
        }
    }
}

} // namespace

void InlineCacheProfiler::record(SiteKind kind, void* codePtr, ByteCodeBlock* block, String* propertyName, Event event)
{
    Registry& r = registry();
    std::lock_guard<std::mutex> guard(r.mutex);
    siteFor(r, kind, codePtr, block, propertyName).events[event]++;
}

void InlineCacheProfiler::recordAccess(SiteKind kind, void* codePtr, ByteCodeBlock* block, String* propertyName,
                                       size_t depth, bool found, const void* receiverStructure, bool isLength, size_t foundIndex)
{
    Registry& r = registry();
    std::lock_guard<std::mutex> guard(r.mutex);
    SiteStats& s = siteFor(r, kind, codePtr, block, propertyName);
    s.isLength = isLength;
    s.accessCount++;
    if (found) {
        s.foundCount++;
        if (foundIndex <= 255) {
            s.foundIndexLE255++;
        }
        s.depthSum += depth;
        if (depth > s.depthMax) {
            s.depthMax = depth;
        }
        size_t bucket = (depth == 0) ? 0 : std::min(depth - 1, SiteStats::DepthBuckets - 1);
        s.depthHist[bucket]++;
    } else {
        s.notFoundCount++;
        s.notFoundChainSum += depth;
    }

    // polymorphism: consecutive-same ratio + distinct-structure set (saturating)
    if (s.accessCount > 1 && receiverStructure == s.lastStructure) {
        s.sameAsLastCount++;
    }
    s.lastStructure = receiverStructure;
    if (!s.polyOverflow) {
        bool seen = false;
        for (uint32_t i = 0; i < s.structureCount; i++) {
            if (s.structuresSeen[i] == receiverStructure) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            if (s.structureCount < SiteStats::PolyCap) {
                s.structuresSeen[s.structureCount++] = receiverStructure;
            } else {
                s.polyOverflow = true;
            }
        }
    }
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

    bool hasEvents = false;
    bool hasAccesses = false;
    for (const SiteStats* s : sorted) {
        if (s->exec()) {
            hasEvents = true;
        }
        if (s->accessCount) {
            hasAccesses = true;
        }
    }

    // === baseline mode (inline caching disabled): per-site property-access profile ===
    if (hasAccesses) {
        std::vector<const SiteStats*> byCount(sorted);
        std::sort(byCount.begin(), byCount.end(), [](const SiteStats* a, const SiteStats* b) {
            return a->accessCount > b->accessCount;
        });

        KindSummary get, set;
        for (const SiteStats* s : byCount) {
            if (!s->accessCount) {
                continue;
            }
            if (s->kind == GetSite) {
                get.add(*s);
            } else {
                set.add(*s);
            }
        }

        fprintf(out, "\n=== Escargot IC baseline profile — inline caching disabled (pid %d) ===\n", (int)getpid());
        fprintf(out, "receiver structure = hidden class after ToObject; set sites with non-object receivers are not recorded\n");
        fprintf(out, "depth semantics are structural (Proxy traps not consulted); chain walk bounded at 64\n");
        dumpKindSummary(out, "GET", get);
        dumpKindSummary(out, "SET", set);

        fprintf(out, "\n--- per-site CSV (sorted by access count) ---\n");
        fprintf(out, "kind,src,function,offset,property,is_length,count,found,not_found,distinct_structures,poly_saturated,same_as_last,idx_le255,depth_avg_found,depth_max,notfound_chain_avg,d1,d2,d3,d4,d5,d6,d7,d8,d9plus\n");
        for (const SiteStats* s : byCount) {
            if (!s->accessCount) {
                continue;
            }
            fprintf(out, "%s,%s,%s,%zu,%s,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%u,%d,%" PRIu64 ",%" PRIu64 ",%.3f,%" PRIu64 ",%.3f",
                    s->kind == GetSite ? "get" : "set",
                    csvEscape(s->src).c_str(), csvEscape(s->function).c_str(), s->offset, csvEscape(s->property).c_str(),
                    s->isLength ? 1 : 0,
                    s->accessCount, s->foundCount, s->notFoundCount,
                    s->structureCount, s->polyOverflow ? 1 : 0,
                    s->sameAsLastCount, s->foundIndexLE255,
                    s->foundCount ? (double)s->depthSum / s->foundCount : 0.0, s->depthMax,
                    s->notFoundCount ? (double)s->notFoundChainSum / s->notFoundCount : 0.0);
            for (size_t i = 0; i < SiteStats::DepthBuckets; i++) {
                fprintf(out, ",%" PRIu64, s->depthHist[i]);
            }
            fprintf(out, "\n");
        }
        fprintf(out, "=== end of IC baseline profile ===\n");
    }

    if (!hasEvents) {
        if (needClose) {
            fclose(out);
        } else {
            fflush(out);
        }
        return;
    }

    // === event mode (IC enabled builds; unused by the baseline profiling build) ===
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
    uint64_t warmupAtCachedSites = 0, warmupAtNeverCachedSites = 0;
    size_t megamorphicSites = 0;
    uint64_t wastedFillsAtMegamorphicSites = 0;

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
            totalExec, totalHits, pct(totalHits, totalExec),
            totalMisses, pct(totalMisses, totalExec), totals[LengthFastPath]);
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
