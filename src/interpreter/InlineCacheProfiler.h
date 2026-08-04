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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 *  02110-1301 USA
 */

#ifndef __EscargotInlineCacheProfiler__
#define __EscargotInlineCacheProfiler__

#if defined(ESCARGOT_IC_PROFILE)

namespace Escargot {

class ByteCodeBlock;
class String;

// Phase 0 instrumentation for the IC-in-code-cache research.
// Collects per-site counters for GetObjectPreComputedCase / SetObjectPreComputedCase
// in a side table keyed by the bytecode instruction address, so neither the bytecode
// layout nor the code cache file format is affected.
//
// Every dynamic execution of an instrumented site records exactly one event,
// so per-site execution count == sum of all event counters of the site.
//
// Output: process-exit dump (CSV + summary). Set ESCARGOT_IC_PROFILE_OUT=<path>
// to append the dump to a file; default is stderr.
class InlineCacheProfiler {
public:
    enum SiteKind : uint8_t {
        GetSite,
        SetSite
    };

    enum Event : uint8_t {
        HitSimple, // cache hit on own-property (simple) entry
        HitComplex, // cache hit on proto-chain/transition (complex) entry
        MissWarmup, // generic lookup because of the warm-up gate (missCount below MinCacheFillCount)
        MissFillSimple, // miss handled by filling an own-property cache entry
        MissFillComplex, // miss handled by filling a proto-chain/transition cache entry
        MissMegamorphic, // generic lookup because the site exceeded MaxCacheMissCount
        MissUncacheable, // generic lookup because the receiver is not inline-cacheable
        MissGiveUp, // site permanently gave up caching on this execution
        LengthFastPath, // array length special path (bypasses IC entirely)
        EventCount
    };

    // codePtr: address of the instruction inside ByteCodeBlock::m_code (site identity)
    // propertyName: only used the first time a site is seen (identity is copied out of GC memory)
    static void record(SiteKind kind, void* codePtr, ByteCodeBlock* block, String* propertyName, Event event);

    static void dump();
};
} // namespace Escargot

#define ESCARGOT_IC_PROFILE_RECORD(kind, codePtr, block, propertyName, event) \
    ::Escargot::InlineCacheProfiler::record(::Escargot::InlineCacheProfiler::kind, codePtr, block, propertyName, ::Escargot::InlineCacheProfiler::event)

#else

#define ESCARGOT_IC_PROFILE_RECORD(kind, codePtr, block, propertyName, event)

#endif // ESCARGOT_IC_PROFILE

#endif
