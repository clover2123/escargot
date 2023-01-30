/*
 * Copyright (c) 2016-present Samsung Electronics Co., Ltd
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

#ifndef __EscargotArrayObject__
#define __EscargotArrayObject__

#include "runtime/Object.h"
#include "runtime/ErrorObject.h"
#include "runtime/IteratorObject.h"

namespace Escargot {

#define ESCARGOT_ARRAY_NON_FASTMODE_MIN_SIZE 65536 * 16
#define ESCARGOT_ARRAY_NON_FASTMODE_START_MIN_GAP 1024

class ArrayIteratorObject;

class ArrayObject : public DerivedObject {
    friend class VMInstance;
    friend class Global;
    friend class ByteCodeInterpreter;
    friend class EnumerateObject;
    friend class EnumerateObjectWithDestruction;
    friend class EnumerateObjectWithIteration;
    friend Value builtinArrayConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget);
    friend void initializeCustomAllocators();
    friend int getValidValueInArrayObject(void* ptr, GC_mark_custom_result* arr);

    // dummy element to represent non-fast mode array
    static ObjectPropertyValue DummyArrayElement;

    enum ForSpreadArray { __ForSpreadArray__ };

public:
    explicit ArrayObject(ExecutionState& state);
    explicit ArrayObject(ExecutionState& state, Object* proto);
    ArrayObject(ExecutionState& state, const uint64_t& size, bool shouldConsiderHole = true);
    ArrayObject(ExecutionState& state, Object* proto, const uint64_t& size, bool shouldConsiderHole = true);
    ArrayObject(ExecutionState& state, const Value* src, const uint64_t& size);
    ArrayObject(ExecutionState& state, Object* proto, const Value* src, const uint64_t& size);

    static ArrayObject* createSpreadArray(ExecutionState& state);

    virtual bool hasOwnEnumeration() const override
    {
        return true;
    }

    virtual ObjectHasPropertyResult hasProperty(ExecutionState& state, const ObjectPropertyName& P) override;
    virtual ObjectGetResult getOwnProperty(ExecutionState& state, const ObjectPropertyName& P) override;
    virtual bool defineOwnProperty(ExecutionState& state, const ObjectPropertyName& P, const ObjectPropertyDescriptor& desc) override;
    virtual bool deleteOwnProperty(ExecutionState& state, const ObjectPropertyName& P) override;
    virtual void enumeration(ExecutionState& state, bool (*callback)(ExecutionState& state, Object* self, const ObjectPropertyName&, const ObjectStructurePropertyDescriptor& desc, void* data), void* data, bool shouldSkipSymbolKey = true) override;
    virtual void sort(ExecutionState& state, uint64_t length, const std::function<bool(const Value& a, const Value& b)>& comp) override;
    virtual ObjectGetResult getIndexedProperty(ExecutionState& state, const Value& property, const Value& receiver) override;
    virtual ObjectHasPropertyResult hasIndexedProperty(ExecutionState& state, const Value& propertyName) override;
    virtual bool setIndexedProperty(ExecutionState& state, const Value& property, const Value& value, const Value& receiver) override;
    virtual bool preventExtensions(ExecutionState&) override;
    virtual uint64_t length(ExecutionState& state) override;
    virtual void markAsPrototypeObject(ExecutionState& state) override;

    // Use custom allocator for Array object (for Badtime)
    void* operator new(size_t size);
    void* operator new[](size_t size) = delete;

    static void iterateArrays(ExecutionState& state, HeapObjectIteratorCallback callback);

    void defineOwnIndexedPropertyWithoutExpanding(ExecutionState& state, const size_t& index, const Value& value)
    {
        ASSERT(index < arrayLength(state));
        if (LIKELY(isFastModeArray())) {
            setFastModeArrayValueWithoutExpanding(state, index, value);
        } else {
            DerivedObject::defineOwnProperty(state, ObjectPropertyName(state, index), ObjectPropertyDescriptor(value, ObjectPropertyDescriptor::AllPresent));
        }
    }

protected:
    ArrayObject()
        : DerivedObject()
        , m_arrayLength(0)
#if defined(ESCARGOT_64) && defined(ESCARGOT_USE_32BIT_IN_64BIT)
        , m_fastModeData()
#else
        , m_fastModeData(nullptr)
#endif
    {
        // default constructor
        // only called by Global::initialize to set tag value
    }

    // constructor for SpreadArray (ArrayObject::createSpreadArray)
    ArrayObject(ExecutionState& state, ForSpreadArray);

    void convertIntoNonFastMode(ExecutionState& state);

private:
    ALWAYS_INLINE bool isFastModeArray()
    {
#if defined(ESCARGOT_64) && defined(ESCARGOT_USE_32BIT_IN_64BIT)
        return (m_fastModeData.data() != &ArrayObject::DummyArrayElement);
#else
        return (m_fastModeData != &ArrayObject::DummyArrayElement);
#endif
    }

    bool isLengthPropertyWritable()
    {
        return hasRareData() ? rareData()->m_isArrayObjectLengthWritable : true;
    }

    void setFastModeArrayValueWithoutExpanding(ExecutionState& state, size_t idx, const Value& v)
    {
        ASSERT(isFastModeArray());
        ASSERT(idx < arrayLength(state));
        m_fastModeData[idx] = v;
    }

    ALWAYS_INLINE const uint32_t& arrayLength(ExecutionState&)
    {
        return m_arrayLength;
    }

    bool setArrayLength(ExecutionState& state, const Value& newLength);
    bool setArrayLength(ExecutionState& state, const uint32_t newLength, bool useFitStorage = false, bool considerHole = true);

    ObjectGetResult getVirtualValue(ExecutionState& state, const ObjectPropertyName& P);

    uint32_t m_arrayLength;
#if defined(ESCARGOT_64) && defined(ESCARGOT_USE_32BIT_IN_64BIT)
    TightVectorWithNoSize<ObjectPropertyValue, CustomAllocator<ObjectPropertyValue>> m_fastModeData;
#else
    ObjectPropertyValue* m_fastModeData;
#endif
};

class ArrayPrototypeObject : public ArrayObject {
    friend class Global;

public:
    explicit ArrayPrototypeObject(ExecutionState& state);

    virtual void markAsPrototypeObject(ExecutionState& state) override;
    virtual bool isEverSetAsPrototypeObject() const override;

private:
    ArrayPrototypeObject()
        : ArrayObject()
    {
        // dummy default constructor
        // only called by Global::initialize to set tag value
    }
};

class ArrayIteratorObject : public IteratorObject {
public:
    enum Type {
        TypeKey,
        TypeValue,
        TypeKeyValue
    };

    ArrayIteratorObject(ExecutionState& state, Object* array, Type type);

    virtual bool isArrayIteratorObject() const override
    {
        return true;
    }

    virtual std::pair<Value, bool> advance(ExecutionState& state) override;

    void* operator new(size_t size);
    void* operator new[](size_t size) = delete;

private:
    Object* m_array;
    size_t m_iteratorNextIndex;
    Type m_type;
};
} // namespace Escargot

#endif
