/*
 * Copyright (c) 2022-present Samsung Electronics Co., Ltd
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

#include "Escargot.h"
#include "runtime/GlobalObject.h"
#include "runtime/NativeFunctionObject.h"
#include "runtime/VMInstance.h"
#include "runtime/BigIntObject.h"
#include "runtime/TemporalObject.h"
#include "runtime/DateObject.h"
#include "runtime/ArrayObject.h"

namespace Escargot {
#if defined(ENABLE_TEMPORAL)

#define CHECK_TEMPORAL_OBJECT_HAS_YEAR_AND_MONTH(temporalDateLike) \
    !(temporalDateLike.isObject() && (temporalDateLike.asObject()->isTemporalPlainDateObject() || temporalDateLike.asObject()->isTemporalPlainDateTimeObject() || temporalDateLike.asObject()->isTemporalPlainYearMonthObject()))

#define CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, value)                                \
    if (!(value.isObject() && value.asObject()->isTemporalPlainYearMonthObject())) { \
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type"); \
    }

#define CHECK_TEMPORAL_INSTANT(state, value)                                       \
    if (!(value.isObject() && value.asObject()->isTemporalInstantObject())) {      \
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "wrong type"); \
    }

#define CHECK_TEMPORAL_CALENDAR(state, thisValue, argc)                                                                 \
    if (!(thisValue.isObject() && thisValue.asObject()->isTemporalCalendarObject())) {                                  \
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, ErrorObject::Messages::GlobalObject_ThisNotObject); \
    }                                                                                                                   \
                                                                                                                        \
    ASSERT(thisValue.asObject()->asTemporalCalendarObject()->getIdentifier()->equals("iso8601"));                       \
                                                                                                                        \
    if (argc == 0) {                                                                                                    \
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type");                                    \
    }

#define CHECK_TEMPORAL_ZONED_DATE_TIME(state, value)                                \
    if (!(value.isObject() && value.asObject()->isTemporalZonedDateTimeObject())) { \
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "wrong type");  \
    }

#define CHECK_TEMPORAL_PLAIN_DATE(state, value)                                      \
    if (!(value.isObject() && value.asObject()->isTemporalPlainDateObject())) {      \
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type"); \
    }

#define CHECK_TEMPORAL_PLAIN_TIME(state, value)                                      \
    if (!(value.isObject() && value.asObject()->isTemporalPlainTimeObject())) {      \
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type"); \
    }

#define CHECK_TEMPORAL_PLAIN_DATE_TIME(state, value)                                 \
    if (!(value.isObject() && value.asObject()->isTemporalPlainDateTimeObject())) {  \
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type"); \
    }

#define CHECK_TEMPORAL_DURATION(state, value)                                        \
    if (!(value.isObject() && value.asObject()->isTemporalDurationObject())) {       \
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type"); \
    }

#define CHECK_TEMPORAL_TIME_ZONE(state, value)                                       \
    if (!(value.isObject() && value.asObject()->isTemporalTimeZoneObject())) {       \
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type"); \
    }

#define CHECK_TEMPORAL_TIME_ZONE_OFFSET_VALUE(state, value)                                                                                                                \
    if (value.asObject()->asTemporalTimeZoneObject()->getIdentifier()->equals("UTC") && !value.asObject()->asTemporalTimeZoneObject()->getOffsetNanoseconds().isInt32()) { \
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid offset value");                                                                               \
    }

static TemporalPlainDateObject* getTemporalPlainDate(ExecutionState& state, const Value& thisValue, unsigned long argc, Value* argv)
{
    CHECK_TEMPORAL_CALENDAR(state, thisValue, argc);
    return TemporalPlainDateObject::toTemporalDate(state, argv[0]).asObject()->asTemporalPlainDateObject();
}

static Value temporalInstantFromEpoch(ExecutionState& state, size_t argc, Value* argv, BigInt* epoch)
{
    if (argc == 0) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, ErrorObject::Messages::GlobalObject_IllegalFirstArgument);
    }

    auto epochNanoSeconds = argv[0].toBigInt(state)->multiply(state, epoch);

    if (!TemporalInstantObject::isValidEpochNanoseconds(epochNanoSeconds)) {
        ErrorObject::throwBuiltinError(state, ErrorCode::RangeError, "nanoSeconds is out of range");
    }

    return TemporalInstantObject::createTemporalInstant(state, epochNanoSeconds);
}

static Value builtinTemporalNowTimeZone(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    return Value(String::fromUTF8(state.context()->vmInstance()->timezoneID().c_str(), state.context()->vmInstance()->timezoneID().length(), true));
}

static Value builtinTemporalNowPlainDateISO(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    DateObject d(state);
    d.setTimeValue(DateObject::currentTime());
    return TemporalObject::toISODate(state, d);
}

static Value builtinTemporalNowPlainTimeISO(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    DateObject d(state);
    d.setTimeValue(DateObject::currentTime());
    return TemporalObject::toISOTime(state, d);
}

static Value builtinTemporalNowPlainDateTimeISO(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    DateObject d(state);
    d.setTimeValue(DateObject::currentTime());
    return TemporalObject::toISODateTime(state, d);
}

static Value builtinTemporalPlainDateConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!newTarget.hasValue()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, ErrorObject::Messages::New_Target_Is_Undefined);
    }

    ASSERT(argc > 2);

    if (!(argv[0].isInteger(state) || argv[1].isInteger(state) || argv[2].isInteger(state))) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type");
    }

    Value calendar = TemporalCalendarObject::toTemporalCalendarWithISODefault(state, argc > 4 ? argv[3] : Value());
    return TemporalPlainDateObject::createTemporalDate(state, argv[0].asInt32(), argv[1].asInt32(), argv[2].asInt32(), calendar, newTarget);
}

static Value builtinTemporalPlainDateFrom(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (argc > 1 && !argv[1].isObject()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "options must be object");
    }

    if (argv[0].isObject() && argv[0].asObject()->isTemporalPlainDateObject()) {
        TemporalObject::toTemporalOverflow(state, argc > 1 ? Value(argv[1].asObject()) : Value());
        TemporalPlainDateObject* plainDate = argv[0].asObject()->asTemporalPlainDateObject();
        return TemporalPlainDateObject::createTemporalDate(state, plainDate->year(), plainDate->month(), plainDate->day(), plainDate->getCalendar());
    }
    return TemporalPlainDateObject::toTemporalDate(state, argv[0], argc > 1 ? argv[1].asObject() : nullptr);
}

static Value builtinTemporalPlainDateCalendar(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);
    return thisValue.asObject()->asTemporalPlainDateObject()->getCalendar();
}

static Value builtinTemporalPlainDateYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);
    return TemporalCalendarObject::calendarYear(state, thisValue.asObject()->asTemporalPlainDateObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateMonth(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);
    return TemporalCalendarObject::calendarMonth(state, thisValue.asObject()->asTemporalPlainDateObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateMonthCode(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);
    return TemporalCalendarObject::calendarMonthCode(state, thisValue.asObject()->asTemporalPlainDateObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateDay(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);
    return TemporalCalendarObject::calendarDay(state, thisValue.asObject()->asTemporalPlainDateObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateDayOfWeek(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);
    return TemporalCalendarObject::calendarDayOfWeek(state, thisValue.asObject()->asTemporalPlainDateObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateDayOfYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);
    return TemporalCalendarObject::calendarDayOfYear(state, thisValue.asObject()->asTemporalPlainDateObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateWeekOfYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);
    return TemporalCalendarObject::calendarWeekOfYear(state, thisValue.asObject()->asTemporalPlainDateObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateDaysInWeek(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);
    return TemporalCalendarObject::calendarDaysInWeek(state, thisValue.asObject()->asTemporalPlainDateObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateDaysInMonth(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);
    return TemporalCalendarObject::calendarDaysInMonth(state, thisValue.asObject()->asTemporalPlainDateObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateDaysInYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);
    return TemporalCalendarObject::calendarDaysInYear(state, thisValue.asObject()->asTemporalPlainDateObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateMonthsInYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);
    return TemporalCalendarObject::calendarMonthsInYear(state, thisValue.asObject()->asTemporalPlainDateObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateInLeapYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);
    return TemporalCalendarObject::calendarInLeapYear(state, thisValue.asObject()->asTemporalPlainDateObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDatePrototypeAdd(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);

    auto duration = TemporalDurationObject::toTemporalDuration(state, argv[0]);
    auto options = TemporalObject::getOptionsObject(state, argc > 2 ? argv[1] : Value());
    return TemporalCalendarObject::calendarDateAdd(state, thisValue.asObject()->asTemporalPlainDateObject()->getCalendar(), thisValue, duration, options);
}

static Value builtinTemporalPlainDatePrototypeSubtract(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE(state, thisValue);

    auto duration = TemporalDurationObject::createNegatedTemporalDuration(state, TemporalDurationObject::toTemporalDuration(state, argv[0]));
    auto options = TemporalObject::getOptionsObject(state, argc > 2 ? argv[1] : Value());
    return TemporalCalendarObject::calendarDateAdd(state, thisValue.asObject()->asTemporalPlainDateObject()->getCalendar(), thisValue, duration, options);
}

static Value builtinTemporalPlainTimeConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!newTarget.hasValue()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, ErrorObject::Messages::New_Target_Is_Undefined);
    }

    int values[6];
    memset(values, 0, sizeof(values));

    for (unsigned int i = 0; i < argc && i < 6; ++i) {
        values[i] = argv[i].toInteger(state);
    }

    return TemporalPlainTimeObject::createTemporalTime(state, values[0], values[1], values[2], values[3], values[4], values[5], newTarget);
}

static Value builtinTemporalPlainTimeFrom(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value options = TemporalObject::getOptionsObject(state, argc > 1 ? argv[1] : Value());
    options = TemporalObject::toTemporalOverflow(state, options);

    if (argv[0].isObject() && argv[0].asObject()->isTemporalPlainTimeObject()) {
        TemporalPlainTimeObject* item = argv[0].asObject()->asTemporalPlainTimeObject();
        return TemporalPlainTimeObject::createTemporalTime(state, item->getHour(), item->getMinute(), item->getSecond(),
                                                           item->getMillisecond(), item->getMicrosecond(),
                                                           item->getNanosecond(), nullptr);
    }
    return TemporalPlainTimeObject::toTemporalTime(state, argv[0], options);
}

static Value builtinTemporalPlainTimeCompare(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    TemporalPlainTimeObject* firstPlainTimeObject = TemporalPlainTimeObject::toTemporalTime(state, argv[0], Value()).asObject()->asTemporalPlainTimeObject();
    TemporalPlainTimeObject* secondPlainTimeObject = TemporalPlainTimeObject::toTemporalTime(state, argv[1], Value()).asObject()->asTemporalPlainTimeObject();
    int firstPlainTimeArray[] = { firstPlainTimeObject->getHour(), firstPlainTimeObject->getMinute(), firstPlainTimeObject->getSecond(), firstPlainTimeObject->getMillisecond(), firstPlainTimeObject->getMicrosecond(), firstPlainTimeObject->getNanosecond() };
    int secondPlainTimeArray[] = { secondPlainTimeObject->getHour(), secondPlainTimeObject->getMinute(), secondPlainTimeObject->getSecond(), secondPlainTimeObject->getMillisecond(), secondPlainTimeObject->getMicrosecond(), secondPlainTimeObject->getNanosecond() };
    return Value(TemporalPlainTimeObject::compareTemporalTime(state, firstPlainTimeArray, secondPlainTimeArray));
}

static Value builtinTemporalPlainTimeCalendar(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_TIME(state, thisValue);
    return Value(thisValue.asObject()->asTemporalPlainTimeObject()->getCalendar());
}

static Value builtinTemporalPlainTimeHour(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_TIME(state, thisValue);
    return Value(thisValue.asObject()->asTemporalPlainTimeObject()->getHour());
}

static Value builtinTemporalPlainTimeMinute(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_TIME(state, thisValue);
    return Value(thisValue.asObject()->asTemporalPlainTimeObject()->getMinute());
}

static Value builtinTemporalPlainTimeSecond(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_TIME(state, thisValue);
    return Value(thisValue.asObject()->asTemporalPlainTimeObject()->getSecond());
}

static Value builtinTemporalPlainTimeMilliSecond(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_TIME(state, thisValue);
    return Value(thisValue.asObject()->asTemporalPlainTimeObject()->getMillisecond());
}

static Value builtinTemporalPlainTimeMicroSecond(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_TIME(state, thisValue);
    return Value(thisValue.asObject()->asTemporalPlainTimeObject()->getMicrosecond());
}

static Value builtinTemporalPlainTimeNanoSecond(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_TIME(state, thisValue);
    return Value(thisValue.asObject()->asTemporalPlainTimeObject()->getNanosecond());
}

static Value builtinTemporalPlainTimePrototypeAdd(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_TIME(state, thisValue);

    return TemporalPlainTimeObject::addDurationToOrSubtractDurationFromPlainTime(state, TemporalPlainTimeObject::ADD, thisValue.asObject()->asTemporalPlainTimeObject(), argv[0]);
}

static Value builtinTemporalPlainTimePrototypeSubtract(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_TIME(state, thisValue);

    return TemporalPlainTimeObject::addDurationToOrSubtractDurationFromPlainTime(state, TemporalPlainTimeObject::SUBTRACT, thisValue.asObject()->asTemporalPlainTimeObject(), argv[0]);
}

static Value builtinTemporalPlainTimeWith(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_TIME(state, thisValue);
    TemporalPlainTimeObject* temporalTime = thisValue.asObject()->asTemporalPlainTimeObject();

    if (!argv[0].isObject()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "temporalTimeLike is not an Object");
    }

    TemporalObject::rejectObjectWithCalendarOrTimeZone(state, argv[0]);

    auto partialTime = TemporalPlainTimeObject::toPartialTime(state, argv[0]);

    Value overFlow = TemporalObject::toTemporalOverflow(state, TemporalObject::getOptionsObject(state, argc > 1 ? argv[1] : Value()));

    auto result = TemporalPlainTimeObject::regulateTime(state,
                                                        partialTime[TemporalObject::HOUR_UNIT].isUndefined() ? partialTime[TemporalObject::HOUR_UNIT].asInt32() : temporalTime->getHour(),
                                                        partialTime[TemporalObject::MINUTE_UNIT].isUndefined() ? partialTime[TemporalObject::MINUTE_UNIT].asInt32() : temporalTime->getMinute(),
                                                        partialTime[TemporalObject::SECOND_UNIT].isUndefined() ? partialTime[TemporalObject::SECOND_UNIT].asInt32() : temporalTime->getSecond(),
                                                        partialTime[TemporalObject::MILLISECOND_UNIT].isUndefined() ? partialTime[TemporalObject::MILLISECOND_UNIT].asInt32() : temporalTime->getMillisecond(),
                                                        partialTime[TemporalObject::MICROSECOND_UNIT].isUndefined() ? partialTime[TemporalObject::MICROSECOND_UNIT].asInt32() : temporalTime->getMicrosecond(),
                                                        partialTime[TemporalObject::NANOSECOND_UNIT].isUndefined() ? partialTime[TemporalObject::NANOSECOND_UNIT].asInt32() : temporalTime->getNanosecond(),
                                                        overFlow);
    return TemporalPlainTimeObject::createTemporalTime(state, result[TemporalObject::HOUR_UNIT], result[TemporalObject::MINUTE_UNIT], result[TemporalObject::SECOND_UNIT], result[TemporalObject::MILLISECOND_UNIT], result[TemporalObject::MICROSECOND_UNIT], result[TemporalObject::NANOSECOND_UNIT], overFlow.asObject());
}

static Value builtinTemporalPlainTimeToPlainDateTime(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_TIME(state, thisValue);
    auto temporalDate = TemporalPlainDateObject::toTemporalDate(state, argv[0], new Object(state)).asObject()->asTemporalPlainDateObject();
    TemporalPlainTimeObject* temporalTime = thisValue.asObject()->asTemporalPlainTimeObject();
    return TemporalPlainDateTimeObject::createTemporalDateTime(state, temporalDate->year(), temporalDate->month(),
                                                               temporalDate->day(), temporalTime->getHour(),
                                                               temporalTime->getMinute(), temporalTime->getSecond(),
                                                               temporalTime->getMillisecond(), temporalTime->getMicrosecond(),
                                                               temporalTime->getNanosecond(), temporalTime->getCalendar(), nullptr);
}

static Value builtinTemporalPlainTimeGetISOFields(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_TIME(state, thisValue);
    TemporalPlainTimeObject* temporalTime = thisValue.asObject()->asTemporalPlainTimeObject();
    auto fields = new Object(state);
    fields->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().calendar), ObjectPropertyDescriptor(temporalTime->getCalendar(), ObjectPropertyDescriptor::AllPresent));
    fields->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazyIsoHour()), ObjectPropertyDescriptor(Value(new ASCIIString(std::to_string(temporalTime->getHour()).c_str())), ObjectPropertyDescriptor::AllPresent));
    fields->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazyIsoMicrosecond()), ObjectPropertyDescriptor(Value(new ASCIIString(std::to_string(temporalTime->getMicrosecond()).c_str())), ObjectPropertyDescriptor::AllPresent));
    fields->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazyIsoMillisecond()), ObjectPropertyDescriptor(Value(new ASCIIString(std::to_string(temporalTime->getMillisecond()).c_str())), ObjectPropertyDescriptor::AllPresent));
    fields->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazyIsoMinute()), ObjectPropertyDescriptor(Value(new ASCIIString(std::to_string(temporalTime->getMinute()).c_str())), ObjectPropertyDescriptor::AllPresent));
    fields->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazyIsoNanosecond()), ObjectPropertyDescriptor(Value(new ASCIIString(std::to_string(temporalTime->getNanosecond()).c_str())), ObjectPropertyDescriptor::AllPresent));
    fields->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazyIsoSecond()), ObjectPropertyDescriptor(Value(new ASCIIString(std::to_string(temporalTime->getSecond()).c_str())), ObjectPropertyDescriptor::AllPresent));
    return fields;
}

static Value builtinTemporalPlainTimeEquals(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_TIME(state, thisValue);
    auto other = TemporalPlainTimeObject::toTemporalTime(state, argv[0], Value()).asObject()->asTemporalPlainTimeObject();
    auto temporalTime = thisValue.asObject()->asTemporalPlainTimeObject();
    return Value(other->getHour() == temporalTime->getHour() && other->getMinute() == temporalTime->getMinute() && other->getSecond() == temporalTime->getSecond() && other->getMillisecond() == temporalTime->getMillisecond() && other->getMicrosecond() == temporalTime->getMicrosecond() && other->getNanosecond() == temporalTime->getNanosecond());
}

static Value builtinTemporalPlainDateTimeConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!newTarget.hasValue()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, ErrorObject::Messages::New_Target_Is_Undefined);
    }

    ASSERT(argc > 2);

    if (!argv[0].isInteger(state) || !argv[1].isInteger(state) || !argv[2].isInteger(state)
        || (argc > 3 && !argv[3].isInteger(state)) || (argc > 4 && !argv[4].isInteger(state))
        || (argc > 5 && !argv[5].isInteger(state)) || (argc > 6 && !argv[6].isInteger(state))
        || (argc > 7 && !argv[7].isInteger(state)) || (argc > 8 && !argv[8].isInteger(state))) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type");
    }

    Value calendar = TemporalCalendarObject::toTemporalCalendarWithISODefault(state, argc > 8 ? argv[9] : Value());
    return TemporalPlainDateTimeObject::createTemporalDateTime(state, argv[0].asInt32(), argv[1].asInt32(), argv[2].asInt32(), argc > 3 ? argv[3].asInt32() : 0, argc > 4 ? argv[4].asInt32() : 0, argc > 5 ? argv[5].asInt32() : 0, argc > 6 ? argv[6].asInt32() : 0, argc > 7 ? argv[7].asInt32() : 0, argc > 8 ? argv[8].asInt32() : 0, calendar, nullptr);
}

static Value builtinTemporalPlainDateTimeFrom(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (argc > 1 && !argv[1].isObject()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "options must be object");
    }

    if (argv[0].isObject() && argv[0].asObject()->isTemporalPlainDateTimeObject()) {
        TemporalObject::toTemporalOverflow(state, argc > 1 ? Value(argv[1].asObject()) : Value());
        TemporalPlainDateTimeObject* plainDateTime = argv[0].asObject()->asTemporalPlainDateTimeObject();
        return TemporalPlainDateTimeObject::createTemporalDateTime(state, plainDateTime->getYear(), plainDateTime->getMonth(),
                                                                   plainDateTime->getDay(), plainDateTime->getHour(),
                                                                   plainDateTime->getMinute(), plainDateTime->getSecond(),
                                                                   plainDateTime->getMillisecond(),
                                                                   plainDateTime->getMicrosecond(),
                                                                   plainDateTime->getNanosecond(),
                                                                   plainDateTime->getCalendar(), nullptr);
    }
    return TemporalPlainDateTimeObject::toTemporalDateTime(state, argv[0], argc > 1 ? argv[1].asObject() : nullptr);
}

static Value builtinTemporalPlainDateTimeCalendar(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);
    return thisValue.asObject()->asTemporalPlainDateTimeObject()->getCalendar();
}

static Value builtinTemporalPlainDateTimeYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);
    return TemporalCalendarObject::calendarYear(state, thisValue.asObject()->asTemporalPlainDateTimeObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateTimeMonth(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);
    return TemporalCalendarObject::calendarMonth(state, thisValue.asObject()->asTemporalPlainDateTimeObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateTimeMonthCode(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);
    return TemporalCalendarObject::calendarMonthCode(state, thisValue.asObject()->asTemporalPlainDateTimeObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateTimeDay(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);
    return TemporalCalendarObject::calendarDay(state, thisValue.asObject()->asTemporalPlainDateTimeObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateTimeDayOfWeek(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);
    return TemporalCalendarObject::calendarDayOfWeek(state, thisValue.asObject()->asTemporalPlainDateTimeObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateTimeDayOfYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);
    return TemporalCalendarObject::calendarDayOfYear(state, thisValue.asObject()->asTemporalPlainDateTimeObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateTimeWeekOfYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);
    return TemporalCalendarObject::calendarWeekOfYear(state, thisValue.asObject()->asTemporalPlainDateTimeObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateTimeDaysInWeek(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);
    return TemporalCalendarObject::calendarDaysInWeek(state, thisValue.asObject()->asTemporalPlainDateTimeObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateTimeDaysInMonth(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);
    return TemporalCalendarObject::calendarDaysInMonth(state, thisValue.asObject()->asTemporalPlainDateTimeObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateTimeDaysInYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);
    return TemporalCalendarObject::calendarDaysInYear(state, thisValue.asObject()->asTemporalPlainDateTimeObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateTimeMonthsInYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);
    return TemporalCalendarObject::calendarMonthsInYear(state, thisValue.asObject()->asTemporalPlainDateTimeObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateTimeInLeapYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);
    return TemporalCalendarObject::calendarInLeapYear(state, thisValue.asObject()->asTemporalPlainDateTimeObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainDateTimePrototypeAdd(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);

    return TemporalPlainDateTimeObject::addDurationToOrSubtractDurationFromPlainDateTime(state, TemporalPlainTimeObject::ADD, thisValue.asObject()->asTemporalPlainDateTimeObject(), argv[0], argc > 1 ? argv[1] : Value());
}

static Value builtinTemporalPlainDateTimePrototypeSubtract(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_DATE_TIME(state, thisValue);

    return TemporalPlainDateTimeObject::addDurationToOrSubtractDurationFromPlainDateTime(state, TemporalPlainTimeObject::SUBTRACT, thisValue.asObject()->asTemporalPlainDateTimeObject(), argv[0], argc > 1 ? argv[1] : Value());
}

static Value builtinTemporalZonedDateTimeConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!argv[0].isBigInt()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type");
    }

    if (!TemporalInstantObject::isValidEpochNanoseconds(argv[0])) {
        ErrorObject::throwBuiltinError(state, ErrorCode::RangeError, "epoch Nanoseconds is out of range");
    }

    auto timeZoneValue = TemporalTimeZoneObject::toTemporalTimeZone(state, argv[1]);
    if (!timeZoneValue.asObject()->isTemporalTimeZoneObject()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type");
    }
    auto calendarValue = TemporalCalendarObject::toTemporalCalendarWithISODefault(state, argc > 2 ? argv[2] : Value());
    if (!calendarValue.asObject()->isTemporalCalendarObject()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type");
    }
    return TemporalZonedDateTimeObject::createTemporalZonedDateTime(state, *(argv[0].asBigInt()), timeZoneValue.asObject()->asTemporalTimeZoneObject(), calendarValue.asObject()->asTemporalCalendarObject(), newTarget);
}

static Value builtinTemporalZonedDateTimeFrom(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value options = TemporalObject::getOptionsObject(state, argc > 1 ? argv[1] : Value());

    if (argv[0].isObject() && argv[0].asObject()->isTemporalZonedDateTimeObject()) {
        TemporalObject::toTemporalOverflow(state, options);
        TemporalObject::toTemporalDisambiguation(state, options);
        TemporalObject::toTemporalOffset(state, options, Value(state.context()->staticStrings().reject.string()));
        auto item = argv[0].asObject()->asTemporalZonedDateTimeObject();
        return TemporalZonedDateTimeObject::createTemporalZonedDateTime(state, *(item->getNanoseconds()), item->getTimeZone(), item->getCalendar());
    }

    return TemporalZonedDateTimeObject::toTemporalZonedDateTime(state, argv[0], options);
}

static Value builtinTemporalZonedDateTimeCompare(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    return Value(TemporalInstantObject::compareEpochNanoseconds(state, *TemporalZonedDateTimeObject::toTemporalZonedDateTime(state, argv[0]).asObject()->asTemporalZonedDateTimeObject()->getNanoseconds(), *TemporalZonedDateTimeObject::toTemporalZonedDateTime(state, argv[1]).asObject()->asTemporalZonedDateTimeObject()->getNanoseconds()));
}

static Value builtinTemporalZonedDateTimeCalendar(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return thisValue.asObject()->asTemporalZonedDateTimeObject()->getCalendar();
}

static Value builtinTemporalZonedDateTimeTimeZone(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return thisValue.asObject()->asTemporalZonedDateTimeObject()->getTimeZone();
}

static Value builtinTemporalZonedDateTimeYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return TemporalCalendarObject::calendarYear(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getCalendar(), thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state));
}

static Value builtinTemporalZonedDateTimeMonth(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return TemporalCalendarObject::calendarMonth(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getCalendar(), thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state));
}

static Value builtinTemporalZonedDateTimeMonthCode(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return TemporalCalendarObject::calendarMonthCode(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getCalendar(), thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state));
}

static Value builtinTemporalZonedDateTimeDay(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return TemporalCalendarObject::calendarDay(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getCalendar(), thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state));
}

static Value builtinTemporalZonedDateTimeHour(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return Value(thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state)->getHour());
}

static Value builtinTemporalZonedDateTimeMinute(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return Value(thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state)->getMinute());
}

static Value builtinTemporalZonedDateTimeSecond(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return Value(thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state)->getSecond());
}

static Value builtinTemporalZonedDateTimeMillisecond(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return Value(thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state)->getMillisecond());
}

static Value builtinTemporalZonedDateTimeMicrosecond(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return Value(thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state)->getMicrosecond());
}

static Value builtinTemporalZonedDateTimeNanosecond(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return Value(thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state)->getNanosecond());
}

static Value builtinTemporalZonedDateTimeEpochSeconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return Value(thisValue.asObject()->asTemporalZonedDateTimeObject()->getNanoseconds()->division(state, new BigInt(TemporalInstantObject::SecondToNanosecond)));
}

static Value builtinTemporalZonedDateTimeEpochMilliSeconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return Value(thisValue.asObject()->asTemporalZonedDateTimeObject()->getNanoseconds()->division(state, new BigInt(TemporalInstantObject::MillisecondToNanosecond)));
}

static Value builtinTemporalZonedDateTimeEpochMicroSeconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return Value(thisValue.asObject()->asTemporalZonedDateTimeObject()->getNanoseconds()->division(state, new BigInt(TemporalInstantObject::MicrosecondToNanosecond)));
}

static Value builtinTemporalZonedDateTimeEpochNanoSeconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return Value(thisValue.asObject()->asTemporalZonedDateTimeObject()->getNanoseconds());
}

static Value builtinTemporalZonedDateTimeDayOfWeek(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return TemporalCalendarObject::calendarDayOfWeek(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getCalendar(), thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state));
}

static Value builtinTemporalZonedDateTimeDayOfYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return TemporalCalendarObject::calendarDayOfYear(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getCalendar(), thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state));
}

static Value builtinTemporalZonedDateTimeWeekOfYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return TemporalCalendarObject::calendarWeekOfYear(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getCalendar(), thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state));
}

static Value builtinTemporalZonedDateTimeHoursInDay(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    auto instant = TemporalInstantObject::createTemporalInstant(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getNanoseconds());
    auto temporalDateTime = TemporalTimeZoneObject::builtinTimeZoneGetPlainDateTimeFor(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getTimeZone(), instant, TemporalCalendarObject::getISO8601Calendar(state)).asObject()->asTemporalPlainDateTimeObject();
    auto today = TemporalPlainDateTimeObject::createTemporalDateTime(state, temporalDateTime->getYear(), temporalDateTime->getMonth(), temporalDateTime->getDay(), 0, 0, 0, 0, 0, 0, TemporalCalendarObject::getISO8601Calendar(state));
    auto tomorrowFields = TemporalPlainDateObject::balanceISODate(state, temporalDateTime->getYear(), temporalDateTime->getMonth(), temporalDateTime->getDay() + 1);
    auto tomorrow = TemporalPlainDateTimeObject::createTemporalDateTime(state, tomorrowFields[TemporalObject::YEAR_UNIT], tomorrowFields[TemporalObject::MONTH_UNIT], tomorrowFields[TemporalObject::DAY_UNIT], 0, 0, 0, 0, 0, 0, TemporalCalendarObject::getISO8601Calendar(state));
    auto todayInstant = TemporalTimeZoneObject::builtinTimeZoneGetInstantFor(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getTimeZone(), today, Value(state.context()->staticStrings().lazyCompatible().string()));
    auto tomorrowInstant = TemporalTimeZoneObject::builtinTimeZoneGetInstantFor(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getTimeZone(), tomorrow, Value(state.context()->staticStrings().lazyCompatible().string()));
    return Value(tomorrowInstant.asObject()->asTemporalInstantObject()->getNanoseconds()->subtraction(state, todayInstant.asObject()->asTemporalZonedDateTimeObject()->getNanoseconds())->division(state, new BigInt(TemporalInstantObject::HourToNanosecond)));
}

static Value builtinTemporalZonedDateTimeDaysInWeek(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return TemporalCalendarObject::calendarDaysInWeek(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getCalendar(), thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state));
}

static Value builtinTemporalZonedDateTimeDaysInMonth(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return TemporalCalendarObject::calendarDaysInMonth(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getCalendar(), thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state));
}

static Value builtinTemporalZonedDateTimeDaysInYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return TemporalCalendarObject::calendarDaysInYear(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getCalendar(), thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state));
}

static Value builtinTemporalZonedDateTimeMonthsInYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return TemporalCalendarObject::calendarMonthsInYear(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getCalendar(), thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state));
}

static Value builtinTemporalZonedDateTimeInLeapYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return TemporalCalendarObject::calendarInLeapYear(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getCalendar(), thisValue.asObject()->asTemporalZonedDateTimeObject()->toTemporalPlainDateTime(state));
}

static Value builtinTemporalZonedDateTimeOffsetNanoseconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return Value(TemporalTimeZoneObject::getOffsetNanosecondsFor(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getTimeZone(), TemporalInstantObject::createTemporalInstant(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getNanoseconds())));
}

static Value builtinTemporalZonedDateTimeOffset(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue)

    return Value(TemporalTimeZoneObject::builtinTimeZoneGetOffsetStringFor(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getTimeZone(), TemporalInstantObject::createTemporalInstant(state, thisValue.asObject()->asTemporalZonedDateTimeObject()->getNanoseconds())));
}

static Value builtinTemporalZonedDateTimePrototypeAdd(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue);

    return TemporalZonedDateTimeObject::addDurationToOrSubtractDurationFromZonedDateTime(state, TemporalPlainTimeObject::ADD, thisValue.asObject()->asTemporalZonedDateTimeObject(), argv[0], argc > 1 ? argv[1] : Value());
}

static Value builtinTemporalZonedDateTimePrototypeSubtract(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_ZONED_DATE_TIME(state, thisValue);

    return TemporalZonedDateTimeObject::addDurationToOrSubtractDurationFromZonedDateTime(state, TemporalPlainTimeObject::SUBTRACT, thisValue.asObject()->asTemporalZonedDateTimeObject(), argv[0], argc > 1 ? argv[1] : Value());
}

static Value builtinTemporalDurationConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!newTarget.hasValue()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, ErrorObject::Messages::New_Target_Is_Undefined);
    }

    double values[10];
    memset(values, 0, sizeof(values));

    for (unsigned int i = 0; i < argc && i < 10; ++i) {
        if (!argv[i].isInteger(state)) {
            ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type");
        }
        values[i] = argv[i].toInteger(state);
    }

    return TemporalDurationObject::createTemporalDuration(state, values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7], values[8], values[9], newTarget);
}

static Value builtinTemporalDurationFrom(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (argc == 0) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid first argument");
    }

    if (argv[0].isObject() && argv[0].asObject()->isTemporalDurationObject()) {
        auto item = argv[0].asObject()->asTemporalDurationObject();
        return TemporalDurationObject::createTemporalDuration(state, item->getYear(), item->getMonth(), item->getWeek(), item->getDay(), item->getHour(), item->getMinute(), item->getSecond(), item->getMillisecond(), item->getMicrosecond(), item->getNanosecond(), newTarget);
    }
    return TemporalDurationObject::toTemporalDuration(state, argv[0]);
}

static Value builtinTemporalDurationPrototypeYears(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);
    return Value(thisValue.asObject()->asTemporalDurationObject()->getYear());
}

static Value builtinTemporalDurationPrototypeMonths(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);
    return Value(thisValue.asObject()->asTemporalDurationObject()->getMonth());
}

static Value builtinTemporalDurationPrototypeWeeks(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);
    return Value(thisValue.asObject()->asTemporalDurationObject()->getWeek());
}

static Value builtinTemporalDurationPrototypeDays(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);
    return Value(thisValue.asObject()->asTemporalDurationObject()->getDay());
}

static Value builtinTemporalDurationPrototypeHours(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);
    return Value(thisValue.asObject()->asTemporalDurationObject()->getHour());
}

static Value builtinTemporalDurationPrototypeMinutes(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);
    return Value(thisValue.asObject()->asTemporalDurationObject()->getMinute());
}

static Value builtinTemporalDurationPrototypeSeconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);
    return Value(thisValue.asObject()->asTemporalDurationObject()->getSecond());
}

static Value builtinTemporalDurationPrototypeMilliSeconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);
    return Value(thisValue.asObject()->asTemporalDurationObject()->getMillisecond());
}

static Value builtinTemporalDurationPrototypeMicroSeconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);
    return Value(thisValue.asObject()->asTemporalDurationObject()->getMicrosecond());
}

static Value builtinTemporalDurationPrototypeNanoSeconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);
    return Value(thisValue.asObject()->asTemporalDurationObject()->getNanosecond());
}

static Value builtinTemporalDurationPrototypeSign(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);
    auto duration = thisValue.asObject()->asTemporalDurationObject();
    int dateTime[] = { duration->getYear(), duration->getMonth(), duration->getWeek(), duration->getDay(), duration->getHour(), duration->getMinute(), duration->getSecond(), duration->getMillisecond(), duration->getMicrosecond(), duration->getNanosecond() };
    return Value(TemporalDurationObject::durationSign(dateTime));
}

static Value builtinTemporalDurationPrototypeBlank(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);
    auto duration = thisValue.asObject()->asTemporalDurationObject();
    int dateTime[] = { duration->getYear(), duration->getMonth(), duration->getWeek(), duration->getDay(), duration->getHour(), duration->getMinute(), duration->getSecond(), duration->getMillisecond(), duration->getMicrosecond(), duration->getNanosecond() };
    return Value(TemporalDurationObject::durationSign(dateTime) == 0);
}

static Value builtinTemporalDurationPrototypeNegated(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);
    return TemporalDurationObject::createNegatedTemporalDuration(state, thisValue);
}

static Value builtinTemporalDurationPrototypeAbs(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);
    auto duration = thisValue.asObject()->asTemporalDurationObject();
    return TemporalDurationObject::createTemporalDuration(state, std::abs(duration->getYear()), std::abs(duration->getMonth()), std::abs(duration->getWeek()), std::abs(duration->getDay()), std::abs(duration->getHour()), std::abs(duration->getMinute()), std::abs(duration->getSecond()), std::abs(duration->getMillisecond()), std::abs(duration->getMicrosecond()), std::abs(duration->getNanosecond()), nullptr);
}

static Value builtinTemporalDurationPrototypeAdd(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);

    return TemporalDurationObject::addDurationToOrSubtractDurationFromDuration(state, TemporalPlainTimeObject::ADD, thisValue.asObject()->asTemporalDurationObject(), argv[0], argc > 1 ? argv[1] : Value());
}

static Value builtinTemporalDurationPrototypeSubtract(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_DURATION(state, thisValue);

    return TemporalDurationObject::addDurationToOrSubtractDurationFromDuration(state, TemporalPlainTimeObject::SUBTRACT, thisValue.asObject()->asTemporalDurationObject(), argv[0], argc > 1 ? argv[1] : Value());
}

static Value builtinTemporalPlainYearMonthConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!newTarget.hasValue()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, ErrorObject::Messages::New_Target_Is_Undefined);
    }

    int referenceISODay = 1;

    if (argc >= 4) {
        if (argv[3].isInt32()) {
            ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type");
        }
        referenceISODay = argv[3].asInt32();
    }

    return TemporalPlainYearMonthObject::createTemporalYearMonth(state, argv[0].asInt32(), argv[1].asInt32(), TemporalCalendarObject::toTemporalCalendarWithISODefault(state, argc >= 3 ? argv[2] : Value()), referenceISODay, newTarget);
}

static Value builtinTemporalPlainYearMonthFrom(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    auto options = TemporalObject::getOptionsObject(state, argc == 2 ? argv[1] : Value());

    if (argv[0].isObject() && argv[0].asObject()->isTemporalPlainYearMonthObject()) {
        TemporalObject::toTemporalOverflow(state, options);
        auto item = argv[0].asObject()->asTemporalPlainYearMonthObject();
        return TemporalPlainYearMonthObject::createTemporalYearMonth(state, item->getIsoYear(), item->getIsoMonth(), item->getCalendar(), item->getReferenceIsoDay());
    }

    return TemporalPlainYearMonthObject::toTemporalYearMonth(state, argv[0], options);
}

static Value builtinTemporalPlainYearMonthCompare(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    auto firstTemporalYearMonth = TemporalPlainYearMonthObject::toTemporalYearMonth(state, argv[0], Value()).asObject()->asTemporalPlainYearMonthObject();
    auto secondTemporalYearMonth = TemporalPlainYearMonthObject::toTemporalYearMonth(state, argv[1], Value()).asObject()->asTemporalPlainYearMonthObject();
    return Value(TemporalPlainDateObject::compareISODate(firstTemporalYearMonth->getIsoYear(), firstTemporalYearMonth->getIsoMonth(), firstTemporalYearMonth->getReferenceIsoDay(), secondTemporalYearMonth->getIsoYear(), secondTemporalYearMonth->getIsoMonth(), secondTemporalYearMonth->getReferenceIsoDay()));
}

static Value builtinTemporalPlainYearMonthCalendar(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, thisValue);
    return thisValue.asObject()->asTemporalPlainYearMonthObject()->getCalendar();
}

static Value builtinTemporalPlainYearMonthYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, thisValue);
    return TemporalCalendarObject::calendarYear(state, thisValue.asObject()->asTemporalPlainYearMonthObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainYearMonthMonth(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, thisValue);
    return TemporalCalendarObject::calendarMonth(state, thisValue.asObject()->asTemporalPlainYearMonthObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainYearMonthMonthCode(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, thisValue);
    return TemporalCalendarObject::calendarMonthCode(state, thisValue.asObject()->asTemporalPlainYearMonthObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainYearMonthDay(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, thisValue);
    return TemporalCalendarObject::calendarDay(state, thisValue.asObject()->asTemporalPlainYearMonthObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainYearMonthDayOfWeek(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, thisValue);
    return TemporalCalendarObject::calendarDayOfWeek(state, thisValue.asObject()->asTemporalPlainYearMonthObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainYearMonthDayOfYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, thisValue);
    return TemporalCalendarObject::calendarDayOfYear(state, thisValue.asObject()->asTemporalPlainYearMonthObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainYearMonthWeekOfYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, thisValue);
    return TemporalCalendarObject::calendarWeekOfYear(state, thisValue.asObject()->asTemporalPlainYearMonthObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainYearMonthDaysInWeek(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, thisValue);
    return TemporalCalendarObject::calendarDaysInWeek(state, thisValue.asObject()->asTemporalPlainYearMonthObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainYearMonthDaysInMonth(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, thisValue);
    return TemporalCalendarObject::calendarDaysInMonth(state, thisValue.asObject()->asTemporalPlainYearMonthObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainYearMonthDaysInYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, thisValue);
    return TemporalCalendarObject::calendarDaysInYear(state, thisValue.asObject()->asTemporalPlainYearMonthObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainYearMonthMonthsInYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, thisValue);
    return TemporalCalendarObject::calendarMonthsInYear(state, thisValue.asObject()->asTemporalPlainYearMonthObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainYearMonthInLeapYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, thisValue);
    return TemporalCalendarObject::calendarInLeapYear(state, thisValue.asObject()->asTemporalPlainYearMonthObject()->getCalendar(), thisValue);
}

static Value builtinTemporalPlainYearMonthPrototypeEquals(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    auto other = TemporalPlainYearMonthObject::toTemporalYearMonth(state, argv[0], Value()).asObject()->asTemporalPlainYearMonthObject();
    auto yearMonth = thisValue.asObject()->asTemporalPlainYearMonthObject();

    return Value(!(yearMonth->getIsoYear() != other->getIsoYear() || yearMonth->getIsoMonth() != other->getIsoMonth() || yearMonth->getReferenceIsoDay() != other->getReferenceIsoDay()) || yearMonth->getCalendar() == other->getCalendar());
}

static Value builtinTemporalPlainYearMonthPrototypeAdd(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_PLAIN_YEAR_MONTH(state, thisValue);

    return TemporalPlainYearMonthObject::addDurationToOrSubtractDurationFromPlainYearMonth(state, TemporalPlainTimeObject::ADD, thisValue.asObject()->asTemporalPlainYearMonthObject(), argv[0], argc > 1 ? argv[1] : Value());
}

static Value builtinTemporalPlainYearMonthPrototypeSubtract(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_INSTANT(state, thisValue);

    return TemporalPlainYearMonthObject::addDurationToOrSubtractDurationFromPlainYearMonth(state, TemporalPlainTimeObject::SUBTRACT, thisValue.asObject()->asTemporalPlainYearMonthObject(), argv[0], argc > 1 ? argv[1] : Value());
}

static Value builtinTemporalInstantConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!newTarget.hasValue()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, ErrorObject::Messages::New_Target_Is_Undefined);
    }

    if (argc == 0) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, ErrorObject::Messages::GlobalObject_IllegalFirstArgument);
    }

    if (!(argv[0].isBigInt() || argv[0].isString())) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type");
    }

    if (!TemporalInstantObject::isValidEpochNanoseconds(argv[0].toBigInt(state))) {
        ErrorObject::throwBuiltinError(state, ErrorCode::RangeError, "Invalid epoch nanoseconds");
    }

    return TemporalInstantObject::createTemporalInstant(state, argv[0].toBigInt(state), newTarget);
}

static Value builtinTemporalInstantFrom(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (argc == 0) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, ErrorObject::Messages::GlobalObject_IllegalFirstArgument);
    }

    if (argv[0].isObject() && argv[0].asObject()->isTemporalInstantObject()) {
        return TemporalInstantObject::createTemporalInstant(state, argv[0].asObject()->asTemporalInstantObject()->getNanoseconds());
    }

    return TemporalInstantObject::toTemporalInstant(state, argv[0]);
}

static Value builtinTemporalInstantFromEpochSeconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    return temporalInstantFromEpoch(state, argc, argv, new BigInt(TemporalInstantObject::SecondToNanosecond));
}

static Value builtinTemporalInstantFromEpochMilliSeconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    return temporalInstantFromEpoch(state, argc, argv, new BigInt(TemporalInstantObject::MillisecondToNanosecond));
}

static Value builtinTemporalInstantFromEpochMicroSeconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    return temporalInstantFromEpoch(state, argc, argv, new BigInt(TemporalInstantObject::MicrosecondToNanosecond));
}

static Value builtinTemporalInstantFromEpochNanoSeconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    return temporalInstantFromEpoch(state, argc, argv, new BigInt((int64_t)1));
}

static Value builtinTemporalInstantCompare(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    auto firstTemporalInstant = TemporalInstantObject::toTemporalInstant(state, argv[0]);
    auto secondTemporalInstant = TemporalInstantObject::toTemporalInstant(state, argv[1]);
    return Value(TemporalInstantObject::compareEpochNanoseconds(state, *firstTemporalInstant.asObject()->asTemporalInstantObject()->getNanoseconds(), *secondTemporalInstant.asObject()->asTemporalInstantObject()->getNanoseconds()));
}

static Value builtinTemporalInstantPrototypeEpochSeconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_INSTANT(state, thisValue);

    return Value(thisValue.asObject()->asTemporalInstantObject()->getNanoseconds()->division(state, new BigInt(TemporalInstantObject::SecondToNanosecond)));
}

static Value builtinTemporalInstantPrototypeEpochMilliseconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_INSTANT(state, thisValue);

    return Value(thisValue.asObject()->asTemporalInstantObject()->getNanoseconds()->division(state, new BigInt(TemporalInstantObject::MillisecondToNanosecond)));
}

static Value builtinTemporalInstantPrototypeEpochMicroseconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_INSTANT(state, thisValue);

    return Value(thisValue.asObject()->asTemporalInstantObject()->getNanoseconds()->division(state, new BigInt(TemporalInstantObject::MicrosecondToNanosecond)));
}

static Value builtinTemporalInstantPrototypeEpochNanoseconds(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_INSTANT(state, thisValue);

    return { thisValue.asObject()->asTemporalInstantObject()->getNanoseconds() };
}

static Value builtinTemporalInstantPrototypeEquals(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    return Value(TemporalInstantObject::toTemporalInstant(state, argv[0]).asObject()->asTemporalInstantObject()->getNanoseconds() == thisValue.asObject()->asTemporalInstantObject()->getNanoseconds());
}

static Value builtinTemporalInstantPrototypeAdd(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_INSTANT(state, thisValue);

    return TemporalInstantObject::addDurationToOrSubtractDurationFromInstant(state, TemporalPlainTimeObject::ADD, thisValue.asObject()->asTemporalInstantObject(), argv[0], argc > 1 ? argv[1] : Value());
}

static Value builtinTemporalInstantPrototypeSubtract(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_INSTANT(state, thisValue);

    return TemporalInstantObject::addDurationToOrSubtractDurationFromInstant(state, TemporalPlainTimeObject::SUBTRACT, thisValue.asObject()->asTemporalInstantObject(), argv[0], argc > 1 ? argv[1] : Value());
}

static Value builtinTemporalPlainMonthDayConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!newTarget.hasValue()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, ErrorObject::Messages::New_Target_Is_Undefined);
    }

    int referenceISOYear = 1972;

    if (argc >= 4) {
        if (!argv[3].isInt32()) {
            ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Invalid type");
        }
        referenceISOYear = argv[3].asInt32();
    }

    return TemporalPlainMonthDayObject::createTemporalMonthDay(state, argv[0].asInt32(), argv[1].asInt32(), TemporalCalendarObject::toTemporalCalendarWithISODefault(state, argc >= 3 ? argv[2] : Value()).asObject()->asTemporalCalendarObject(), referenceISOYear);
}

static Value builtinTemporalPlainMonthDayFrom(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    auto options = TemporalObject::getOptionsObject(state, argc >= 2 ? argv[1] : Value());

    if (argv[0].isObject() && argv[0].asObject()->isTemporalPlainMonthDayObject()) {
        TemporalObject::toTemporalOverflow(state, options);
        auto item = argv[0].asObject()->asTemporalPlainMonthDayObject();
        return TemporalPlainMonthDayObject::createTemporalMonthDay(state, item->getIsoMonth(), item->getIsoDay(), item->getCalendar(), item->getReferenceIsoYear());
    }
    return TemporalPlainMonthDayObject::toTemporalMonthDay(state, argv[0], options);
}

static Value builtinTemporalPlainMonthDayPrototypeCalendar(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    return thisValue.asObject()->asTemporalPlainMonthDayObject()->getCalendar();
}

static Value builtinTemporalPlainMonthDayPrototypeMonthCode(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    return TemporalCalendarObject::calendarMonthCode(state, thisValue.asObject()->asTemporalPlainMonthDayObject()->getCalendar(), thisValue.asObject()->asTemporalPlainMonthDayObject());
}

static Value builtinTemporalPlainMonthDayPrototypeDay(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    return TemporalCalendarObject::calendarDay(state, thisValue.asObject()->asTemporalPlainMonthDayObject()->getCalendar(), thisValue.asObject()->asTemporalPlainMonthDayObject());
}

static Value builtinTemporalTimeZoneConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!newTarget.hasValue()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, ErrorObject::Messages::New_Target_Is_Undefined);
    }

    if (!argv[0].isString()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::RangeError, "Expected string");
    }

    std::string identifier(argv[0].asString()->toNonGCUTF8StringData());
    unsigned int index = 0;
    identifier = TemporalObject::offset(state, identifier, index);

    if (identifier.empty()) {
        if (!TemporalTimeZoneObject::isValidTimeZoneName(argv[0].asString()->toNonGCUTF8StringData())) {
            ErrorObject::throwBuiltinError(state, ErrorCode::RangeError, "Invalid TimeZone identifier");
        }
        identifier = TemporalTimeZoneObject::canonicalizeTimeZoneName(argv[0].asString()->toNonGCUTF8StringData());
    }

    return TemporalTimeZoneObject::createTemporalTimeZone(state, identifier, newTarget);
}

static Value builtinTemporalTimeZoneFrom(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    return TemporalTimeZoneObject::toTemporalTimeZone(state, argv[0]);
}

static Value builtinTemporalTimeZonePrototypeId(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_TIME_ZONE(state, thisValue);
    return Value(thisValue.asObject()->asTemporalTimeZoneObject()->getIdentifier());
}

static Value builtinTemporalTimeZonePrototypeGetOffsetNanosecondsFor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_TIME_ZONE(state, thisValue);
    CHECK_TEMPORAL_TIME_ZONE_OFFSET_VALUE(state, thisValue);

    auto instant = TemporalInstantObject::toTemporalInstant(state, argv[0]).asObject()->asTemporalInstantObject();

    if (!thisValue.asObject()->asTemporalTimeZoneObject()->getOffsetNanoseconds().isUndefined()) {
        return thisValue.asObject()->asTemporalTimeZoneObject()->getOffsetNanoseconds();
    }

    return Value(TemporalTimeZoneObject::getIANATimeZoneOffsetNanoseconds(state, new BigInt((int64_t)0), thisValue.asObject()->asTemporalTimeZoneObject()->getIdentifier()->toNonGCUTF8StringData()).asBigInt()->toInt64());
}

static Value builtinTemporalTimeZonePrototypeGetOffsetStringFor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_TIME_ZONE(state, thisValue);
    CHECK_TEMPORAL_TIME_ZONE_OFFSET_VALUE(state, thisValue);

    auto instant = TemporalInstantObject::toTemporalInstant(state, argv[0]).asObject()->asTemporalInstantObject();

    return TemporalTimeZoneObject::builtinTimeZoneGetOffsetStringFor(state, thisValue, instant);
}

static Value builtinTemporalTimeZonePrototypeGetPlainDateTimeFor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_TIME_ZONE(state, thisValue);
    CHECK_TEMPORAL_TIME_ZONE_OFFSET_VALUE(state, thisValue);
    auto instant = TemporalInstantObject::toTemporalInstant(state, argv[0]);
    auto calendar = TemporalCalendarObject::toTemporalCalendarWithISODefault(state, argc >= 2 ? argv[1] : Value());
    return TemporalTimeZoneObject::builtinTimeZoneGetPlainDateTimeFor(state, thisValue, instant, calendar);
}

static Value builtinTemporalTimeZonePrototypeGetPossibleInstantsFor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_TIME_ZONE(state, thisValue);
    CHECK_TEMPORAL_TIME_ZONE_OFFSET_VALUE(state, thisValue);

    auto dateTime = TemporalPlainDateTimeObject::toTemporalDateTime(state, argv[0]).asObject()->asTemporalPlainDateTimeObject();
    ValueVector possibleEpochNanoseconds = {};

    if (!thisValue.asObject()->asTemporalTimeZoneObject()->getOffsetNanoseconds().isUndefined()) {
        int64_t epochNanoseconds = TemporalPlainDateTimeObject::getEpochFromISOParts(state, dateTime->getYear(), dateTime->getMonth(), dateTime->getDay(), dateTime->getHour(), dateTime->getMinute(), dateTime->getSecond(), dateTime->getMillisecond(), dateTime->getMicrosecond(), dateTime->getNanosecond());
        possibleEpochNanoseconds.push_back(Value(epochNanoseconds - thisValue.asObject()->asTemporalTimeZoneObject()->getOffsetNanoseconds().asBigInt()->toInt64()));
    } else {
        possibleEpochNanoseconds = TemporalTimeZoneObject::getIANATimeZoneEpochValue(state, thisValue.asObject()->asTemporalTimeZoneObject()->getIdentifier()->toNonGCUTF8StringData(), dateTime->getYear(), dateTime->getMonth(), dateTime->getDay(), dateTime->getHour(), dateTime->getMinute(), dateTime->getSecond(), dateTime->getMillisecond(), dateTime->getMicrosecond(), dateTime->getNanosecond());
    }

    ValueVector possibleInstants = {};

    for (auto& possibleEpochNanosecond : possibleEpochNanoseconds) {
        if (!TemporalInstantObject::isValidEpochNanoseconds(possibleEpochNanosecond)) {
            ErrorObject::throwBuiltinError(state, ErrorCode::RangeError, "Invalid epoch nanosecond");
        }
        possibleInstants.push_back(TemporalInstantObject::createTemporalInstant(state, possibleEpochNanosecond));
    }

    return Object::createArrayFromList(state, possibleInstants);
}

static Value builtinTemporalTimeZonePrototypeGetNextTransition(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_TIME_ZONE(state, thisValue);
    CHECK_TEMPORAL_TIME_ZONE_OFFSET_VALUE(state, thisValue);

    auto startingPoint = TemporalInstantObject::toTemporalInstant(state, argv[0]).asObject()->asTemporalInstantObject();

    if (!thisValue.asObject()->asTemporalTimeZoneObject()->getOffsetNanoseconds().isUndefined()) {
        return Value(Value::Null);
    }

    auto result = TemporalTimeZoneObject::getIANATimeZoneNextTransition(state, startingPoint->getNanoseconds(), thisValue.asObject()->asTemporalTimeZoneObject()->getIdentifier()->toNonGCUTF8StringData());

    if (result.isNull()) {
        return result;
    }

    return TemporalInstantObject::createTemporalInstant(state, result);
}

static Value builtinTemporalTimeZonePrototypeGetPreviousTransition(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_TIME_ZONE(state, thisValue);
    CHECK_TEMPORAL_TIME_ZONE_OFFSET_VALUE(state, thisValue);

    auto startingPoint = TemporalInstantObject::toTemporalInstant(state, argv[0]).asObject()->asTemporalInstantObject();

    if (!thisValue.asObject()->asTemporalTimeZoneObject()->getOffsetNanoseconds().isUndefined()) {
        return Value(Value::Null);
    }

    auto result = TemporalTimeZoneObject::getIANATimeZonePreviousTransition(state, startingPoint->getNanoseconds(), thisValue.asObject()->asTemporalTimeZoneObject()->getIdentifier()->toNonGCUTF8StringData());

    if (result.isNull()) {
        return result;
    }

    return TemporalInstantObject::createTemporalInstant(state, result);
}

static Value builtinTemporalCalendarConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!newTarget.hasValue()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, ErrorObject::Messages::New_Target_Is_Undefined);
    }

    if (!argv[0].isString()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::RangeError, "First argument is not string");
    }

    String* id = argv[0].asString();

    if (!TemporalCalendarObject::isBuiltinCalendar(id)) {
        ErrorObject::throwBuiltinError(state, ErrorCode::RangeError, ErrorObject::Messages::GlobalObject_RangeError);
    }

    return TemporalCalendarObject::createTemporalCalendar(state, id, newTarget);
}

static Value builtinTemporalCalendarFrom(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    return TemporalCalendarObject::toTemporalCalendar(state, argv[0]);
}

static Value builtinTemporalCalendarPrototypeId(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isTemporalCalendarObject()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, ErrorObject::Messages::GlobalObject_ThisNotObject);
    }

    return thisValue.asObject()->asTemporalCalendarObject()->getIdentifier();
}

static Value builtinTemporalCalendarPrototypeDateFromFields(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (argc > 1 && !argv[0].isObject()) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "fields is not an object");
    }

    Object* options;

    if (argc > 1 && argv[1].isObject()) {
        options = argv[1].asObject();
    } else {
        options = new Object(state, Object::PrototypeIsNull);
    }

    auto result = TemporalCalendarObject::ISODateFromFields(state, argv[0], options);
    return TemporalPlainDateObject::createTemporalDate(state, result[TemporalObject::YEAR_UNIT], result[TemporalObject::MONTH_UNIT], result[TemporalObject::DAY_UNIT], thisValue, newTarget);
}

static Value builtinTemporalCalendarPrototypeYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value temporalDateLike = argv[0];

    if (CHECK_TEMPORAL_OBJECT_HAS_YEAR_AND_MONTH(temporalDateLike)) {
        temporalDateLike = TemporalPlainDateObject::toTemporalDate(state, temporalDateLike);
    }

    return Value(TemporalCalendarObject::ISOYear(state, temporalDateLike));
}

static Value builtinTemporalCalendarPrototypeMonth(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value temporalDateLike = argv[0];

    if (CHECK_TEMPORAL_OBJECT_HAS_YEAR_AND_MONTH(temporalDateLike)) {
        temporalDateLike = TemporalPlainDateObject::toTemporalDate(state, temporalDateLike);
    }

    return Value(TemporalCalendarObject::ISOMonth(state, temporalDateLike));
}

static Value builtinTemporalCalendarPrototypeMonthCode(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value temporalDateLike = argv[0];

    if (CHECK_TEMPORAL_OBJECT_HAS_YEAR_AND_MONTH(temporalDateLike)) {
        temporalDateLike = TemporalPlainDateObject::toTemporalDate(state, temporalDateLike);
    }

    return Value(new ASCIIString(TemporalCalendarObject::ISOMonthCode(state, temporalDateLike).c_str()));
}

static Value builtinTemporalCalendarPrototypeDay(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value temporalDateLike = argv[0];

    if (!(temporalDateLike.isObject() && (temporalDateLike.asObject()->isTemporalPlainDateObject() || temporalDateLike.asObject()->isTemporalPlainDateTimeObject()))) {
        temporalDateLike = TemporalPlainDateObject::toTemporalDate(state, temporalDateLike);
    }

    return Value(TemporalCalendarObject::ISODay(state, temporalDateLike));
}

static Value builtinTemporalCalendarPrototypeDayOfWeek(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    TemporalPlainDateObject* temporalDate = getTemporalPlainDate(state, thisValue, argc, argv);
    Value epochDays = DateObject::makeDay(state, Value(temporalDate->year()), Value(temporalDate->month() - 1), Value(temporalDate->day()));
    ASSERT(std::isfinite(epochDays.asNumber()));
    int dayOfWeek = DateObject::weekDay(DateObject::makeDate(state, epochDays, Value(0)).toUint32(state));
    return Value(dayOfWeek == 0 ? 7 : dayOfWeek);
}

static Value builtinTemporalCalendarPrototypeDayOfYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    TemporalPlainDateObject* temporalDate = getTemporalPlainDate(state, thisValue, argc, argv);
    Value epochDays = DateObject::makeDay(state, Value(temporalDate->year()), Value(temporalDate->month() - 1), Value(temporalDate->day()));
    ASSERT(std::isfinite(epochDays.asNumber()));

    return Value(TemporalCalendarObject::dayOfYear(state, epochDays));
}

static Value builtinTemporalCalendarPrototypeWeekOfYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    TemporalPlainDateObject* temporalDate = getTemporalPlainDate(state, thisValue, argc, argv);
    return Value(TemporalCalendarObject::toISOWeekOfYear(state, temporalDate->year(), temporalDate->month(), temporalDate->day()));
}

static Value builtinTemporalCalendarPrototypeDaysInWeek(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_CALENDAR(state, thisValue, argc);
    return Value(7);
}

static Value builtinTemporalCalendarPrototypeDaysInMonth(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    getTemporalPlainDate(state, thisValue, argc, argv);

    TemporalPlainDateObject* temporalDate = nullptr;

    if (!argv[0].isObject() || !(argv[0].asObject()->isTemporalPlainDateObject() || argv[0].asObject()->isTemporalPlainDateTimeObject() || argv[0].asObject()->isTemporalPlainYearMonthObject())) {
        temporalDate = TemporalPlainDateObject::toTemporalDate(state, argv[0]).asObject()->asTemporalPlainDateObject();
    } else {
        temporalDate = argv[0].asObject()->asTemporalPlainDateObject();
    }

    return TemporalCalendarObject::ISODaysInMonth(state, temporalDate->year(), temporalDate->month());
}

static Value builtinTemporalCalendarPrototypeDaysInYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_CALENDAR(state, thisValue, argc);

    TemporalPlainDateObject* temporalDate = nullptr;

    if (!argv[0].isObject() || !argv[0].asObject()->isTemporalPlainDateObject() || !argv[0].asObject()->isTemporalPlainDateTimeObject() || !argv[0].asObject()->isTemporalPlainYearMonthObject()) {
        temporalDate = TemporalPlainDateObject::toTemporalDate(state, argv[0]).asObject()->asTemporalPlainDateObject();
    } else {
        temporalDate = argv[0].asObject()->asTemporalPlainDateObject();
    }

    return Value(DateObject::daysInYear(temporalDate->year()));
}

static Value builtinTemporalCalendarPrototypeMonthsInYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_CALENDAR(state, thisValue, argc);

    if (!argv[0].isObject() || !argv[0].asObject()->isTemporalPlainDateObject() || !argv[0].asObject()->isTemporalPlainDateTimeObject() || !argv[0].asObject()->isTemporalPlainYearMonthObject()) {
        TemporalPlainDateObject::toTemporalDate(state, argv[0]);
    }

    return Value(12);
}

static Value builtinTemporalCalendarInLeapYear(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    CHECK_TEMPORAL_CALENDAR(state, thisValue, argc);
    TemporalPlainDateObject* temporalDate = nullptr;

    if (!argv[0].isObject() || !argv[0].asObject()->isTemporalPlainDateObject() || !argv[0].asObject()->isTemporalPlainDateTimeObject() || !argv[0].asObject()->isTemporalPlainYearMonthObject()) {
        temporalDate = TemporalPlainDateObject::toTemporalDate(state, argv[0]).asObject()->asTemporalPlainDateObject();
    } else {
        temporalDate = argv[0].asObject()->asTemporalPlainDateObject();
    }

    return Value(TemporalCalendarObject::isIsoLeapYear(state, temporalDate->year()));
}

static Value builtinTemporalCalendarFields(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    IteratorRecord* iteratorRecord = IteratorObject::getIterator(state, argv[0]);
    ValueVector fieldNames;
    Optional<Object*> next;

    while (true) {
        next = IteratorObject::iteratorStep(state, iteratorRecord);

        if (!next.hasValue()) {
            break;
        }

        Value nextValue = IteratorObject::iteratorValue(state, next->asObject());

        if (!nextValue.isString()) {
            Value throwCompletion = ErrorObject::createError(state, ErrorCode::TypeError, new ASCIIString("Value is not a string"));
            return IteratorObject::iteratorClose(state, iteratorRecord, throwCompletion, true);
        }

        for (unsigned int i = 0; i < fieldNames.size(); ++i) {
            if (fieldNames[i].equalsTo(state, nextValue)) {
                Value throwCompletion = ErrorObject::createError(state, ErrorCode::RangeError, new ASCIIString("Duplicated keys"));
                return IteratorObject::iteratorClose(state, iteratorRecord, throwCompletion, true);
            }
        }

        if (!(nextValue.asString()->equals("year")
              || nextValue.asString()->equals("month")
              || nextValue.asString()->equals("monthCode")
              || nextValue.asString()->equals("day")
              || nextValue.asString()->equals("hour")
              || nextValue.asString()->equals("minute")
              || nextValue.asString()->equals("second")
              || nextValue.asString()->equals("millisecond")
              || nextValue.asString()->equals("microsecond")
              || nextValue.asString()->equals("nanosecond"))) {
            Value throwCompletion = ErrorObject::createError(state, ErrorCode::RangeError, new ASCIIString("Invalid key"));
            return IteratorObject::iteratorClose(state, iteratorRecord, throwCompletion, true);
        }
        fieldNames.pushBack(nextValue);
    }
    return Object::createArrayFromList(state, fieldNames);
}

static Value builtinTemporalCalendarPrototypeMergeFields(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (argc < 2) {
        ErrorObject::throwBuiltinError(state, ErrorCode::TypeError, "Too few arguments");
    }

    Value fields = argv[0];
    Value additionalFields = argv[1];
    return TemporalCalendarObject::defaultMergeFields(state, fields, additionalFields);
}

static Value builtinTemporalCalendarToString(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    return Value(thisValue.asObject()->asTemporalCalendarObject()->getIdentifier());
}

static Value builtinTemporalCalendarToJSON(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    return Value(thisValue.asObject()->asTemporalCalendarObject()->getIdentifier());
}

void GlobalObject::initializeTemporal(ExecutionState& state)
{
    ObjectPropertyNativeGetterSetterData* nativeData = new ObjectPropertyNativeGetterSetterData(
        true, false, true,
        [](ExecutionState& state, Object* self, const Value& receiver, const EncodedValue& privateDataFromObjectPrivateArea) -> Value {
            ASSERT(self->isGlobalObject());
            return self->asGlobalObject()->temporal();
        },
        nullptr);

    defineNativeDataAccessorProperty(state, ObjectPropertyName(state.context()->staticStrings().lazyTemporal()), nativeData, Value(Value::EmptyValue));
}

void GlobalObject::installTemporal(ExecutionState& state)
{
    StaticStrings* strings = &state.context()->staticStrings();

    auto temporalNow = new Object(state);
    temporalNow->setGlobalIntrinsicObject(state);

    auto temporalPlainDate = new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDate(), builtinTemporalPlainDateConstructor, 4), NativeFunctionObject::__ForBuiltinConstructor__);
    temporalPlainDate->setGlobalIntrinsicObject(state);

    m_temporalPlainDatePrototype = new PrototypeObject(state);
    m_temporalPlainDatePrototype->setGlobalIntrinsicObject(state, true);

    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->constructor), ObjectPropertyDescriptor(temporalPlainDate, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    JSGetterSetter dateCalendarGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->calendar, builtinTemporalPlainDateCalendar, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateCalendarDesc(dateCalendarGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->calendar), dateCalendarDesc);

    JSGetterSetter dateYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyYear(), builtinTemporalPlainDateYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateYearDesc(dateYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyYear()), dateYearDesc);

    JSGetterSetter dateMonthGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonth(), builtinTemporalPlainDateMonth, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateMonthDesc(dateMonthGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonth()), dateMonthDesc);

    JSGetterSetter dateMonthCodeGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonthCode(), builtinTemporalPlainDateMonthCode, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateMonthCodeDesc(dateMonthCodeGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonthCode()), dateMonthCodeDesc);

    JSGetterSetter dateDayGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDay(), builtinTemporalPlainDateDay, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateDayDesc(dateDayGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDay()), dateDayDesc);

    JSGetterSetter dateDayOfWeekGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDayOfWeek(), builtinTemporalPlainDateDayOfWeek, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateDayOfWeekDesc(dateDayOfWeekGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDayOfWeek()), dateDayOfWeekDesc);

    JSGetterSetter dateDayOfYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDayOfYear(), builtinTemporalPlainDateDayOfYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateDayOfYearDesc(dateDayOfYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDayOfYear()), dateDayOfYearDesc);

    JSGetterSetter dateWeekOfYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyWeekOfYear(), builtinTemporalPlainDateWeekOfYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateWeekOfYearDesc(dateWeekOfYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyWeekOfYear()), dateWeekOfYearDesc);

    JSGetterSetter dateDaysInWeekGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInWeek(), builtinTemporalPlainDateDaysInWeek, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateDaysInWeekDesc(dateDaysInWeekGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInWeek()), dateDaysInWeekDesc);

    JSGetterSetter dateDaysInMonthGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInMonth(), builtinTemporalPlainDateDaysInMonth, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateDaysInMonthDesc(dateDaysInMonthGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInMonth()), dateDaysInMonthDesc);

    JSGetterSetter dateDaysInYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInYear(), builtinTemporalPlainDateDaysInYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateDaysInYearDesc(dateDaysInYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInYear()), dateDaysInYearDesc);

    JSGetterSetter dateMonthsInYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonthsInYear(), builtinTemporalPlainDateMonthsInYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateMonthsInYearDesc(dateMonthsInYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonthsInYear()), dateMonthsInYearDesc);

    JSGetterSetter dateInLeapYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyInLeapYear(), builtinTemporalPlainDateInLeapYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateInLeapYearDesc(dateInLeapYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyInLeapYear()), dateInLeapYearDesc);

    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->add),
                                                          ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->add, builtinTemporalPlainDatePrototypeAdd, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalPlainDatePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazySubtract()),
                                                          ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazySubtract(), builtinTemporalPlainDatePrototypeSubtract, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalPlainDate->setFunctionPrototype(state, m_temporalPlainDatePrototype);

    temporalPlainDate->directDefineOwnProperty(state, ObjectPropertyName(strings->from),
                                               ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->from, builtinTemporalPlainDateFrom, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    auto temporalPlainTime = new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyTime(), builtinTemporalPlainTimeConstructor, 0), NativeFunctionObject::__ForBuiltinConstructor__);
    temporalPlainTime->setGlobalIntrinsicObject(state);

    m_temporalPlainTimePrototype = new PrototypeObject(state);
    m_temporalPlainTimePrototype->setGlobalIntrinsicObject(state, true);

    m_temporalPlainTimePrototype->defineOwnProperty(state, ObjectPropertyName(strings->constructor), ObjectPropertyDescriptor(temporalPlainTime, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalPlainTime->directDefineOwnProperty(state, ObjectPropertyName(strings->from),
                                               ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->from, builtinTemporalPlainTimeFrom, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalPlainTime->directDefineOwnProperty(state, ObjectPropertyName(strings->compare),
                                               ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->compare, builtinTemporalPlainTimeCompare, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    JSGetterSetter timeCalendarGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->calendar, builtinTemporalPlainTimeCalendar, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor timeCalendarDesc(timeCalendarGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->calendar), timeCalendarDesc);

    JSGetterSetter timeHourGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyHour(), builtinTemporalPlainTimeHour, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor timeHourDesc(timeHourGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyHour()), timeHourDesc);

    JSGetterSetter timeMinuteGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMinute(), builtinTemporalPlainTimeMinute, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor timeMinuteDesc(timeMinuteGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMinute()), timeMinuteDesc);

    JSGetterSetter timeSecondGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazySecond(), builtinTemporalPlainTimeSecond, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor timeSecondDesc(timeSecondGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazySecond()), timeSecondDesc);

    JSGetterSetter timeMilliSecondGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMillisecond(), builtinTemporalPlainTimeMilliSecond, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor timeMilliSecondDesc(timeMilliSecondGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMillisecond()), timeMilliSecondDesc);

    JSGetterSetter timeMicroSecondGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMicrosecond(), builtinTemporalPlainTimeMicroSecond, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor timeMicroSecondDesc(timeMicroSecondGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMicrosecond()), timeMicroSecondDesc);

    JSGetterSetter timeNanoSecondGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyNanosecond(), builtinTemporalPlainTimeNanoSecond, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor timeNanoSecondDesc(timeNanoSecondGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyNanosecond()), timeNanoSecondDesc);

    m_temporalPlainTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->add),
                                                          ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->add, builtinTemporalPlainTimePrototypeAdd, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalPlainTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazySubtract()),
                                                          ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazySubtract(), builtinTemporalPlainTimePrototypeSubtract, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalPlainTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->with),
                                                          ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->with, builtinTemporalPlainTimeWith, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalPlainTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyEquals()),
                                                          ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyEquals(), builtinTemporalPlainTimeEquals, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalPlainTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyGetISOFields()),
                                                          ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyGetISOFields(), builtinTemporalPlainTimeGetISOFields, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalPlainTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyToPlainDateTime()),
                                                          ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyToPlainDateTime(), builtinTemporalPlainTimeToPlainDateTime, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));


    temporalPlainTime->setFunctionPrototype(state, m_temporalPlainTimePrototype);

    auto temporalPlainDateTime = new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDateTime(), builtinTemporalPlainDateTimeConstructor, 3), NativeFunctionObject::__ForBuiltinConstructor__);
    temporalPlainDateTime->setGlobalIntrinsicObject(state);

    m_temporalPlainDateTimePrototype = new PrototypeObject(state);
    m_temporalPlainDateTimePrototype->setGlobalIntrinsicObject(state, true);

    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->constructor), ObjectPropertyDescriptor(temporalPlainDateTime, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    JSGetterSetter dateTimeCalendarGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->calendar, builtinTemporalPlainDateTimeCalendar, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateTimeCalendarDesc(dateTimeCalendarGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->calendar), dateTimeCalendarDesc);

    JSGetterSetter dateTimeYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyYear(), builtinTemporalPlainDateTimeYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateTimeYearDesc(dateTimeYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyYear()), dateTimeYearDesc);

    JSGetterSetter dateTimeMonthGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonth(), builtinTemporalPlainDateTimeMonth, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateTimeMonthDesc(dateTimeMonthGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonth()), dateTimeMonthDesc);

    JSGetterSetter dateTimeMonthCodeGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonthCode(), builtinTemporalPlainDateTimeMonthCode, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateTimeMonthCodeDesc(dateTimeMonthCodeGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonthCode()), dateTimeMonthCodeDesc);

    JSGetterSetter dateTimeDayGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDay(), builtinTemporalPlainDateTimeDay, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateTimeDayDesc(dateTimeDayGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDay()), dateTimeDayDesc);

    JSGetterSetter dateTimeDayOfWeekGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDayOfWeek(), builtinTemporalPlainDateTimeDayOfWeek, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateTimeDayOfWeekDesc(dateTimeDayOfWeekGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDayOfWeek()), dateTimeDayOfWeekDesc);

    JSGetterSetter dateTimeDayOfYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDayOfYear(), builtinTemporalPlainDateTimeDayOfYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateTimeDayOfYearDesc(dateTimeDayOfYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDayOfYear()), dateTimeDayOfYearDesc);

    JSGetterSetter dateTimeWeekOfYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyWeekOfYear(), builtinTemporalPlainDateTimeWeekOfYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateTimeWeekOfYearDesc(dateTimeWeekOfYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyWeekOfYear()), dateTimeWeekOfYearDesc);

    JSGetterSetter dateTimeDaysInWeekGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInWeek(), builtinTemporalPlainDateTimeDaysInWeek, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateTimeDaysInWeekDesc(dateTimeDaysInWeekGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInWeek()), dateTimeDaysInWeekDesc);

    JSGetterSetter dateTimeDaysInMonthGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInMonth(), builtinTemporalPlainDateTimeDaysInMonth, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateTimeDaysInMonthDesc(dateTimeDaysInMonthGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInMonth()), dateTimeDaysInMonthDesc);

    JSGetterSetter dateTimeDaysInYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInYear(), builtinTemporalPlainDateTimeDaysInYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateTimeDaysInYearDesc(dateTimeDaysInYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInYear()), dateTimeDaysInYearDesc);

    JSGetterSetter dateTimeMonthsInYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonthsInYear(), builtinTemporalPlainDateTimeMonthsInYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateTimeMonthsInYearDesc(dateTimeMonthsInYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonthsInYear()), dateTimeMonthsInYearDesc);

    JSGetterSetter dateTimeInLeapYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyInLeapYear(), builtinTemporalPlainDateTimeInLeapYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor dateTimeInLeapYearDesc(dateTimeInLeapYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyInLeapYear()), dateTimeInLeapYearDesc);

    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->add),
                                                              ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->add, builtinTemporalPlainDateTimePrototypeAdd, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalPlainDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazySubtract()),
                                                              ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazySubtract(), builtinTemporalPlainDateTimePrototypeSubtract, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalPlainDateTime->setFunctionPrototype(state, m_temporalPlainDateTimePrototype);

    temporalPlainDateTime->directDefineOwnProperty(state, ObjectPropertyName(strings->from),
                                                   ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->from, builtinTemporalPlainDateTimeFrom, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    auto temporalZonedDateTime = new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDateTime(), builtinTemporalZonedDateTimeConstructor, 3), NativeFunctionObject::__ForBuiltinConstructor__);
    temporalZonedDateTime->setGlobalIntrinsicObject(state);

    m_temporalZonedDateTimePrototype = new PrototypeObject(state);
    m_temporalZonedDateTimePrototype->setGlobalIntrinsicObject(state, true);

    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->constructor), ObjectPropertyDescriptor(temporalZonedDateTime, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    JSGetterSetter zonedDateTimeCalendarGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->calendar, builtinTemporalZonedDateTimeCalendar, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeCalendarDesc(zonedDateTimeCalendarGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->calendar), zonedDateTimeCalendarDesc);

    JSGetterSetter zonedDateTimeTimeZoneGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyTimeZone(), builtinTemporalZonedDateTimeTimeZone, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeTimeZoneDesc(zonedDateTimeTimeZoneGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyTimeZone()), zonedDateTimeTimeZoneDesc);

    JSGetterSetter zonedDateTimeYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyYear(), builtinTemporalZonedDateTimeYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeYearDesc(zonedDateTimeYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyYear()), zonedDateTimeYearDesc);

    JSGetterSetter zonedDateTimeMonthGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonth(), builtinTemporalZonedDateTimeMonth, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeMonthDesc(zonedDateTimeMonthGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonth()), zonedDateTimeMonthDesc);

    JSGetterSetter zonedDateTimeMonthCodeGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonthCode(), builtinTemporalZonedDateTimeMonthCode, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeMonthCodeDesc(zonedDateTimeMonthCodeGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonthCode()), zonedDateTimeMonthCodeDesc);

    JSGetterSetter zonedDateTimeDayGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDay(), builtinTemporalZonedDateTimeDay, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeDayDesc(zonedDateTimeDayGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDay()), zonedDateTimeDayDesc);

    JSGetterSetter zonedDateTimeHourGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyHour(), builtinTemporalZonedDateTimeHour, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeHourDesc(zonedDateTimeHourGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyHour()), zonedDateTimeHourDesc);

    JSGetterSetter zonedDateTimeMinuteGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMinute(), builtinTemporalZonedDateTimeMinute, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeMinuteDesc(zonedDateTimeMinuteGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMinute()), zonedDateTimeMinuteDesc);

    JSGetterSetter zonedDateTimeSecondGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazySecond(), builtinTemporalZonedDateTimeSecond, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeSecondDesc(zonedDateTimeSecondGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazySecond()), zonedDateTimeSecondDesc);

    JSGetterSetter zonedDateTimeMillisecondGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMillisecond(), builtinTemporalZonedDateTimeMillisecond, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeMillisecondDesc(zonedDateTimeMillisecondGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMillisecond()), zonedDateTimeMillisecondDesc);

    JSGetterSetter zonedDateTimeMicrosecondGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMicrosecond(), builtinTemporalZonedDateTimeMicrosecond, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeMicrosecondDesc(zonedDateTimeMicrosecondGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMicrosecond()), zonedDateTimeMicrosecondDesc);

    JSGetterSetter zonedDateTimeNanosecondGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyNanosecond(), builtinTemporalZonedDateTimeNanosecond, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeNanosecondDesc(zonedDateTimeNanosecondGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyNanosecond()), zonedDateTimeNanosecondDesc);

    JSGetterSetter zonedDateTimeEpochSecondGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyEpochSeconds(), builtinTemporalZonedDateTimeEpochSeconds, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeEpochSecondsDesc(zonedDateTimeEpochSecondGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyEpochSeconds()), zonedDateTimeEpochSecondsDesc);

    JSGetterSetter zonedDateTimeEpochMillisecondsGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyEpochMicroseconds(), builtinTemporalZonedDateTimeEpochMicroSeconds, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeEpochMillisecondsDesc(zonedDateTimeEpochMillisecondsGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyEpochMicroseconds()), zonedDateTimeEpochMillisecondsDesc);

    JSGetterSetter zonedDateTimeEpochMicrosecondsGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyEpochMilliseconds(), builtinTemporalZonedDateTimeEpochMilliSeconds, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeEpochMicrosecondsDesc(zonedDateTimeEpochMicrosecondsGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyEpochMilliseconds()), zonedDateTimeEpochMicrosecondsDesc);

    JSGetterSetter zonedDateTimeEpochNanosecondsGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyEpochNanoseconds(), builtinTemporalZonedDateTimeEpochNanoSeconds, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeEpochNanosecondsDesc(zonedDateTimeEpochNanosecondsGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyEpochNanoseconds()), zonedDateTimeEpochNanosecondsDesc);

    JSGetterSetter zonedDateTimeDayOfWeekGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDayOfWeek(), builtinTemporalZonedDateTimeDayOfWeek, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeDayOfWeekDesc(zonedDateTimeDayOfWeekGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDayOfWeek()), zonedDateTimeDayOfWeekDesc);

    JSGetterSetter zonedDateTimeDayOfYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDayOfYear(), builtinTemporalZonedDateTimeDayOfYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeDayOfYearDesc(zonedDateTimeDayOfYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDayOfYear()), zonedDateTimeDayOfYearDesc);

    JSGetterSetter zonedDateTimeWeekOfYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyWeekOfYear(), builtinTemporalZonedDateTimeWeekOfYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeWeekOfYearDesc(zonedDateTimeWeekOfYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyWeekOfYear()), zonedDateTimeWeekOfYearDesc);

    JSGetterSetter zonedDateTimeHoursInDayGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyHoursInDay(), builtinTemporalZonedDateTimeHoursInDay, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeHoursInDayDesc(zonedDateTimeHoursInDayGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyHoursInDay()), zonedDateTimeHoursInDayDesc);

    JSGetterSetter zonedDateTimeDaysInWeekGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInWeek(), builtinTemporalZonedDateTimeDaysInWeek, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeDaysInWeekDesc(zonedDateTimeDaysInWeekGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInWeek()), zonedDateTimeDaysInWeekDesc);

    JSGetterSetter zonedDateTimeDaysInMonthGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInMonth(), builtinTemporalZonedDateTimeDaysInMonth, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeDaysInMonthDesc(zonedDateTimeDaysInMonthGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInMonth()), zonedDateTimeDaysInMonthDesc);

    JSGetterSetter zonedDateTimeDaysInYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInYear(), builtinTemporalZonedDateTimeDaysInYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeDaysInYearDesc(zonedDateTimeDaysInYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInYear()), zonedDateTimeDaysInYearDesc);

    JSGetterSetter zonedDateTimeMonthsInYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonthsInYear(), builtinTemporalZonedDateTimeMonthsInYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeMonthsInYearDesc(zonedDateTimeMonthsInYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonthsInYear()), zonedDateTimeMonthsInYearDesc);

    JSGetterSetter zonedDateTimeInLeapYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyInLeapYear(), builtinTemporalZonedDateTimeInLeapYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeInLeapYearDesc(zonedDateTimeInLeapYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyInLeapYear()), zonedDateTimeInLeapYearDesc);

    JSGetterSetter zonedDateTimeOffsetNanosecondsGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyOffsetNanoseconds(), builtinTemporalZonedDateTimeOffsetNanoseconds, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeOffsetNanosecondsDesc(zonedDateTimeOffsetNanosecondsGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyOffsetNanoseconds()), zonedDateTimeOffsetNanosecondsDesc);

    JSGetterSetter zonedDateTimeOffsetGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyOffset(), builtinTemporalZonedDateTimeOffset, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor zonedDateTimeOffsetDesc(zonedDateTimeOffsetGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyOffset()), zonedDateTimeOffsetDesc);

    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->add),
                                                              ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->add, builtinTemporalZonedDateTimePrototypeAdd, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalZonedDateTimePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazySubtract()),
                                                              ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazySubtract(), builtinTemporalZonedDateTimePrototypeSubtract, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalZonedDateTime->setFunctionPrototype(state, m_temporalZonedDateTimePrototype);
    temporalZonedDateTime->directDefineOwnProperty(state, ObjectPropertyName(strings->from),
                                                   ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->from, builtinTemporalZonedDateTimeFrom, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalZonedDateTime->directDefineOwnProperty(state, ObjectPropertyName(strings->compare),
                                                   ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->compare, builtinTemporalZonedDateTimeCompare, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    auto temporalDuration = new NativeFunctionObject(state, NativeFunctionInfo(strings->constructor, builtinTemporalDurationConstructor, 0), NativeFunctionObject::__ForBuiltinConstructor__);
    temporalDuration->setGlobalIntrinsicObject(state);

    m_temporalDurationPrototype = new PrototypeObject(state);
    m_temporalDurationPrototype->setGlobalIntrinsicObject(state, true);

    JSGetterSetter durationYearsGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyYears(), builtinTemporalDurationPrototypeYears, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor durationYearsDesc(durationYearsGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyYears()), durationYearsDesc);

    JSGetterSetter durationMonthsGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonths(), builtinTemporalDurationPrototypeMonths, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor durationMonthsDesc(durationMonthsGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonths()), durationMonthsDesc);

    JSGetterSetter durationWeeksGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyWeeks(), builtinTemporalDurationPrototypeWeeks, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor durationWeeksDesc(durationWeeksGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyWeeks()), durationWeeksDesc);

    JSGetterSetter durationDaysGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDays(), builtinTemporalDurationPrototypeDays, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor durationDaysDesc(durationDaysGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDays()), durationDaysDesc);

    JSGetterSetter durationYHoursGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyHours(), builtinTemporalDurationPrototypeHours, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor durationHoursDesc(durationYHoursGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyHours()), durationHoursDesc);

    JSGetterSetter durationMinutesGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMinutes(), builtinTemporalDurationPrototypeMinutes, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor durationMinutesDesc(durationMinutesGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMinutes()), durationMinutesDesc);

    JSGetterSetter durationSecondsGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazySeconds(), builtinTemporalDurationPrototypeSeconds, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor durationSecondsDesc(durationSecondsGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazySeconds()), durationSecondsDesc);

    JSGetterSetter durationMilliSecondsGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMilliseconds(), builtinTemporalDurationPrototypeMilliSeconds, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor durationMilliSecondsDesc(durationMilliSecondsGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMilliseconds()), durationMilliSecondsDesc);

    JSGetterSetter durationMicroSecondsGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMicroseconds(), builtinTemporalDurationPrototypeMicroSeconds, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor durationMicroSecondsDesc(durationMicroSecondsGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMicroseconds()), durationMicroSecondsDesc);

    JSGetterSetter durationNanoSecondsGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyNanoseconds(), builtinTemporalDurationPrototypeNanoSeconds, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor durationNanoSecondsDesc(durationNanoSecondsGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyNanoseconds()), durationNanoSecondsDesc);

    JSGetterSetter durationSignGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->sign, builtinTemporalDurationPrototypeSign, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor durationSignDesc(durationSignGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->sign), durationSignDesc);

    JSGetterSetter durationBlankGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyBlank(), builtinTemporalDurationPrototypeBlank, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor durationBlankDesc(durationBlankGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyBlank()), durationBlankDesc);

    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->add),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->add, builtinTemporalDurationPrototypeAdd, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazySubtract()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazySubtract(), builtinTemporalDurationPrototypeSubtract, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->abs),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->abs, builtinTemporalDurationPrototypeAbs, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyNegated()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyNegated(), builtinTemporalDurationPrototypeNegated, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalDuration->setFunctionPrototype(state, m_temporalDurationPrototype);

    temporalDuration->directDefineOwnProperty(state, ObjectPropertyName(strings->from),
                                              ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->from, builtinTemporalDurationFrom, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    auto temporalPlainYearMonth = new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyPlainYearMonth(), builtinTemporalPlainYearMonthConstructor, 2), NativeFunctionObject::__ForBuiltinConstructor__);
    temporalPlainYearMonth->setGlobalIntrinsicObject(state);

    m_temporalPlainYearMonthPrototype = new PrototypeObject(state);
    m_temporalPlainYearMonthPrototype->setGlobalIntrinsicObject(state, true);

    temporalPlainYearMonth->directDefineOwnProperty(state, ObjectPropertyName(strings->from),
                                                    ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->from, builtinTemporalPlainYearMonthFrom, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalPlainYearMonth->directDefineOwnProperty(state, ObjectPropertyName(strings->compare),
                                                    ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->compare, builtinTemporalPlainYearMonthCompare, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    JSGetterSetter yearMonthCalendarGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->calendar, builtinTemporalPlainYearMonthCalendar, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor yearMonthCalendarDesc(yearMonthCalendarGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->calendar), yearMonthCalendarDesc);

    JSGetterSetter yearMonthYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyYear(), builtinTemporalPlainYearMonthYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor yearMonthYearDesc(yearMonthYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyYear()), yearMonthYearDesc);

    JSGetterSetter yearMonthMonthGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonth(), builtinTemporalPlainYearMonthMonth, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor yearMonthMonthDesc(yearMonthMonthGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonth()), yearMonthMonthDesc);

    JSGetterSetter yearMonthMonthCodeGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonthCode(), builtinTemporalPlainYearMonthMonthCode, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor yearMonthMonthCodeDesc(yearMonthMonthCodeGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonthCode()), yearMonthMonthCodeDesc);

    JSGetterSetter yearMonthDayGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDay(), builtinTemporalPlainYearMonthDay, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor yearMonthDayDesc(yearMonthDayGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDay()), yearMonthDayDesc);

    JSGetterSetter yearMonthDayOfWeekGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDayOfWeek(), builtinTemporalPlainYearMonthDayOfWeek, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor yearMonthDayOfWeekDesc(yearMonthDayOfWeekGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDayOfWeek()), yearMonthDayOfWeekDesc);

    JSGetterSetter yearMonthDayOfYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDayOfYear(), builtinTemporalPlainYearMonthDayOfYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor yearMonthDayOfYearDesc(yearMonthDayOfYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDayOfYear()), yearMonthDayOfYearDesc);

    JSGetterSetter yearMonthWeekOfYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyWeekOfYear(), builtinTemporalPlainYearMonthWeekOfYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor yearMonthWeekOfYearDesc(yearMonthWeekOfYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyWeekOfYear()), yearMonthWeekOfYearDesc);

    JSGetterSetter yearMonthDaysInWeekGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInWeek(), builtinTemporalPlainYearMonthDaysInWeek, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor yearMonthDaysInWeekDesc(yearMonthDaysInWeekGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInWeek()), yearMonthDaysInWeekDesc);

    JSGetterSetter yearMonthDaysInMonthGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInMonth(), builtinTemporalPlainYearMonthDaysInMonth, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor yearMonthDaysInMonthDesc(yearMonthDaysInMonthGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInMonth()), yearMonthDaysInMonthDesc);

    JSGetterSetter yearMonthDaysInYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInYear(), builtinTemporalPlainYearMonthDaysInYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor yearMonthDaysInYearDesc(yearMonthDaysInYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInYear()), yearMonthDaysInYearDesc);

    JSGetterSetter yearMonthMonthsInYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonthsInYear(), builtinTemporalPlainYearMonthMonthsInYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor yearMonthMonthsInYearDesc(yearMonthMonthsInYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonthsInYear()), yearMonthMonthsInYearDesc);

    JSGetterSetter yearMonthInLeapYearGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyInLeapYear(), builtinTemporalPlainYearMonthInLeapYear, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor yearMonthInLeapYearDesc(yearMonthInLeapYearGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyInLeapYear()), yearMonthInLeapYearDesc);

    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->constructor), ObjectPropertyDescriptor(temporalPlainYearMonth, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->add),
                                                               ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->add, builtinTemporalPlainYearMonthPrototypeAdd, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalPlainYearMonthPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazySubtract()),
                                                               ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazySubtract(), builtinTemporalPlainYearMonthPrototypeSubtract, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalDurationPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyEquals()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyEquals(), builtinTemporalPlainYearMonthPrototypeEquals, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalPlainYearMonth->setFunctionPrototype(state, m_temporalPlainYearMonthPrototype);

    auto temporalInstant = new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyInstant(), builtinTemporalInstantConstructor, 1), NativeFunctionObject::__ForBuiltinConstructor__);
    temporalInstant->setGlobalIntrinsicObject(state);

    temporalInstant->directDefineOwnProperty(state, ObjectPropertyName(strings->from),
                                             ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->from, builtinTemporalInstantFrom, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalInstant->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyFromEpochSeconds()),
                                             ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyFromEpochSeconds(), builtinTemporalInstantFromEpochSeconds, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalInstant->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyFromEpochMilliseconds()),
                                             ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyFromEpochMilliseconds(), builtinTemporalInstantFromEpochMilliSeconds, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalInstant->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyFromEpochMicroseconds()),
                                             ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyFromEpochMicroseconds(), builtinTemporalInstantFromEpochMicroSeconds, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalInstant->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyFromEpochNanoseconds()),
                                             ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyFromEpochNanoseconds(), builtinTemporalInstantFromEpochNanoSeconds, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalInstant->directDefineOwnProperty(state, ObjectPropertyName(strings->compare),
                                             ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->compare, builtinTemporalInstantCompare, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalInstantPrototype = new PrototypeObject(state);
    m_temporalInstantPrototype->setGlobalIntrinsicObject(state, true);

    m_temporalInstantPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->constructor), ObjectPropertyDescriptor(temporalInstant, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    JSGetterSetter instantSecondsGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyEpochSeconds(), builtinTemporalInstantPrototypeEpochSeconds, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor instantSecondsDesc(instantSecondsGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalInstantPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyEpochSeconds()), instantSecondsDesc);

    JSGetterSetter instantMillisecondsGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyEpochMilliseconds(), builtinTemporalInstantPrototypeEpochMilliseconds, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor instantMillisecondsDesc(instantMillisecondsGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalInstantPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyEpochMilliseconds()), instantMillisecondsDesc);

    JSGetterSetter instantMicrosecondsGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyEpochMicroseconds(), builtinTemporalInstantPrototypeEpochMicroseconds, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor instantMicrosecondsDesc(instantMicrosecondsGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalInstantPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyEpochMicroseconds()), instantMicrosecondsDesc);

    JSGetterSetter instantNanosecondsGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyEpochNanoseconds(), builtinTemporalInstantPrototypeEpochNanoseconds, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor instantNanosecondsDesc(instantNanosecondsGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalInstantPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyEpochNanoseconds()), instantNanosecondsDesc);

    m_temporalInstantPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyEquals()),
                                                        ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyEquals(), builtinTemporalInstantPrototypeEquals, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalInstantPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->add),
                                                        ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->add, builtinTemporalInstantPrototypeAdd, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalInstantPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazySubtract()),
                                                        ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazySubtract(), builtinTemporalInstantPrototypeSubtract, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalInstant->setFunctionPrototype(state, m_temporalInstantPrototype);

    auto temporalPlainMonthDay = new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyPlainMonthDay(), builtinTemporalPlainMonthDayConstructor, 2), NativeFunctionObject::__ForBuiltinConstructor__);
    temporalPlainMonthDay->setGlobalIntrinsicObject(state);

    m_temporalPlainMonthDayPrototype = new PrototypeObject(state);
    m_temporalPlainMonthDayPrototype->setGlobalIntrinsicObject(state, true);

    m_temporalPlainMonthDayPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->constructor), ObjectPropertyDescriptor(temporalPlainMonthDay, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    JSGetterSetter monthDayCalendarGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->calendar, builtinTemporalPlainMonthDayPrototypeCalendar, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor monthDayCalendarDesc(monthDayCalendarGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainMonthDayPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->calendar), monthDayCalendarDesc);

    JSGetterSetter monthDayMonthCodeGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonthCode(), builtinTemporalPlainMonthDayPrototypeMonthCode, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor monthDayMonthCodeDesc(monthDayMonthCodeGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainMonthDayPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonthCode()), monthDayMonthCodeDesc);

    JSGetterSetter monthDayDayGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDay(), builtinTemporalPlainMonthDayPrototypeDay, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor monthDayDayDesc(monthDayDayGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalPlainMonthDayPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDay()), monthDayDayDesc);

    temporalPlainMonthDay->directDefineOwnProperty(state, ObjectPropertyName(strings->from),
                                                   ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->from, builtinTemporalPlainMonthDayFrom, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    auto temporalTimeZone = new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyCalendar(), builtinTemporalTimeZoneConstructor, 1), NativeFunctionObject::__ForBuiltinConstructor__);
    temporalTimeZone->setGlobalIntrinsicObject(state);

    temporalTimeZone->directDefineOwnProperty(state, ObjectPropertyName(strings->from),
                                              ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->from, builtinTemporalTimeZoneFrom, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalTimeZonePrototype = new PrototypeObject(state);
    m_temporalTimeZonePrototype->setGlobalIntrinsicObject(state, true);

    m_temporalTimeZonePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->constructor), ObjectPropertyDescriptor(temporalTimeZone, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    JSGetterSetter timeZoneIDGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyId(), builtinTemporalTimeZonePrototypeId, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor timeZoneIDDesc(timeZoneIDGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalTimeZonePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyId()), timeZoneIDDesc);

    m_temporalTimeZonePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyGetOffsetNanosecondsFor()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyGetOffsetNanosecondsFor(), builtinTemporalTimeZonePrototypeGetOffsetNanosecondsFor, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalTimeZonePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyGetOffsetStringFor()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyGetOffsetStringFor(), builtinTemporalTimeZonePrototypeGetOffsetStringFor, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalTimeZonePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyGetPlainDateTimeFor()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyGetPlainDateTimeFor(), builtinTemporalTimeZonePrototypeGetPlainDateTimeFor, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalTimeZonePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyGetPossibleInstantsFor()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyGetPossibleInstantsFor(), builtinTemporalTimeZonePrototypeGetPossibleInstantsFor, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalTimeZonePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyGetNextTransition()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyGetNextTransition(), builtinTemporalTimeZonePrototypeGetNextTransition, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalTimeZonePrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyGetPreviousTransition()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyGetPreviousTransition(), builtinTemporalTimeZonePrototypeGetPreviousTransition, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalTimeZone->setFunctionPrototype(state, m_temporalTimeZonePrototype);

    auto temporalCalendar = new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyCalendar(), builtinTemporalCalendarConstructor, 1), NativeFunctionObject::__ForBuiltinConstructor__);
    temporalCalendar->setGlobalIntrinsicObject(state);

    m_temporalCalendarPrototype = new PrototypeObject(state);
    m_temporalCalendarPrototype->setGlobalIntrinsicObject(state, true);

    JSGetterSetter calendarIDGS(
        new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyId(), builtinTemporalCalendarPrototypeId, 0, NativeFunctionInfo::Strict)),
        Value(Value::EmptyValue));
    ObjectPropertyDescriptor calendarIDDesc(calendarIDGS, ObjectPropertyDescriptor::ConfigurablePresent);
    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyId()), calendarIDDesc);

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->constructor), ObjectPropertyDescriptor(temporalCalendar, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));


    temporalCalendar->setFunctionPrototype(state, m_temporalCalendarPrototype);

    temporalNow->directDefineOwnProperty(state, ObjectPropertyName(state.context()->vmInstance()->globalSymbols().toStringTag),
                                         ObjectPropertyDescriptor(strings->lazyTemporalDotNow().string(), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalNow->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyTimeZone()),
                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyTimeZone(), builtinTemporalNowTimeZone, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalNow->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyPlainDateISO()),
                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyPlainDateISO(), builtinTemporalNowPlainDateISO, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalNow->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyPlainTimeISO()),
                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyPlainTimeISO(), builtinTemporalNowPlainTimeISO, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalNow->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyPlainDateTimeISO()),
                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyPlainDateTimeISO(), builtinTemporalNowPlainDateTimeISO, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalPlainDate->directDefineOwnProperty(state, ObjectPropertyName(state.context()->vmInstance()->globalSymbols().toStringTag),
                                               ObjectPropertyDescriptor(strings->lazyTemporalDotPlainDate().string(), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent)));

    temporalCalendar->directDefineOwnProperty(state, ObjectPropertyName(strings->from),
                                              ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->from, builtinTemporalCalendarFrom, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDateFromFields()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDateFromFields(), builtinTemporalCalendarPrototypeDateFromFields, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyYear()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyYear(), builtinTemporalCalendarPrototypeYear, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonth()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonth(), builtinTemporalCalendarPrototypeMonth, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonthCode()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonthCode(), builtinTemporalCalendarPrototypeMonthCode, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDay()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDay(), builtinTemporalCalendarPrototypeDay, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDayOfWeek()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDayOfWeek(), builtinTemporalCalendarPrototypeDayOfWeek, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDayOfYear()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDayOfYear(), builtinTemporalCalendarPrototypeDayOfYear, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyWeekOfYear()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyWeekOfYear(), builtinTemporalCalendarPrototypeWeekOfYear, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInWeek()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInWeek(), builtinTemporalCalendarPrototypeDaysInWeek, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInMonth()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInMonth(), builtinTemporalCalendarPrototypeDaysInMonth, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDaysInYear()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyDaysInYear(), builtinTemporalCalendarPrototypeDaysInYear, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMonthsInYear()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMonthsInYear(), builtinTemporalCalendarPrototypeMonthsInYear, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyInLeapYear()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyInLeapYear(), builtinTemporalCalendarInLeapYear, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyMergeFields()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyMergeFields(), builtinTemporalCalendarPrototypeMergeFields, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyFields()),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->lazyFields(), builtinTemporalCalendarFields, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));


    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->toString),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->toString, builtinTemporalCalendarToString, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporalCalendarPrototype->directDefineOwnProperty(state, ObjectPropertyName(strings->toJSON),
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->toJSON, builtinTemporalCalendarToJSON, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporal = new TemporalObject(state);
    m_temporal->setGlobalIntrinsicObject(state);

    m_temporal->directDefineOwnProperty(state, ObjectPropertyName(state.context()->vmInstance()->globalSymbols().toStringTag),
                                        ObjectPropertyDescriptor(Value(strings->lazyTemporal().string()), (ObjectPropertyDescriptor::PresentAttribute)ObjectPropertyDescriptor::ConfigurablePresent));

    m_temporal->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyNow()),
                                        ObjectPropertyDescriptor(temporalNow, (ObjectPropertyDescriptor::PresentAttribute)ObjectPropertyDescriptor::ConfigurablePresent));

    m_temporal->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyPlainDate()),
                                        ObjectPropertyDescriptor(temporalPlainDate, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporal->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyPlainTime()),
                                        ObjectPropertyDescriptor(temporalPlainTime, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporal->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyPlainDateTime()),
                                        ObjectPropertyDescriptor(temporalPlainDateTime, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporal->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyZonedDateTime()),
                                        ObjectPropertyDescriptor(temporalZonedDateTime, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporal->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyDuration()),
                                        ObjectPropertyDescriptor(temporalDuration, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporal->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyPlainYearMonth()),
                                        ObjectPropertyDescriptor(temporalPlainYearMonth, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporal->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyInstant()),
                                        ObjectPropertyDescriptor(temporalInstant, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporal->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyPlainMonthDay()),
                                        ObjectPropertyDescriptor(temporalPlainMonthDay, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporal->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyTemporalTimeZone()),
                                        ObjectPropertyDescriptor(temporalTimeZone, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_temporal->directDefineOwnProperty(state, ObjectPropertyName(strings->lazyCalendar()),
                                        ObjectPropertyDescriptor(temporalCalendar, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    redefineOwnProperty(state, ObjectPropertyName(strings->lazyTemporal()),
                        ObjectPropertyDescriptor(m_temporal, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));
}

#else

void GlobalObject::initializeTemporal(ExecutionState& state)
{
    // dummy initialize function
}

#endif

} // namespace Escargot
