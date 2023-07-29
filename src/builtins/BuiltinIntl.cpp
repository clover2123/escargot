/*
 * Copyright (C) 2015 Andy VanWagoner (thetalecrafter@gmail.com)
 * Copyright (C) 2015 Sukolsak Sakshuwong (sukolsak@gmail.com)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright (c) 2017-present Samsung Electronics Co., Ltd
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
#include "runtime/Context.h"
#include "runtime/StringObject.h"
#include "runtime/ArrayObject.h"
#include "runtime/VMInstance.h"
#include "runtime/NativeFunctionObject.h"
#include "runtime/DateObject.h"
#include "runtime/BigInt.h"
#include "intl/Intl.h"
#include "intl/IntlCollator.h"
#include "intl/IntlNumberFormat.h"
#include "intl/IntlDateTimeFormat.h"
#include "intl/IntlPluralRules.h"
#include "intl/IntlLocale.h"
#include "intl/IntlRelativeTimeFormat.h"
#include "intl/IntlDisplayNames.h"
#include "intl/IntlListFormat.h"

namespace Escargot {

#if defined(ENABLE_ICU) && defined(ENABLE_INTL)

static Value builtinIntlCollatorConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // https://www.ecma-international.org/ecma-402/6.0/index.html#sec-intl.collator
    Value locales, options;
    if (argc >= 1) {
        locales = argv[0];
    }
    if (argc >= 2) {
        options = argv[1];
    }

    // If NewTarget is undefined, let newTarget be the active function object, else let newTarget be NewTarget.
    if (!newTarget) {
        newTarget = state.resolveCallee();
    }

    // Let internalSlotsList be « [[InitializedCollator]], [[Locale]], [[Usage]], [[Sensitivity]], [[IgnorePunctuation]], [[Collation]], [[BoundCompare]] ».
    // If %Collator%.[[RelevantExtensionKeys]] contains "kn", then
    // Append [[Numeric]] as the last element of internalSlotsList.
    // If %Collator%.[[RelevantExtensionKeys]] contains "kf", then
    // Append [[CaseFirst]] as the last element of internalSlotsList.
    // Let collator be ? OrdinaryCreateFromConstructor(newTarget, "%CollatorPrototype%", internalSlotsList).
    // Return ? InitializeCollator(collator, locales, options).
    return IntlCollator::create(state, newTarget->getFunctionRealm(state), locales, options);
}

static Value builtinIntlCollatorCompare(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    FunctionObject* callee = state.resolveCallee();
    if (!callee->hasInternalSlot() || !callee->internalSlot()->hasOwnProperty(state, ObjectPropertyName(state.context()->staticStrings().lazyInitializedCollator()))) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    Object* colllator = callee->asObject();

    String* x = argv[0].toString(state);
    String* y = argv[1].toString(state);

    return Value(IntlCollator::compare(state, colllator, x, y));
}

static Value builtinIntlCollatorCompareGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->hasInternalSlot() || !thisValue.asObject()->internalSlot()->hasOwnProperty(state, ObjectPropertyName(state.context()->staticStrings().lazyInitializedCollator()))) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    Object* internalSlot = thisValue.asObject()->internalSlot();
    FunctionObject* fn;
    auto g = internalSlot->get(state, ObjectPropertyName(state.context()->staticStrings().lazyCompareFunction()));
    if (g.hasValue()) {
        fn = g.value(state, internalSlot).asFunction();
    } else {
        fn = new NativeFunctionObject(state, NativeFunctionInfo(AtomicString(), builtinIntlCollatorCompare, 2, NativeFunctionInfo::Strict));
        internalSlot->set(state, ObjectPropertyName(state.context()->staticStrings().lazyCompareFunction()), Value(fn), internalSlot);
        fn->setInternalSlot(internalSlot);
    }

    return fn;
}

static Value builtinIntlCollatorResolvedOptions(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->hasInternalSlot() || !thisValue.asObject()->internalSlot()->hasOwnProperty(state, ObjectPropertyName(state.context()->staticStrings().lazyInitializedCollator()))) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    Object* internalSlot = thisValue.asObject()->internalSlot();
    auto r = IntlCollator::resolvedOptions(state, internalSlot);
    Object* result = new Object(state);
    result->defineOwnProperty(state, ObjectPropertyName(state.context()->staticStrings().lazySmallLetterLocale()), ObjectPropertyDescriptor(r.locale, ObjectPropertyDescriptor::AllPresent));
    result->defineOwnProperty(state, ObjectPropertyName(state.context()->staticStrings().lazyUsage()), ObjectPropertyDescriptor(r.usage, ObjectPropertyDescriptor::AllPresent));
    result->defineOwnProperty(state, ObjectPropertyName(state.context()->staticStrings().lazySensitivity()), ObjectPropertyDescriptor(r.sensitivity, ObjectPropertyDescriptor::AllPresent));
    result->defineOwnProperty(state, ObjectPropertyName(state.context()->staticStrings().lazyIgnorePunctuation()), ObjectPropertyDescriptor(Value(r.ignorePunctuation), ObjectPropertyDescriptor::AllPresent));
    result->defineOwnProperty(state, ObjectPropertyName(state.context()->staticStrings().collation), ObjectPropertyDescriptor(r.collation, ObjectPropertyDescriptor::AllPresent));
    result->defineOwnProperty(state, ObjectPropertyName(state.context()->staticStrings().numeric), ObjectPropertyDescriptor(Value(r.numeric), ObjectPropertyDescriptor::AllPresent));
    result->defineOwnProperty(state, ObjectPropertyName(state.context()->staticStrings().caseFirst), ObjectPropertyDescriptor(Value(r.caseFirst), ObjectPropertyDescriptor::AllPresent));
    return result;
}

static Value builtinIntlCollatorSupportedLocalesOf(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // If options is not provided, then let options be undefined.
    Value locales = argv[0];
    Value options;
    if (argc >= 2) {
        options = argv[1];
    }
    // Let availableLocales be the value of the [[availableLocales]] internal property of the standard built-in object that is the initial value of Intl.Collator.
    const auto& availableLocales = state.context()->vmInstance()->intlCollatorAvailableLocales();
    // Let requestedLocales be the result of calling the CanonicalizeLocaleList abstract operation (defined in 9.2.1) with argument locales.
    ValueVector requestedLocales = Intl::canonicalizeLocaleList(state, locales);
    // Return the result of calling the SupportedLocales abstract operation (defined in 9.2.8) with arguments availableLocales, requestedLocales, and options.
    return Intl::supportedLocales(state, availableLocales, requestedLocales, options);
}


static Value builtinIntlDateTimeFormatConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value locales, options;
    if (argc >= 1) {
        locales = argv[0];
    }
    if (argc >= 2) {
        options = argv[1];
    }

    // If NewTarget is undefined, let newTarget be the active function object, else let newTarget be NewTarget.
    Object* newTargetVariable;
    if (!newTarget.hasValue()) {
        newTargetVariable = state.resolveCallee();
    } else {
        newTargetVariable = newTarget.value();
    }

    // Let dateTimeFormat be ? OrdinaryCreateFromConstructor(newTarget, "%DateTimeFormatPrototype%", « [[InitializedDateTimeFormat]], [[Locale]], [[Calendar]], [[NumberingSystem]], [[TimeZone]], [[Weekday]], [[Era]], [[Year]], [[Month]], [[Day]], [[Hour]], [[Minute]], [[Second]], [[TimeZoneName]], [[HourCycle]], [[Pattern]], [[BoundFormat]] »).
    Object* proto = Object::getPrototypeFromConstructor(state, newTargetVariable, [](ExecutionState& state, Context* realm) -> Object* {
        return realm->globalObject()->intlDateTimeFormatPrototype();
    });
    Object* dateTimeFormat = new IntlDateTimeFormatObject(state, proto, locales, options);
    return dateTimeFormat;
}

static Value builtinIntlDateTimeFormatFormat(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    FunctionObject* callee = state.resolveCallee();
    if (!callee->internalSlot() || !callee->internalSlot()->isIntlDateTimeFormatObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    IntlDateTimeFormatObject* dateTimeFormat = callee->internalSlot()->asIntlDateTimeFormatObject();
    double value;
    if (argc == 0 || argv[0].isUndefined()) {
        value = DateObject::currentTime();
    } else {
        value = argv[0].toNumber(state);
    }
    auto result = dateTimeFormat->format(state, value);

    return Value(new UTF16String(result.data(), result.length()));
}

static Value builtinIntlDateTimeFormatFormatGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlDateTimeFormatObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    IntlDateTimeFormatObject* dtf = thisValue.asObject()->asIntlDateTimeFormatObject();

    if (!dtf->internalSlot()) {
        FunctionObject* formatFunction = new NativeFunctionObject(state, NativeFunctionInfo(AtomicString(), builtinIntlDateTimeFormatFormat, 1, NativeFunctionInfo::Strict));
        formatFunction->setInternalSlot(dtf);
        dtf->setInternalSlot(formatFunction);
    }

    return dtf->internalSlot();
}

static Value builtinIntlDateTimeFormatFormatToParts(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // Let dtf be this value.
    // If Type(dtf) is not Object, throw a TypeError exception.
    // If dtf does not have an [[InitializedDateTimeFormat]] internal slot, throw a TypeError exception.
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlDateTimeFormatObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }
    IntlDateTimeFormatObject* dtf = thisValue.asObject()->asIntlDateTimeFormatObject();
    Value date = argv[0];
    double x;
    // If date is undefined, then
    if (date.isUndefined()) {
        // Let x be Call(%Date_now%, undefined).
        x = DateObject::currentTime();
    } else {
        // Else,
        // Let x be ? ToNumber(date).
        x = date.toNumber(state);
    }
    // Return ? FormatDateTimeToParts(dtf, x).
    return dtf->formatToParts(state, x);
}

static void setFormatOpt(ExecutionState& state, Object* internalSlot, Object* result, String* prop)
{
    ObjectGetResult r;
    r = internalSlot->get(state, ObjectPropertyName(state, prop));

    if (r.hasValue()) {
        result->defineOwnProperty(state, ObjectPropertyName(state, prop), ObjectPropertyDescriptor(Value(r.value(state, internalSlot)), ObjectPropertyDescriptor::AllPresent));
    }
}

static Value builtinIntlDateTimeFormatResolvedOptions(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlDateTimeFormatObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }
    IntlDateTimeFormatObject* intlDateTimeFormatObject = thisValue.asObject()->asIntlDateTimeFormatObject();
    Object* result = new Object(state);

#define SET_RESULT(name)                                                                                                                                                         \
    {                                                                                                                                                                            \
        Value v(intlDateTimeFormatObject->name());                                                                                                                               \
        if (!v.isUndefined()) {                                                                                                                                                  \
            const char s[] = #name;                                                                                                                                              \
            result->defineOwnProperty(state, ObjectPropertyName(state, String::fromASCII(s, sizeof(s) - 1)), ObjectPropertyDescriptor(v, ObjectPropertyDescriptor::AllPresent)); \
        }                                                                                                                                                                        \
    }

    SET_RESULT(locale);
    SET_RESULT(calendar);
    SET_RESULT(numberingSystem);
    SET_RESULT(timeZone);
    SET_RESULT(hourCycle);
    SET_RESULT(hour12);
    SET_RESULT(weekday);
    SET_RESULT(era);
    SET_RESULT(year);
    SET_RESULT(month);
    SET_RESULT(day);
    SET_RESULT(dayPeriod);
    SET_RESULT(hour);
    SET_RESULT(minute);
    SET_RESULT(second);
    SET_RESULT(fractionalSecondDigits);
    SET_RESULT(timeZoneName);
    SET_RESULT(dateStyle);
    SET_RESULT(timeStyle);
#undef SET_RESULT

    return Value(result);
}

static Value builtinIntlDateTimeFormatSupportedLocalesOf(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // If options is not provided, then let options be undefined.
    Value locales = argv[0];
    Value options;
    if (argc >= 2) {
        options = argv[1];
    }
    // Let availableLocales be the value of the [[availableLocales]] internal property of the standard built-in object that is the initial value of Intl.DateTimeFormat.
    const auto& availableLocales = state.context()->vmInstance()->intlDateTimeFormatAvailableLocales();
    // Let requestedLocales be the result of calling the CanonicalizeLocaleList abstract operation (defined in 9.2.1) with argument locales.
    ValueVector requestedLocales = Intl::canonicalizeLocaleList(state, locales);
    // Return the result of calling the SupportedLocales abstract operation (defined in 9.2.8) with arguments availableLocales, requestedLocales, and options.
    return Intl::supportedLocales(state, availableLocales, requestedLocales, options);
}

#if defined(ENABLE_INTL_NUMBERFORMAT)
static Value builtinIntlNumberFormatFormat(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    FunctionObject* callee = state.resolveCallee();
    if (!callee->hasInternalSlot() || !callee->internalSlot()->hasOwnProperty(state, ObjectPropertyName(state.context()->staticStrings().lazyInitializedNumberFormat()))) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    Object* numberFormat = callee->asObject();

    UTF16StringDataNonGCStd result;
    auto numeric = argv[0].toNumeric(state);
    if (numeric.second) {
        result = IntlNumberFormat::format(state, numberFormat, numeric.first.asBigInt()->toString());
    } else {
        result = IntlNumberFormat::format(state, numberFormat, numeric.first.asNumber());
    }

    return new UTF16String(result.data(), result.length());
}

static Value builtinIntlNumberFormatFormatGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->hasInternalSlot() || !thisValue.asObject()->internalSlot()->hasOwnProperty(state, ObjectPropertyName(state.context()->staticStrings().lazyInitializedNumberFormat()))) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    Object* internalSlot = thisValue.asObject()->internalSlot();
    FunctionObject* fn;
    auto g = internalSlot->get(state, ObjectPropertyName(state.context()->staticStrings().format));
    if (g.hasValue()) {
        fn = g.value(state, internalSlot).asFunction();
    } else {
        fn = new NativeFunctionObject(state, NativeFunctionInfo(AtomicString(), builtinIntlNumberFormatFormat, 1, NativeFunctionInfo::Strict));
        internalSlot->set(state, ObjectPropertyName(state.context()->staticStrings().format), Value(fn), internalSlot);
        fn->setInternalSlot(internalSlot);
    }

    return fn;
}

static Value builtinIntlNumberFormatConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value locales, options;
    if (argc >= 1) {
        locales = argv[0];
    }
    if (argc >= 2) {
        options = argv[1];
    }

    // If NewTarget is undefined, let newTarget be the active function object, else let newTarget be NewTarget.
    Object* newTargetVariable;
    if (!newTarget.hasValue()) {
        newTargetVariable = state.resolveCallee();
    } else {
        newTargetVariable = newTarget.value();
    }

    // Let numberFormat be ? OrdinaryCreateFromConstructor(newTarget, "%NumberFormatPrototype%", « [[InitializedNumberFormat]], [[Locale]], [[DataLocale]], [[NumberingSystem]], [[Style]], [[Unit]], [[UnitDisplay]], [[Currency]], [[CurrencyDisplay]], [[CurrencySign]], [[MinimumIntegerDigits]], [[MinimumFractionDigits]], [[MaximumFractionDigits]], [[MinimumSignificantDigits]], [[MaximumSignificantDigits]], [[RoundingType]], [[Notation]], [[CompactDisplay]], [[UseGrouping]], [[SignDisplay]], [[BoundFormat]] »).
    Object* proto = Object::getPrototypeFromConstructor(state, newTargetVariable, [](ExecutionState& state, Context* realm) -> Object* {
        return realm->globalObject()->intlNumberFormatPrototype();
    });
    Object* numberFormat = new Object(state, proto);
    IntlNumberFormat::initialize(state, numberFormat, locales, options);
    return numberFormat;
}

static Value builtinIntlNumberFormatResolvedOptions(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->hasInternalSlot() || !thisValue.asObject()->internalSlot()->hasOwnProperty(state, state.context()->staticStrings().lazyInitializedNumberFormat())) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    Object* internalSlot = thisValue.asObject()->internalSlot();
    Object* result = new Object(state);

    setFormatOpt(state, internalSlot, result, String::fromASCII("locale"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("numberingSystem"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("style"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("currency"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("currencyDisplay"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("currencySign"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("unit"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("unitDisplay"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("minimumIntegerDigits"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("minimumFractionDigits"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("maximumFractionDigits"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("minimumSignificantDigits"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("maximumSignificantDigits"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("useGrouping"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("notation"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("compactDisplay"));
    setFormatOpt(state, internalSlot, result, String::fromASCII("signDisplay"));
    return result;
}

static Value builtinIntlNumberFormatFormatToParts(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // Let nf be the this value.
    // If Type(nf) is not Object, throw a TypeError exception.
    // If nf does not have an [[InitializedNumberFormat]] internal slot, throw a TypeError exception.
    if (!thisValue.isObject() || !thisValue.asObject()->hasInternalSlot() || !thisValue.asObject()->internalSlot()->hasOwnProperty(state, state.context()->staticStrings().lazyInitializedNumberFormat())) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }
    // Let x be ? ToNumeric(value).
    double x = argv[0].toNumber(state);
    // Return ? FormatNumericToParts(nf, x).
    return IntlNumberFormat::formatToParts(state, thisValue.asObject(), x);
}

static Value builtinIntlNumberFormatSupportedLocalesOf(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // If options is not provided, then let options be undefined.
    Value locales = argv[0];
    Value options;
    if (argc >= 2) {
        options = argv[1];
    }
    // Let availableLocales be the value of the [[availableLocales]] internal property of the standard built-in object that is the initial value of Intl.NumberFormat.
    const auto& availableLocales = state.context()->vmInstance()->intlNumberFormatAvailableLocales();
    // Let requestedLocales be the result of calling the CanonicalizeLocaleList abstract operation (defined in 9.2.1) with argument locales.
    ValueVector requestedLocales = Intl::canonicalizeLocaleList(state, locales);
    // Return the result of calling the SupportedLocales abstract operation (defined in 9.2.8) with arguments availableLocales, requestedLocales, and options.
    return Intl::supportedLocales(state, availableLocales, requestedLocales, options);
}
#endif

#if defined(ENABLE_INTL_PLURALRULES)
static Value builtinIntlPluralRulesConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // If NewTarget is undefined, throw a TypeError exception.
    if (!newTarget) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, ErrorObject::Messages::GlobalObject_ConstructorRequiresNew);
    }

#if defined(ENABLE_RUNTIME_ICU_BINDER)
    UVersionInfo versionArray;
    u_getVersion(versionArray);
    if (versionArray[0] < 60) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Intl.PluralRules needs 60+ version of ICU");
    }
#endif

    Value locales = argc >= 1 ? argv[0] : Value();
    Value options = argc >= 2 ? argv[1] : Value();

    Object* proto = Object::getPrototypeFromConstructor(state, newTarget.value(), [](ExecutionState& state, Context* constructorRealm) -> Object* {
        return constructorRealm->globalObject()->intlPluralRulesPrototype();
    });

    return new IntlPluralRulesObject(state, proto, locales, options);
}

static Value builtinIntlPluralRulesSelect(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // https://www.ecma-international.org/ecma-402/6.0/index.html#sec-intl.pluralrules.prototype.select
    // Let pr be the this value.
    // If Type(pr) is not Object, throw a TypeError exception.
    // If pr does not have an [[InitializedPluralRules]] internal slot, throw a TypeError exception.
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlPluralRulesObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }
    // Let n be ? ToNumber(value).
    double n = argv[0].toNumber(state);
    // Return ? ResolvePlural(pr, n).
    return thisValue.asObject()->asIntlPluralRulesObject()->asIntlPluralRulesObject()->resolvePlural(n);
}

static Value builtinIntlPluralRulesResolvedOptions(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // Let pr be the this value.
    // If Type(pr) is not Object, throw a TypeError exception.
    // If pr does not have an [[InitializedPluralRules]] internal slot, throw a TypeError exception.
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlPluralRulesObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    IntlPluralRulesObject* pr = thisValue.asObject()->asIntlPluralRulesObject();

    // Let options be ! ObjectCreate(%ObjectPrototype%).
    Object* options = new Object(state);
    // For each row of Table 8, except the header row, in table order, do
    // Let p be the Property value of the current row.
    // Let v be the value of pr's internal slot whose name is the Internal Slot value of the current row.
    // If v is not undefined, then
    // Perform ! CreateDataPropertyOrThrow(options, p, v).


    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazySmallLetterLocale()), ObjectPropertyDescriptor(pr->locale(), ObjectPropertyDescriptor::AllPresent));
    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazyType()), ObjectPropertyDescriptor(pr->type(), ObjectPropertyDescriptor::AllPresent));
    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazyMinimumIntegerDigits()), ObjectPropertyDescriptor(Value(Value::DoubleToIntConvertibleTestNeeds, pr->minimumIntegerDigits()), ObjectPropertyDescriptor::AllPresent));

    if (pr->minimumSignificantDigits()) {
        options->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazyMinimumSignificantDigits()), ObjectPropertyDescriptor(Value(Value::DoubleToIntConvertibleTestNeeds, pr->minimumSignificantDigits().value()), ObjectPropertyDescriptor::AllPresent));
        options->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazyMaximumSignificantDigits()), ObjectPropertyDescriptor(Value(Value::DoubleToIntConvertibleTestNeeds, pr->maximumSignificantDigits().value()), ObjectPropertyDescriptor::AllPresent));
    } else {
        options->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazyMinimumFractionDigits()), ObjectPropertyDescriptor(Value(Value::DoubleToIntConvertibleTestNeeds, pr->minimumFractionDigits()), ObjectPropertyDescriptor::AllPresent));
        options->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazyMaximumFractionDigits()), ObjectPropertyDescriptor(Value(Value::DoubleToIntConvertibleTestNeeds, pr->maximumFractionDigits()), ObjectPropertyDescriptor::AllPresent));
    }


    // Let pluralCategories be a List of Strings representing the possible results of PluralRuleSelect for the selected locale pr.[[Locale]]. This List consists of unique string values, from the the list "zero", "one", "two", "few", "many" and "other", that are relevant for the locale whose localization is specified in LDML Language Plural Rules.
    // Perform ! CreateDataProperty(options, "pluralCategories", CreateArrayFromList(pluralCategories)).
    ArrayObject* pluralCategories = new ArrayObject(state);

    UErrorCode status = U_ZERO_ERROR;
    UEnumeration* ue = uplrules_getKeywords(pr->icuPluralRules(), &status);
    ASSERT(U_SUCCESS(status));
    uint32_t i = 0;

    do {
        int32_t size;
        const char* str = uenum_next(ue, &size, &status);
        ASSERT(U_SUCCESS(status));

        if (!str) {
            break;
        }

        String* s = String::fromUTF8(str, size);
        pluralCategories->defineOwnPropertyThrowsException(state, ObjectPropertyName(state, (size_t)i), ObjectPropertyDescriptor(Value(s), ObjectPropertyDescriptor::AllPresent));
        i++;
    } while (true);

    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(AtomicString(state.context()->atomicStringMap(), "pluralCategories", sizeof("pluralCategories") - 1, AtomicString::FromExternalMemory)),
                                              ObjectPropertyDescriptor(pluralCategories, ObjectPropertyDescriptor::AllPresent));

    uenum_close(ue);
    // Return options.
    return options;
}

static Value builtinIntlPluralRulesSupportedLocalesOf(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // If options is not provided, then let options be undefined.
    Value locales = argv[0];
    Value options;
    if (argc >= 2) {
        options = argv[1];
    }
    // Let availableLocales be the value of the [[availableLocales]] internal property of the standard built-in object that is the initial value of Intl.Collator.
    const auto& availableLocales = state.context()->vmInstance()->intlPluralRulesAvailableLocales();
    // Let requestedLocales be the result of calling the CanonicalizeLocaleList abstract operation (defined in 9.2.1) with argument locales.
    ValueVector requestedLocales = Intl::canonicalizeLocaleList(state, locales);
    // Return the result of calling the SupportedLocales abstract operation (defined in 9.2.8) with arguments availableLocales, requestedLocales, and options.
    return Intl::supportedLocales(state, availableLocales, requestedLocales, options);
}
#endif

static Value builtinIntlLocaleConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // If NewTarget is undefined, throw a TypeError exception.
    if (!newTarget) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, ErrorObject::Messages::GlobalObject_ConstructorRequiresNew);
    }

    Value tagValue = argv[0];

    // If Type(tag) is not String or Object, throw a TypeError exception.
    if (!tagValue.isObject() && !tagValue.isString()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "First argument of Intl.Locale should be String or Object");
    }

    String* tag;
    // If Type(tag) is Object and tag has an [[InitializedLocale]] internal slot, then
    if (tagValue.isObject() && tagValue.asObject()->isIntlLocaleObject()) {
        // Let tag be tag.[[Locale]].
        tag = tagValue.asObject()->asIntlLocaleObject()->locale();
    } else {
        // Else,
        // Let tag be ? ToString(tag).
        tag = tagValue.toString(state);
    }

    Optional<Object*> options;
    // If options is undefined, then
    if (argc <= 1 || argv[1].isUndefined()) {
        // Let options be ! ObjectCreate(null).
    } else {
        // Let options be ? ToObject(options).
        options = argv[1].toObject(state);
    }

    Object* proto = Object::getPrototypeFromConstructor(state, newTarget.value(), [](ExecutionState& state, Context* constructorRealm) -> Object* {
        return constructorRealm->globalObject()->intlLocalePrototype();
    });
    return new IntlLocaleObject(state, proto, tag, options);
}

static Value builtinIntlLocaleToString(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // Let loc be the this value.
    Value loc = thisValue;
    // If Type(loc) is not Object or loc does not have an [[InitializedLocale]] internal slot, then
    if (!loc.isObject() || !loc.asObject()->isIntlLocaleObject()) {
        // Throw a TypeError exception.
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }
    // Return loc.[[Locale]].
    return loc.asObject()->asIntlLocaleObject()->locale();
}

static Value builtinIntlLocaleBaseNameGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value loc = thisValue;
    // If Type(loc) is not Object or loc does not have an [[InitializedLocale]] internal slot, then
    if (!loc.isObject() || !loc.asObject()->isIntlLocaleObject()) {
        // Throw a TypeError exception.
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    return loc.asObject()->asIntlLocaleObject()->baseName();
}

static Value builtinIntlLocaleCalendarGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value loc = thisValue;
    // If Type(loc) is not Object or loc does not have an [[InitializedLocale]] internal slot, then
    if (!loc.isObject() || !loc.asObject()->isIntlLocaleObject()) {
        // Throw a TypeError exception.
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    return loc.asObject()->asIntlLocaleObject()->calendar().hasValue() ? loc.asObject()->asIntlLocaleObject()->calendar().value() : Value();
}

static Value builtinIntlLocaleCaseFirstGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value loc = thisValue;
    // If Type(loc) is not Object or loc does not have an [[InitializedLocale]] internal slot, then
    if (!loc.isObject() || !loc.asObject()->isIntlLocaleObject()) {
        // Throw a TypeError exception.
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    return loc.asObject()->asIntlLocaleObject()->caseFirst().hasValue() ? loc.asObject()->asIntlLocaleObject()->caseFirst().value() : Value();
}

static Value builtinIntlLocaleCollationGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value loc = thisValue;
    // If Type(loc) is not Object or loc does not have an [[InitializedLocale]] internal slot, then
    if (!loc.isObject() || !loc.asObject()->isIntlLocaleObject()) {
        // Throw a TypeError exception.
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    return loc.asObject()->asIntlLocaleObject()->collation().hasValue() ? loc.asObject()->asIntlLocaleObject()->collation().value() : Value();
}

static Value builtinIntlLocaleHourCycleGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value loc = thisValue;
    // If Type(loc) is not Object or loc does not have an [[InitializedLocale]] internal slot, then
    if (!loc.isObject() || !loc.asObject()->isIntlLocaleObject()) {
        // Throw a TypeError exception.
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    return loc.asObject()->asIntlLocaleObject()->hourCycle().hasValue() ? loc.asObject()->asIntlLocaleObject()->hourCycle().value() : Value();
}

static Value builtinIntlLocaleNumericGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value loc = thisValue;
    // If Type(loc) is not Object or loc does not have an [[InitializedLocale]] internal slot, then
    if (!loc.isObject() || !loc.asObject()->isIntlLocaleObject()) {
        // Throw a TypeError exception.
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    return loc.asObject()->asIntlLocaleObject()->numeric().hasValue() ? Value(loc.asObject()->asIntlLocaleObject()->numeric().value()->equals("true")) : Value(false);
}

static Value builtinIntlLocaleNumberingSystemGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value loc = thisValue;
    // If Type(loc) is not Object or loc does not have an [[InitializedLocale]] internal slot, then
    if (!loc.isObject() || !loc.asObject()->isIntlLocaleObject()) {
        // Throw a TypeError exception.
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    return loc.asObject()->asIntlLocaleObject()->numberingSystem().hasValue() ? loc.asObject()->asIntlLocaleObject()->numberingSystem().value() : Value();
}

static Value builtinIntlLocaleLanguageGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value loc = thisValue;
    // If Type(loc) is not Object or loc does not have an [[InitializedLocale]] internal slot, then
    if (!loc.isObject() || !loc.asObject()->isIntlLocaleObject()) {
        // Throw a TypeError exception.
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    return loc.asObject()->asIntlLocaleObject()->language();
}

static Value builtinIntlLocaleScriptGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value loc = thisValue;
    // If Type(loc) is not Object or loc does not have an [[InitializedLocale]] internal slot, then
    if (!loc.isObject() || !loc.asObject()->isIntlLocaleObject()) {
        // Throw a TypeError exception.
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    return loc.asObject()->asIntlLocaleObject()->script();
}

static Value builtinIntlLocaleRegionGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value loc = thisValue;
    // If Type(loc) is not Object or loc does not have an [[InitializedLocale]] internal slot, then
    if (!loc.isObject() || !loc.asObject()->isIntlLocaleObject()) {
        // Throw a TypeError exception.
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    return loc.asObject()->asIntlLocaleObject()->region();
}

static void icuLocleToBCP47Locale(char* buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '_') {
            buf[i] = '-';
        } else if ((std::numeric_limits<char>::is_signed && buf[i] < 0) || (!std::numeric_limits<char>::is_signed && buf[i] > 127)) {
            // when using uloc_addLikelySubtags with `und-...` input, old version of ICU shows weird behavior
            // it contains minus value in string
            buf[i] = 0;
            len = i;
            break;
        } else if (buf[i] == '@') { // we should ignore tags after '@'. ex) es-Latn-ES@currency=ESP -> es-Latn-ES
            buf[i] = 0;
            len = i;
            break;
        }
    }

    if (len) {
        for (size_t i = 0; i < len - 1; i++) {
            if (buf[i] == '-' && buf[i + 1] == '-') {
                for (size_t j = i; j < len - 1; j++) {
                    buf[j] = buf[j + 1];
                }
                len--;
                buf[len] = 0;
            }
        }
    }
}

static Value builtinIntlLocaleMaximize(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value loc = thisValue;
    // If Type(loc) is not Object or loc does not have an [[InitializedLocale]] internal slot, then
    if (!loc.isObject() || !loc.asObject()->isIntlLocaleObject()) {
        // Throw a TypeError exception.
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    // Let maximal be the result of the Add Likely Subtags algorithm applied to loc.[[Locale]]. If an error is signaled, set maximal to loc.[[Locale]].
    // Return ! Construct(%Locale%, maximal).
    IntlLocaleObject* localeObject = loc.asObject()->asIntlLocaleObject();
    String* locale = localeObject->locale();
    auto u8Locale = locale->toNonGCUTF8StringData();
    UErrorCode status = U_ZERO_ERROR;
    char buf[128];
    int32_t len = uloc_addLikelySubtags(u8Locale.data(), buf, sizeof(buf), &status);
    if (U_SUCCESS(status)) {
        icuLocleToBCP47Locale(buf, strlen(buf));
        StringBuilder sb;
        sb.appendString(buf);
        sb.appendSubString(locale, localeObject->baseName()->length(), locale->length());
        return new IntlLocaleObject(state, sb.finalize(), nullptr);

    } else if (status != U_BUFFER_OVERFLOW_ERROR) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::RangeError, "Unexpected error is occured while parsing locale");
    }
    status = U_ZERO_ERROR;
    char* newBuf = (char*)alloca(len + 1);
    uloc_addLikelySubtags(u8Locale.data(), newBuf, len + 1, &status);
    ASSERT(U_SUCCESS(status));

    icuLocleToBCP47Locale(newBuf, strlen(newBuf));
    StringBuilder sb;
    sb.appendString(newBuf);
    sb.appendSubString(locale, localeObject->baseName()->length(), locale->length());
    return new IntlLocaleObject(state, sb.finalize(), nullptr);
}

static Value builtinIntlLocaleMinimize(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value loc = thisValue;
    // If Type(loc) is not Object or loc does not have an [[InitializedLocale]] internal slot, then
    if (!loc.isObject() || !loc.asObject()->isIntlLocaleObject()) {
        // Throw a TypeError exception.
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    // Let minimal be the result of the Remove Likely Subtags algorithm applied to loc.[[Locale]]. If an error is signaled, set minimal to loc.[[Locale]].
    // Return ! Construct(%Locale%, minimal).
    IntlLocaleObject* localeObject = loc.asObject()->asIntlLocaleObject();
    String* locale = localeObject->locale();
    auto u8Locale = locale->toNonGCUTF8StringData();
    UErrorCode status = U_ZERO_ERROR;
    char buf[128];
    int32_t len = uloc_minimizeSubtags(u8Locale.data(), buf, sizeof(buf), &status);
    if (U_SUCCESS(status)) {
        icuLocleToBCP47Locale(buf, len);
        StringBuilder sb;
        sb.appendString(buf);
        sb.appendSubString(locale, localeObject->baseName()->length(), locale->length());
        return new IntlLocaleObject(state, sb.finalize(), nullptr);
    } else if (status != U_BUFFER_OVERFLOW_ERROR) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::RangeError, "Unexpected error is occured while parsing locale");
    }
    status = U_ZERO_ERROR;
    char* newBuf = (char*)alloca(len + 1);
    len = uloc_minimizeSubtags(u8Locale.data(), newBuf, len + 1, &status);
    ASSERT(U_SUCCESS(status));

    icuLocleToBCP47Locale(newBuf, len);
    StringBuilder sb;
    sb.appendString(newBuf);
    sb.appendSubString(locale, localeObject->baseName()->length(), locale->length());
    return new IntlLocaleObject(state, sb.finalize(), nullptr);
}

static Value builtinIntlLocaleCalendarsGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlLocaleObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }
    return thisValue.asObject()->asIntlLocaleObject()->calendars(state);
}

static Value builtinIntlLocaleCollationsGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlLocaleObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }
    return thisValue.asObject()->asIntlLocaleObject()->collations(state);
}

static Value builtinIntlLocaleHourCyclesGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlLocaleObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }
    return thisValue.asObject()->asIntlLocaleObject()->hourCycles(state);
}

static Value builtinIntlLocaleNumberingSystemsGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlLocaleObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }
    return thisValue.asObject()->asIntlLocaleObject()->numberingSystems(state);
}

static Value builtinIntlLocaleTextInfoGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlLocaleObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }
    return thisValue.asObject()->asIntlLocaleObject()->textInfo(state);
}

static Value builtinIntlLocaleWeekInfoGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlLocaleObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }
    return thisValue.asObject()->asIntlLocaleObject()->weekInfo(state);
}

static Value builtinIntlLocaleTimeZonesGetter(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlLocaleObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }
    return thisValue.asObject()->asIntlLocaleObject()->timeZones(state);
}

#if defined(ENABLE_INTL_RELATIVETIMEFORMAT)
static Value builtinIntlRelativeTimeFormatConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // If NewTarget is undefined, throw a TypeError exception.
    if (!newTarget) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, ErrorObject::Messages::GlobalObject_ConstructorRequiresNew);
    }

#if defined(ENABLE_RUNTIME_ICU_BINDER)
    UVersionInfo versionArray;
    u_getVersion(versionArray);
    if (versionArray[0] < 64) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Intl.RelativeTimeFormat needs 64+ version of ICU");
    }
#endif

    Value locales = argc >= 1 ? argv[0] : Value();
    Value options = argc >= 2 ? argv[1] : Value();

    Object* proto = Object::getPrototypeFromConstructor(state, newTarget.value(), [](ExecutionState& state, Context* constructorRealm) -> Object* {
        return constructorRealm->globalObject()->intlRelativeTimeFormatPrototype();
    });

    return new IntlRelativeTimeFormatObject(state, proto, locales, options);
}

static Value builtinIntlRelativeTimeFormatResolvedOptions(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlRelativeTimeFormatObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    IntlRelativeTimeFormatObject* r = thisValue.asObject()->asIntlRelativeTimeFormatObject();

    // Let options be ! ObjectCreate(%ObjectPrototype%).
    Object* options = new Object(state);

    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazySmallLetterLocale()), ObjectPropertyDescriptor(r->locale(), ObjectPropertyDescriptor::AllPresent));
    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().lazyStyle()), ObjectPropertyDescriptor(r->style(), ObjectPropertyDescriptor::AllPresent));
    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().numeric), ObjectPropertyDescriptor(r->numeric(), ObjectPropertyDescriptor::AllPresent));
    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(state.context()->staticStrings().numberingSystem), ObjectPropertyDescriptor(r->numberingSystem(), ObjectPropertyDescriptor::AllPresent));

    return options;
}

static Value builtinIntlRelativeTimeFormatSupportedLocalesOf(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value locales = argv[0];
    Value options;
    if (argc >= 2) {
        options = argv[1];
    }
    // Let availableLocales be %RelativeTimeFormat%.[[AvailableLocales]].
    const auto& availableLocales = state.context()->vmInstance()->intlRelativeTimeFormatAvailableLocales();
    // Let requestedLocales be ? CanonicalizeLocaleList(locales).
    ValueVector requestedLocales = Intl::canonicalizeLocaleList(state, locales);
    // Return ? SupportedLocales(availableLocales, requestedLocales, options).
    return Intl::supportedLocales(state, availableLocales, requestedLocales, options);
}

static Value builtinIntlRelativeTimeFormatFormat(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlRelativeTimeFormatObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    // Let relativeTimeFormat be the this value.
    // Perform ? RequireInternalSlot(relativeTimeFormat, [[InitializedRelativeTimeFormat]]).
    // Let value be ? ToNumber(value).
    double value = argv[0].toNumber(state);
    // Let unit be ? ToString(unit).
    String* unit = argv[1].toString(state);
    // Return ? FormatRelativeTime(relativeTimeFormat, value, unit).
    return thisValue.asObject()->asIntlRelativeTimeFormatObject()->format(state, value, unit);
}

static Value builtinIntlRelativeTimeFormatFormatToParts(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlRelativeTimeFormatObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    // Let relativeTimeFormat be the this value.
    // Perform ? RequireInternalSlot(relativeTimeFormat, [[InitializedRelativeTimeFormat]]).
    // Let value be ? ToNumber(value).
    double value = argv[0].toNumber(state);
    // Let unit be ? ToString(unit).
    String* unit = argv[1].toString(state);
    // Return ? FormatRelativeTimeToParts(relativeTimeFormat, value, unit).
    return thisValue.asObject()->asIntlRelativeTimeFormatObject()->formatToParts(state, value, unit);
}
#endif

#if defined(ENABLE_INTL_DISPLAYNAMES)
static Value builtinIntlDisplayNamesConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // https://402.ecma-international.org/8.0/#sec-Intl.DisplayNames
    // If NewTarget is undefined, throw a TypeError exception.
    if (!newTarget) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, ErrorObject::Messages::GlobalObject_ConstructorRequiresNew);
    }

    Object* proto = Object::getPrototypeFromConstructor(state, newTarget.value(), [](ExecutionState& state, Context* realm) -> Object* {
        return realm->globalObject()->intlDisplayNamesPrototype();
    });
    return new IntlDisplayNamesObject(state, proto, argv[0], argv[1]);
}

static Value builtinIntlDisplayNamesOf(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlDisplayNamesObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    IntlDisplayNamesObject* r = thisValue.asObject()->asIntlDisplayNamesObject();
    return r->of(state, argv[0]);
}

static Value builtinIntlDisplayNamesResolvedOptions(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlDisplayNamesObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    IntlDisplayNamesObject* r = thisValue.asObject()->asIntlDisplayNamesObject();

    Object* options = new Object(state);

    auto& staticStrings = state.context()->staticStrings();
    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(staticStrings.lazySmallLetterLocale()), ObjectPropertyDescriptor(r->locale(), ObjectPropertyDescriptor::AllPresent));
    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(staticStrings.lazyStyle()), ObjectPropertyDescriptor(r->style(), ObjectPropertyDescriptor::AllPresent));
    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(staticStrings.lazyType()), ObjectPropertyDescriptor(r->type(), ObjectPropertyDescriptor::AllPresent));
    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(staticStrings.lazyFallback()), ObjectPropertyDescriptor(r->fallback(), ObjectPropertyDescriptor::AllPresent));
    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(staticStrings.lazyLanguageDisplay()), ObjectPropertyDescriptor(r->languageDisplay(), ObjectPropertyDescriptor::AllPresent));
    return options;
}
#endif

#if defined(ENABLE_INTL_LISTFORMAT)
static Value builtinIntlListFormatConstructor(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // If NewTarget is undefined, throw a TypeError exception.
    if (!newTarget) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, ErrorObject::Messages::GlobalObject_ConstructorRequiresNew);
    }

    Object* proto = Object::getPrototypeFromConstructor(state, newTarget.value(), [](ExecutionState& state, Context* realm) -> Object* {
        return realm->globalObject()->intlListFormatPrototype();
    });
    if (argc >= 2) {
        return new IntlListFormatObject(state, proto, argv[0], argv[1]);
    } else if (argc >= 1) {
        return new IntlListFormatObject(state, proto, argv[0], Value());
    } else {
        return new IntlListFormatObject(state, proto, Value(), Value());
    }
}

static Value builtinIntlListFormatSupportedLocalesOf(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    Value locales = argv[0];
    Value options;
    if (argc >= 2) {
        options = argv[1];
    }
    const auto& availableLocales = state.context()->vmInstance()->intlListFormatAvailableLocales();
    ValueVector requestedLocales = Intl::canonicalizeLocaleList(state, locales);
    return Intl::supportedLocales(state, availableLocales, requestedLocales, options);
}

static Value builtinIntlListFormatResolvedOptions(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlListFormatObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    IntlListFormatObject* r = thisValue.asObject()->asIntlListFormatObject();

    Object* options = new Object(state);

    auto& staticStrings = state.context()->staticStrings();
    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(staticStrings.lazySmallLetterLocale()), ObjectPropertyDescriptor(r->locale(), ObjectPropertyDescriptor::AllPresent));
    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(staticStrings.lazyType()), ObjectPropertyDescriptor(r->type(), ObjectPropertyDescriptor::AllPresent));
    options->defineOwnPropertyThrowsException(state, ObjectPropertyName(staticStrings.lazyStyle()), ObjectPropertyDescriptor(r->style(), ObjectPropertyDescriptor::AllPresent));
    return options;
}

static Value builtinIntlListFormatFormat(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlListFormatObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    IntlListFormatObject* r = thisValue.asObject()->asIntlListFormatObject();
    return r->format(state, argv[0]);
}

static Value builtinIntlListFormatFormatToParts(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    if (!thisValue.isObject() || !thisValue.asObject()->isIntlListFormatObject()) {
        THROW_BUILTIN_ERROR_RETURN_VALUE(state, ErrorCode::TypeError, "Method called on incompatible receiver");
    }

    IntlListFormatObject* r = thisValue.asObject()->asIntlListFormatObject();
    return r->formatToParts(state, argv[0]);
}
#endif

static Value builtinIntlGetCanonicalLocales(ExecutionState& state, Value thisValue, size_t argc, Value* argv, Optional<Object*> newTarget)
{
    // Let ll be ? CanonicalizeLocaleList(locales).
    ValueVector ll = Intl::canonicalizeLocaleList(state, argv[0]);
    // Return CreateArrayFromList(ll);
    return Object::createArrayFromList(state, ll);
}

void GlobalObject::initializeIntl(ExecutionState& state)
{
    ObjectPropertyNativeGetterSetterData* nativeData = new ObjectPropertyNativeGetterSetterData(true, false, true,
                                                                                                [](ExecutionState& state, Object* self, const Value& receiver, const EncodedValue& privateDataFromObjectPrivateArea) -> Value {
                                                                                                    ASSERT(self->isGlobalObject());
                                                                                                    return self->asGlobalObject()->intl();
                                                                                                },
                                                                                                nullptr);

    defineNativeDataAccessorProperty(state, ObjectPropertyName(state.context()->staticStrings().Intl), nativeData, Value(Value::EmptyValue));
}

void GlobalObject::installIntl(ExecutionState& state)
{
    m_intl = new Object(state);
    m_intl->setGlobalIntrinsicObject(state);

    StaticStrings* strings = &state.context()->staticStrings();
    redefineOwnProperty(state, ObjectPropertyName(strings->Intl),
                        ObjectPropertyDescriptor(m_intl, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_intlCollator = new NativeFunctionObject(state, NativeFunctionInfo(strings->Collator, builtinIntlCollatorConstructor, 0), NativeFunctionObject::__ForBuiltinConstructor__);
    m_intlCollator->setGlobalIntrinsicObject(state);
    m_intlCollator->getFunctionPrototype(state).asObject()->setGlobalIntrinsicObject(state);

    FunctionObject* compareFunction = new NativeFunctionObject(state, NativeFunctionInfo(strings->getCompare, builtinIntlCollatorCompareGetter, 0, NativeFunctionInfo::Strict));
    m_intlCollator->getFunctionPrototype(state).asObject()->directDefineOwnProperty(state, state.context()->staticStrings().compare,
                                                                                    ObjectPropertyDescriptor(JSGetterSetter(compareFunction, Value(Value::EmptyValue)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent)));

    m_intlCollator->getFunctionPrototype(state).asObject()->directDefineOwnProperty(state, state.context()->staticStrings().resolvedOptions,
                                                                                    ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->resolvedOptions, builtinIntlCollatorResolvedOptions, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlCollator->getFunctionPrototype(state).asObject()->directDefineOwnProperty(state, ObjectPropertyName(state.context()->vmInstance()->globalSymbols().toStringTag),
                                                                                    ObjectPropertyDescriptor(strings->intlDotCollator.string(), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent)));

    m_intlCollator->directDefineOwnProperty(state, state.context()->staticStrings().supportedLocalesOf,
                                            ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->supportedLocalesOf, builtinIntlCollatorSupportedLocalesOf, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlDateTimeFormat = new NativeFunctionObject(state, NativeFunctionInfo(strings->DateTimeFormat, builtinIntlDateTimeFormatConstructor, 0), NativeFunctionObject::__ForBuiltinConstructor__);
    m_intlDateTimeFormat->setGlobalIntrinsicObject(state);
    m_intlDateTimeFormatPrototype = m_intlDateTimeFormat->getFunctionPrototype(state).asObject();
    m_intlDateTimeFormatPrototype->setGlobalIntrinsicObject(state, true);

    FunctionObject* formatFunction = new NativeFunctionObject(state, NativeFunctionInfo(strings->getFormat, builtinIntlDateTimeFormatFormatGetter, 0, NativeFunctionInfo::Strict));
    m_intlDateTimeFormatPrototype->directDefineOwnProperty(state, state.context()->staticStrings().format,
                                                           ObjectPropertyDescriptor(JSGetterSetter(formatFunction, Value(Value::EmptyValue)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent)));

    m_intlDateTimeFormatPrototype->directDefineOwnProperty(state, state.context()->staticStrings().formatToParts,
                                                           ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->formatToParts, builtinIntlDateTimeFormatFormatToParts, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlDateTimeFormatPrototype->directDefineOwnProperty(state, state.context()->staticStrings().resolvedOptions,
                                                           ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->resolvedOptions, builtinIntlDateTimeFormatResolvedOptions, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlDateTimeFormat->directDefineOwnProperty(state, state.context()->staticStrings().supportedLocalesOf,
                                                  ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->supportedLocalesOf, builtinIntlDateTimeFormatSupportedLocalesOf, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

#if defined(ENABLE_INTL_NUMBERFORMAT)
    m_intlNumberFormat = new NativeFunctionObject(state, NativeFunctionInfo(strings->NumberFormat, builtinIntlNumberFormatConstructor, 0), NativeFunctionObject::__ForBuiltinConstructor__);
    m_intlNumberFormat->setGlobalIntrinsicObject(state);
    m_intlNumberFormatPrototype = m_intlNumberFormat->getFunctionPrototype(state).asObject();
    m_intlNumberFormatPrototype->setGlobalIntrinsicObject(state, true);

    {
        formatFunction = new NativeFunctionObject(state, NativeFunctionInfo(strings->getFormat, builtinIntlNumberFormatFormatGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(formatFunction, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlNumberFormatPrototype->directDefineOwnProperty(state, ObjectPropertyName(state, strings->format), desc);
    }

    m_intlNumberFormatPrototype->directDefineOwnProperty(state, state.context()->staticStrings().formatToParts,
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->formatToParts, builtinIntlNumberFormatFormatToParts, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlNumberFormatPrototype->directDefineOwnProperty(state, state.context()->staticStrings().resolvedOptions,
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->resolvedOptions, builtinIntlNumberFormatResolvedOptions, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlNumberFormatPrototype->directDefineOwnProperty(state, ObjectPropertyName(state.context()->vmInstance()->globalSymbols().toStringTag),
                                                         ObjectPropertyDescriptor(Value(state.context()->staticStrings().Object.string()), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent)));

    m_intlNumberFormat->directDefineOwnProperty(state, state.context()->staticStrings().supportedLocalesOf,
                                                ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->supportedLocalesOf, builtinIntlNumberFormatSupportedLocalesOf, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));
#endif

#if defined(ENABLE_INTL_PLURALRULES)
    m_intlPluralRules = new NativeFunctionObject(state, NativeFunctionInfo(strings->PluralRules, builtinIntlPluralRulesConstructor, 0), NativeFunctionObject::__ForBuiltinConstructor__);
    m_intlPluralRules->setGlobalIntrinsicObject(state);

    m_intlPluralRulesPrototype = m_intlPluralRules->getFunctionPrototype(state).asObject();
    m_intlPluralRulesPrototype->setGlobalIntrinsicObject(state, true);

    m_intlPluralRulesPrototype->directDefineOwnProperty(state, state.context()->staticStrings().select,
                                                        ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->select, builtinIntlPluralRulesSelect, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlPluralRulesPrototype->directDefineOwnProperty(state, state.context()->staticStrings().resolvedOptions,
                                                        ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->resolvedOptions, builtinIntlPluralRulesResolvedOptions, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlPluralRulesPrototype->directDefineOwnProperty(state, ObjectPropertyName(state.context()->vmInstance()->globalSymbols().toStringTag),
                                                        ObjectPropertyDescriptor(Value(state.context()->staticStrings().intlDotPluralRules.string()), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent)));

    m_intlPluralRules->directDefineOwnProperty(state, state.context()->staticStrings().supportedLocalesOf,
                                               ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->supportedLocalesOf, builtinIntlPluralRulesSupportedLocalesOf, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));
#endif

    m_intlLocale = new NativeFunctionObject(state, NativeFunctionInfo(strings->Locale, builtinIntlLocaleConstructor, 1), NativeFunctionObject::__ForBuiltinConstructor__);
    m_intlLocale->setGlobalIntrinsicObject(state);

    m_intlLocalePrototype = m_intlLocale->getFunctionPrototype(state).asObject();
    m_intlLocalePrototype->setGlobalIntrinsicObject(state, true);

    m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state.context()->vmInstance()->globalSymbols().toStringTag),
                                                   ObjectPropertyDescriptor(Value(state.context()->staticStrings().intlDotLocale.string()), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent)));

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(state.context()->staticStrings().getBaseName, builtinIntlLocaleBaseNameGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, state.context()->staticStrings().baseName), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(state.context()->staticStrings().getCalendar, builtinIntlLocaleCalendarGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, state.context()->staticStrings().calendar), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(state.context()->staticStrings().getCaseFirst, builtinIntlLocaleCaseFirstGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, state.context()->staticStrings().caseFirst), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(state.context()->staticStrings().getCollation, builtinIntlLocaleCollationGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, state.context()->staticStrings().collation), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(state.context()->staticStrings().getHourCycle, builtinIntlLocaleHourCycleGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, state.context()->staticStrings().hourCycle), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(state.context()->staticStrings().getNumeric, builtinIntlLocaleNumericGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, state.context()->staticStrings().numeric), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(state.context()->staticStrings().getNumberingSystem, builtinIntlLocaleNumberingSystemGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, state.context()->staticStrings().numberingSystem), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(state.context()->staticStrings().getLanguage, builtinIntlLocaleLanguageGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, state.context()->staticStrings().language), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(state.context()->staticStrings().getScript, builtinIntlLocaleScriptGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, state.context()->staticStrings().script), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(state.context()->staticStrings().getRegion, builtinIntlLocaleRegionGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, state.context()->staticStrings().region), desc);
    }

    m_intlLocalePrototype->directDefineOwnProperty(state, state.context()->staticStrings().toString,
                                                   ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->toString, builtinIntlLocaleToString, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlLocalePrototype->directDefineOwnProperty(state, state.context()->staticStrings().maximize,
                                                   ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->maximize, builtinIntlLocaleMaximize, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlLocalePrototype->directDefineOwnProperty(state, state.context()->staticStrings().minimize,
                                                   ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->minimize, builtinIntlLocaleMinimize, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(strings->getCalendars, builtinIntlLocaleCalendarsGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, strings->lazyCalendars()), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(strings->getCollations, builtinIntlLocaleCollationsGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, strings->lazyCollations()), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(strings->getHourCycles, builtinIntlLocaleHourCyclesGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, strings->lazyHourCycles()), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(strings->getNumberingSystems, builtinIntlLocaleNumberingSystemsGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, strings->lazyNumberingSystems()), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(strings->getTextInfo, builtinIntlLocaleTextInfoGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, strings->lazyTextInfo()), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(strings->getWeekInfo, builtinIntlLocaleWeekInfoGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, strings->lazyWeekInfo()), desc);
    }

    {
        Value getter = new NativeFunctionObject(state, NativeFunctionInfo(strings->getTimeZones, builtinIntlLocaleTimeZonesGetter, 0, NativeFunctionInfo::Strict));
        JSGetterSetter gs(getter, Value());
        ObjectPropertyDescriptor desc(gs, ObjectPropertyDescriptor::ConfigurablePresent);
        m_intlLocalePrototype->directDefineOwnProperty(state, ObjectPropertyName(state, strings->lazyTimeZones()), desc);
    }

#if defined(ENABLE_INTL_RELATIVETIMEFORMAT)
    m_intlRelativeTimeFormat = new NativeFunctionObject(state, NativeFunctionInfo(strings->RelativeTimeFormat, builtinIntlRelativeTimeFormatConstructor, 0), NativeFunctionObject::__ForBuiltinConstructor__);
    m_intlRelativeTimeFormat->setGlobalIntrinsicObject(state);

    m_intlRelativeTimeFormatPrototype = m_intlRelativeTimeFormat->getFunctionPrototype(state).asObject();
    m_intlRelativeTimeFormatPrototype->setGlobalIntrinsicObject(state, true);

    m_intlRelativeTimeFormatPrototype->directDefineOwnProperty(state, ObjectPropertyName(state.context()->vmInstance()->globalSymbols().toStringTag),
                                                               ObjectPropertyDescriptor(Value(state.context()->staticStrings().intlDotRelativeTimeFormat.string()), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent)));

    m_intlRelativeTimeFormatPrototype->directDefineOwnProperty(state, state.context()->staticStrings().format,
                                                               ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->format, builtinIntlRelativeTimeFormatFormat, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlRelativeTimeFormatPrototype->directDefineOwnProperty(state, state.context()->staticStrings().formatToParts,
                                                               ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->formatToParts, builtinIntlRelativeTimeFormatFormatToParts, 2, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlRelativeTimeFormatPrototype->directDefineOwnProperty(state, state.context()->staticStrings().resolvedOptions,
                                                               ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->resolvedOptions, builtinIntlRelativeTimeFormatResolvedOptions, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlRelativeTimeFormat->directDefineOwnProperty(state, state.context()->staticStrings().supportedLocalesOf,
                                                      ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->supportedLocalesOf, builtinIntlRelativeTimeFormatSupportedLocalesOf, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));
#endif

#if defined(ENABLE_INTL_DISPLAYNAMES)
    m_intlDisplayNames = new NativeFunctionObject(state, NativeFunctionInfo(strings->DisplayNames, builtinIntlDisplayNamesConstructor, 2), NativeFunctionObject::__ForBuiltinConstructor__);
    m_intlDisplayNames->setGlobalIntrinsicObject(state);

    m_intlDisplayNamesPrototype = m_intlDisplayNames->getFunctionPrototype(state).asObject();
    m_intlDisplayNamesPrototype->setGlobalIntrinsicObject(state, true);

    m_intlDisplayNamesPrototype->directDefineOwnProperty(state, ObjectPropertyName(state.context()->vmInstance()->globalSymbols().toStringTag),
                                                         ObjectPropertyDescriptor(Value(strings->intlDotDisplayNames.string()), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent)));

    m_intlDisplayNamesPrototype->directDefineOwnProperty(state, state.context()->staticStrings().of,
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->of, builtinIntlDisplayNamesOf, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlDisplayNamesPrototype->directDefineOwnProperty(state, state.context()->staticStrings().resolvedOptions,
                                                         ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->resolvedOptions, builtinIntlDisplayNamesResolvedOptions, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));
#endif

#if defined(ENABLE_INTL_LISTFORMAT)
    m_intlListFormat = new NativeFunctionObject(state, NativeFunctionInfo(strings->ListFormat, builtinIntlListFormatConstructor, 0), NativeFunctionObject::__ForBuiltinConstructor__);
    m_intlListFormat->setGlobalIntrinsicObject(state);

    m_intlListFormat->directDefineOwnProperty(state, state.context()->staticStrings().supportedLocalesOf,
                                              ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->supportedLocalesOf, builtinIntlListFormatSupportedLocalesOf, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlListFormatPrototype = m_intlListFormat->getFunctionPrototype(state).asObject();
    m_intlListFormatPrototype->setGlobalIntrinsicObject(state, true);

    m_intlListFormatPrototype->directDefineOwnProperty(state, state.context()->staticStrings().resolvedOptions,
                                                       ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->resolvedOptions, builtinIntlListFormatResolvedOptions, 0, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlListFormatPrototype->directDefineOwnProperty(state, state.context()->staticStrings().format,
                                                       ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->format, builtinIntlListFormatFormat, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlListFormatPrototype->directDefineOwnProperty(state, state.context()->staticStrings().formatToParts,
                                                       ObjectPropertyDescriptor(new NativeFunctionObject(state, NativeFunctionInfo(strings->formatToParts, builtinIntlListFormatFormatToParts, 1, NativeFunctionInfo::Strict)), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent | ObjectPropertyDescriptor::WritablePresent)));

    m_intlListFormatPrototype->directDefineOwnProperty(state, ObjectPropertyName(state.context()->vmInstance()->globalSymbols().toStringTag),
                                                       ObjectPropertyDescriptor(Value(strings->intlDotListFormat.string()), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent)));

    m_intl->directDefineOwnProperty(state, ObjectPropertyName(state.context()->vmInstance()->globalSymbols().toStringTag),
                                    ObjectPropertyDescriptor(Value(state.context()->staticStrings().Intl.string()), (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::ConfigurablePresent)));
#endif

    m_intl->directDefineOwnProperty(state, ObjectPropertyName(strings->Collator),
                                    ObjectPropertyDescriptor(m_intlCollator, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));

    m_intl->directDefineOwnProperty(state, ObjectPropertyName(strings->DateTimeFormat),
                                    ObjectPropertyDescriptor(m_intlDateTimeFormat, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));
#if defined(ENABLE_INTL_NUMBERFORMAT)
    m_intl->directDefineOwnProperty(state, ObjectPropertyName(strings->NumberFormat),
                                    ObjectPropertyDescriptor(m_intlNumberFormat, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));
#endif
#if defined(ENABLE_INTL_PLURALRULES)
    m_intl->directDefineOwnProperty(state, ObjectPropertyName(strings->PluralRules),
                                    ObjectPropertyDescriptor(m_intlPluralRules, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));
#endif
    m_intl->directDefineOwnProperty(state, ObjectPropertyName(strings->Locale),
                                    ObjectPropertyDescriptor(m_intlLocale, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));
#if defined(ENABLE_INTL_RELATIVETIMEFORMAT)
    m_intl->directDefineOwnProperty(state, ObjectPropertyName(strings->RelativeTimeFormat),
                                    ObjectPropertyDescriptor(m_intlRelativeTimeFormat, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));
#endif
#if defined(ENABLE_INTL_DISPLAYNAMES)
    m_intl->directDefineOwnProperty(state, ObjectPropertyName(strings->DisplayNames),
                                    ObjectPropertyDescriptor(m_intlDisplayNames, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));
#endif
#if defined(ENABLE_INTL_LISTFORMAT)
    m_intl->directDefineOwnProperty(state, ObjectPropertyName(strings->ListFormat),
                                    ObjectPropertyDescriptor(m_intlListFormat, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));
#endif
    FunctionObject* getCanonicalLocales = new NativeFunctionObject(state, NativeFunctionInfo(strings->getCanonicalLocales, builtinIntlGetCanonicalLocales, 1, NativeFunctionInfo::Strict));
    m_intl->directDefineOwnProperty(state, ObjectPropertyName(strings->getCanonicalLocales),
                                    ObjectPropertyDescriptor(getCanonicalLocales, (ObjectPropertyDescriptor::PresentAttribute)(ObjectPropertyDescriptor::WritablePresent | ObjectPropertyDescriptor::ConfigurablePresent)));
}

#else

void GlobalObject::initializeIntl(ExecutionState& state)
{
    // dummy initialize function
}

#endif // ENABLE_ICU
} // namespace Escargot
