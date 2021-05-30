//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef MARSHALLING_TEST_COMMON_HPP
#define MARSHALLING_TEST_COMMON_HPP

#include <boost/test/unit_test.hpp>

#include <iostream>
#include <iterator>
#include <tuple>
#include <type_traits>
#include <vector>

#include <nil/marshalling/message.hpp>
#include <nil/marshalling/message_base.hpp>

#include <nil/marshalling/types/bitmask_value.hpp>
#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/int_value.hpp>
#include <nil/marshalling/types/optional.hpp>

enum message_type {
    MessageType1,
    UnusedValue1,
    MessageType2,
    UnusedValue2,
    UnusedValue3,
    MessageType3,
    MessageType4,
    MessageType5,
    MessageType6,
    MessageType7,
};

template<typename TTraits>
using TestMessageBase = nil::marshalling::message<TTraits>;

template<typename TField>
using FieldsMessage1 = std::tuple<nil::marshalling::types::int_value<TField, std::uint16_t>>;

template<typename TMessage>
class Message1 : public nil::marshalling::message_base<
                     TMessage, nil::marshalling::option::static_num_id_impl<MessageType1>,
                     nil::marshalling::option::fields_impl<FieldsMessage1<typename TMessage::field_type>>,
                     nil::marshalling::option::msg_type<Message1<TMessage>>, nil::marshalling::option::has_name> {
    using Base = nil::marshalling::message_base<
        TMessage, nil::marshalling::option::static_num_id_impl<MessageType1>,
        nil::marshalling::option::fields_impl<FieldsMessage1<typename TMessage::field_type>>,
        nil::marshalling::option::msg_type<Message1<TMessage>>, nil::marshalling::option::has_name>;

public:
    static const bool AreFieldsVersionDependent = Base::are_fields_version_dependent();
    static_assert(!AreFieldsVersionDependent, "fields_type mustn't be version dependent");

    MARSHALLING_MSG_FIELDS_ACCESS(value1);

    static const std::size_t MsgMinLen = Base::eval_min_length();
    static const std::size_t MsgMaxLen = Base::eval_max_length();
    static_assert(MsgMinLen == 2U, "Wrong serialization length");
    static_assert(MsgMaxLen == 2U, "Wrong serialization length");

    Message1() = default;

    virtual ~Message1() noexcept = default;

    static const char *eval_name() {
        return "Message1";
    }
};

template<typename TMessage>
class Message2
    : public nil::marshalling::message_base<TMessage, nil::marshalling::option::static_num_id_impl<MessageType2>,
                                            nil::marshalling::option::zero_fields_impl,
                                            nil::marshalling::option::msg_type<Message2<TMessage>>,
                                            nil::marshalling::option::has_name> {
    using Base = nil::marshalling::message_base<TMessage, nil::marshalling::option::static_num_id_impl<MessageType2>,
                                                nil::marshalling::option::zero_fields_impl,
                                                nil::marshalling::option::msg_type<Message2<TMessage>>,
                                                nil::marshalling::option::has_name>;

public:
    virtual ~Message2() noexcept = default;

    static const std::size_t MsgMinLen = Base::eval_min_length();
    static const std::size_t MsgMaxLen = Base::eval_max_length();
    static_assert(MsgMinLen == 0U, "Wrong serialization length");
    static_assert(MsgMaxLen == 0U, "Wrong serialization length");

    static const char *eval_name() {
        return "Message2";
    }
};

template<typename TField>
using Message3Fields = std::tuple<
    nil::marshalling::types::int_value<TField, std::uint32_t>,
    nil::marshalling::types::int_value<TField, std::int16_t, nil::marshalling::option::fixed_length<1>,
                                       nil::marshalling::option::valid_num_value_range<-120, 120>,
                                       nil::marshalling::option::default_num_value<127>>,    // invalid upon creation
    nil::marshalling::types::bitmask_value<TField, nil::marshalling::option::fixed_length<2>>,
    nil::marshalling::types::bitmask_value<TField, nil::marshalling::option::fixed_length<3>>>;

template<typename TMessage>
class Message3 : public nil::marshalling::message_base<
                     TMessage, nil::marshalling::option::static_num_id_impl<MessageType3>,
                     nil::marshalling::option::fields_impl<Message3Fields<typename TMessage::field_type>>,
                     nil::marshalling::option::msg_type<Message3<TMessage>>, nil::marshalling::option::has_name> {
    using Base = nil::marshalling::message_base<
        TMessage, nil::marshalling::option::static_num_id_impl<MessageType3>,
        nil::marshalling::option::fields_impl<Message3Fields<typename TMessage::field_type>>,
        nil::marshalling::option::msg_type<Message3<TMessage>>, nil::marshalling::option::has_name>;

public:
    static const bool AreFieldsVersionDependent = Base::are_fields_version_dependent();
    static_assert(!AreFieldsVersionDependent, "fields_type mustn't be version dependent");

    MARSHALLING_MSG_FIELDS_ACCESS(value1, value2, value3, value4);

    static const std::size_t MsgMinLen = Base::eval_min_length();
    static const std::size_t MsgMaxLen = Base::eval_max_length();
    static const std::size_t MsgMinLen_0_1 = Base::template eval_min_length_until<FieldIdx_value2>();
    static const std::size_t MsgMaxLen_0_1 = Base::template eval_max_length_until<FieldIdx_value2>();
    static const std::size_t MsgMinLen_0_2 = Base::template eval_min_length_until<FieldIdx_value3>();
    static const std::size_t MsgMaxLen_0_2 = Base::template eval_max_length_until<FieldIdx_value3>();
    static const std::size_t MsgMinLen_1_4 = Base::template eval_min_length_from<FieldIdx_value2>();
    static const std::size_t MsgMaxLen_1_4 = Base::template eval_max_length_from<FieldIdx_value2>();
    static const std::size_t MsgMinLen_1_3
        = Base::template eval_min_length_from_until<FieldIdx_value2, FieldIdx_value4>();
    static const std::size_t MsgMaxLen_1_3
        = Base::template eval_max_length_from_until<FieldIdx_value2, FieldIdx_value4>();

    static_assert(MsgMinLen == 10U, "Wrong serialization length");
    static_assert(MsgMaxLen == 10U, "Wrong serialization length");
    static_assert(MsgMinLen_0_1 == 4U, "Wrong serialization length");
    static_assert(MsgMaxLen_0_1 == 4U, "Wrong serialization length");
    static_assert(MsgMinLen_0_2 == 5U, "Wrong serialization length");
    static_assert(MsgMaxLen_0_2 == 5U, "Wrong serialization length");
    static_assert(MsgMinLen_1_4 == 6U, "Wrong serialization length");
    static_assert(MsgMaxLen_1_4 == 6U, "Wrong serialization length");
    static_assert(MsgMinLen_1_3 == 3U, "Wrong serialization length");
    static_assert(MsgMaxLen_1_3 == 3U, "Wrong serialization length");

    Message3() = default;

    virtual ~Message3() noexcept = default;

    static const char *eval_name() {
        return "Message3";
    }
};

template<typename TField>
using Message4Fields
    = std::tuple<nil::marshalling::types::bitmask_value<TField, nil::marshalling::option::fixed_length<1>>,
                 nil::marshalling::types::optional<nil::marshalling::types::int_value<TField, std::uint16_t>>>;

template<typename TMessage>
class Message4 : public nil::marshalling::message_base<
                     TMessage, nil::marshalling::option::static_num_id_impl<MessageType4>,
                     nil::marshalling::option::fields_impl<Message4Fields<typename TMessage::field_type>>,
                     nil::marshalling::option::msg_type<Message4<TMessage>>, nil::marshalling::option::has_do_refresh,
                     nil::marshalling::option::has_name> {
    using Base = nil::marshalling::message_base<
        TMessage, nil::marshalling::option::static_num_id_impl<MessageType4>,
        nil::marshalling::option::fields_impl<Message4Fields<typename TMessage::field_type>>,
        nil::marshalling::option::msg_type<Message4<TMessage>>, nil::marshalling::option::has_do_refresh,
        nil::marshalling::option::has_name>;

public:
    static const bool AreFieldsVersionDependent = Base::are_fields_version_dependent();
    static_assert(!AreFieldsVersionDependent, "fields_type mustn't be version dependent");

    MARSHALLING_MSG_FIELDS_ACCESS(value1, value2);

    static const std::size_t MsgMinLen = Base::eval_min_length();
    static const std::size_t MsgMaxLen = Base::eval_max_length();
    static const std::size_t MsgMinLen_1_2 = Base::template eval_min_length_from<FieldIdx_value2>();
    static const std::size_t MsgMaxLen_1_2 = Base::template eval_max_length_from<FieldIdx_value2>();

    static_assert(MsgMinLen == 1U, "Wrong serialization length");
    static_assert(MsgMaxLen == 3U, "Wrong serialization length");
    static_assert(MsgMinLen_1_2 == 0U, "Wrong serialization length");
    static_assert(MsgMaxLen_1_2 == 2U, "Wrong serialization length");

    Message4() {
        auto &optField = field_value2();
        optField.set_missing();
    }

    virtual ~Message4() noexcept = default;

    template<typename TIter>
    nil::marshalling::status_type eval_read(TIter &iter, std::size_t len) {
        auto es = Base::template eval_read_fields_until<FieldIdx_value2>(iter, len);
        if (es != nil::marshalling::status_type::success) {
            return es;
        }

        auto expectedNextFieldMode = nil::marshalling::types::optional_mode::missing;
        if ((field_value1().value() & 0x1) != 0) {
            expectedNextFieldMode = nil::marshalling::types::optional_mode::exists;
        }

        field_value2().set_mode(expectedNextFieldMode);
        return Base::template eval_read_fields_from<FieldIdx_value2>(iter, len);
    }

    bool eval_refresh() {
        auto &mask = field_value1();
        auto expectedNextFieldMode = nil::marshalling::types::optional_mode::missing;
        if ((mask.value() & 0x1) != 0) {
            expectedNextFieldMode = nil::marshalling::types::optional_mode::exists;
        }

        auto &optField = field_value2();
        if (optField.get_mode() == expectedNextFieldMode) {
            return false;
        }

        optField.set_mode(expectedNextFieldMode);
        return true;
    }

    static const char *eval_name() {
        return "Message4";
    }
};

template<typename TField>
using FieldsMessage5 = std::tuple<nil::marshalling::types::int_value<TField, std::uint16_t>,
                                  nil::marshalling::types::int_value<TField, std::int8_t>>;

template<typename TMessage>
class Message5 : public nil::marshalling::message_base<
                     TMessage, nil::marshalling::option::static_num_id_impl<MessageType5>,
                     nil::marshalling::option::fields_impl<
                         FieldsMessage5<nil::marshalling::field_type<nil::marshalling::option::big_endian>>>,
                     nil::marshalling::option::msg_type<Message5<TMessage>>, nil::marshalling::option::has_name> {
    using Base = nil::marshalling::message_base<
        TMessage, nil::marshalling::option::static_num_id_impl<MessageType5>,
        nil::marshalling::option::fields_impl<
            FieldsMessage5<nil::marshalling::field_type<nil::marshalling::option::big_endian>>>,
        nil::marshalling::option::msg_type<Message5<TMessage>>, nil::marshalling::option::has_name>;

public:
    static const bool AreFieldsVersionDependent = Base::are_fields_version_dependent();
    static_assert(!AreFieldsVersionDependent, "fields_type mustn't be version dependent");

    MARSHALLING_MSG_FIELDS_ACCESS(value1, value2);

    static const std::size_t MsgMinLen = Base::eval_min_length();
    static const std::size_t MsgMaxLen = Base::eval_max_length();
    static_assert(MsgMinLen == 3U, "Wrong serialization length");
    static_assert(MsgMaxLen == 3U, "Wrong serialization length");

    Message5() = default;

    virtual ~Message5() noexcept = default;

    static const char *eval_name() {
        return "Message5";
    }
};

template<typename TField>
struct Message6Fields {
    class field
        : public nil::marshalling::types::bundle<
              TField,
              std::tuple<nil::marshalling::types::bitmask_value<TField, nil::marshalling::option::fixed_length<1>>,
                         nil::marshalling::types::optional<nil::marshalling::types::int_value<TField, std::uint16_t>,
                                                           nil::marshalling::option::missing_by_default>>,
              nil::marshalling::option::has_custom_read, nil::marshalling::option::has_custom_refresh> {
        using Base = nil::marshalling::types::bundle<
            TField,
            std::tuple<nil::marshalling::types::bitmask_value<TField, nil::marshalling::option::fixed_length<1>>,
                       nil::marshalling::types::optional<nil::marshalling::types::int_value<TField, std::uint16_t>,
                                                         nil::marshalling::option::missing_by_default>>,
            nil::marshalling::option::has_custom_read, nil::marshalling::option::has_custom_refresh>;

    public:
        MARSHALLING_FIELD_MEMBERS_ACCESS(mask, val);

        template<typename TIter>
        nil::marshalling::status_type read(TIter &iter, std::size_t len) {
            auto es = field_mask().read(iter, len);
            if (es != nil::marshalling::status_type::success) {
                return es;
            }

            nil::marshalling::types::optional_mode mode = nil::marshalling::types::optional_mode::missing;
            if ((field_mask().value() & 0x1) != 0) {
                mode = nil::marshalling::types::optional_mode::exists;
            }

            field_val().set_mode(mode);
            return field_val().read(iter, len - field_mask().length());
        }

        bool refresh() {
            nil::marshalling::types::optional_mode mode = nil::marshalling::types::optional_mode::missing;
            if ((field_mask().value() & 0x1) != 0) {
                mode = nil::marshalling::types::optional_mode::exists;
            }

            if (mode == field_val().get_mode()) {
                return false;
            }

            field_val().set_mode(mode);
            return true;
        }
    };

    using All = std::tuple<field>;
};

template<typename TMessage>
class Message6 : public nil::marshalling::message_base<
                     TMessage, nil::marshalling::option::static_num_id_impl<MessageType6>,
                     nil::marshalling::option::fields_impl<typename Message6Fields<typename TMessage::field_type>::All>,
                     nil::marshalling::option::msg_type<Message6<TMessage>>, nil::marshalling::option::has_name> {
    using Base = nil::marshalling::message_base<
        TMessage, nil::marshalling::option::static_num_id_impl<MessageType6>,
        nil::marshalling::option::fields_impl<typename Message6Fields<typename TMessage::field_type>::All>,
        nil::marshalling::option::msg_type<Message6<TMessage>>, nil::marshalling::option::has_name>;

public:
    static const bool AreFieldsVersionDependent = Base::are_fields_version_dependent();
    static_assert(!AreFieldsVersionDependent, "fields_type mustn't be version dependent");

    MARSHALLING_MSG_FIELDS_ACCESS(value1);

    static const std::size_t MsgMinLen = Base::eval_min_length();
    static const std::size_t MsgMaxLen = Base::eval_max_length();
    static_assert(MsgMinLen == 1U, "Wrong serialization length");
    static_assert(MsgMaxLen == 3U, "Wrong serialization length");

    Message6() = default;

    ~Message6() noexcept = default;

    static const char *eval_name() {
        return "Message6";
    }
};

template<typename TField>
struct Message7Fields {
    using field1 = nil::marshalling::types::int_value<TField, std::uint16_t>;

    using field2 = nil::marshalling::types::optional<nil::marshalling::types::int_value<TField, std::uint16_t>,
                                                     nil::marshalling::option::exists_by_default,
                                                     nil::marshalling::option::exists_between_versions<5, 10>>;

    static_assert(field2::is_version_dependent(), "field2 must be version dependent");

    using All = std::tuple<field1, field2>;
};

template<typename TMessage>
class Message7 : public nil::marshalling::message_base<
                     TMessage, nil::marshalling::option::static_num_id_impl<MessageType7>,
                     nil::marshalling::option::fields_impl<typename Message7Fields<typename TMessage::field_type>::All>,
                     nil::marshalling::option::msg_type<Message7<TMessage>>, nil::marshalling::option::has_name> {
    using Base = nil::marshalling::message_base<
        TMessage, nil::marshalling::option::static_num_id_impl<MessageType7>,
        nil::marshalling::option::fields_impl<typename Message7Fields<typename TMessage::field_type>::All>,
        nil::marshalling::option::msg_type<Message7<TMessage>>, nil::marshalling::option::has_name>;

public:
    static const bool AreFieldsVersionDependent = Base::are_fields_version_dependent();
    static_assert(AreFieldsVersionDependent, "fields_type must be version dependent");

    MARSHALLING_MSG_FIELDS_ACCESS(value1, value2);

    static const std::size_t MsgMinLen = Base::eval_min_length();
    static const std::size_t MsgMaxLen = Base::eval_max_length();
    static_assert(MsgMinLen == 2U, "Wrong serialization length");
    static_assert(MsgMaxLen == 4U, "Wrong serialization length");

    Message7() = default;

    ~Message7() noexcept = default;

    static const char *eval_name() {
        return "Message7";
    }
};

template<typename TMessage>
using all_messages_type = std::tuple<Message1<TMessage>, Message2<TMessage>, Message3<TMessage>>;

template<typename TProtStack>
typename TProtStack::msg_ptr_type
    common_read_write_msg_test(TProtStack &stack, const char *const buf, std::size_t bufSize,
                               nil::marshalling::status_type expectedEs = nil::marshalling::status_type::success) {
    using msg_ptr_type = typename TProtStack::msg_ptr_type;

    msg_ptr_type msg;
    auto readIter = buf;
    auto es = stack.read(msg, readIter, bufSize);
    BOOST_CHECK(es == expectedEs);
    if (es != nil::marshalling::status_type::success) {
        return std::move(msg);
    }

    BOOST_CHECK(msg);

    auto actualBufSize = static_cast<std::size_t>(std::distance(buf, readIter));
    BOOST_CHECK(actualBufSize == stack.length(*msg));
    std::unique_ptr<char[]> outCheckBuf(new char[actualBufSize]);
    auto writeIter = &outCheckBuf[0];
    es = stack.write(*msg, writeIter, actualBufSize);
    BOOST_CHECK(es == nil::marshalling::status_type::success);
    BOOST_CHECK(std::equal(buf, buf + actualBufSize, static_cast<const char *>(&outCheckBuf[0])));
    return std::move(msg);
}

template<typename TProtStack>
typename TProtStack::msg_ptr_type
    common_read_write_msg_test(TProtStack &stack, typename TProtStack::all_fields_type &fields, const char *const buf,
                               std::size_t bufSize,
                               nil::marshalling::status_type expectedEs = nil::marshalling::status_type::success) {
    using msg_ptr_type = typename TProtStack::msg_ptr_type;

    msg_ptr_type msg;
    auto readIter = buf;
    auto es = stack.read_fields_cached(fields, msg, readIter, bufSize);
    BOOST_CHECK(es == expectedEs);
    if (es != nil::marshalling::status_type::success) {
        return std::move(msg);
    }

    BOOST_CHECK(msg);

    auto actualBufSize = static_cast<std::size_t>(std::distance(buf, readIter));
    BOOST_CHECK(actualBufSize == stack.length(*msg));
    std::unique_ptr<char[]> outCheckBuf(new char[actualBufSize]);
    auto writeIter = &outCheckBuf[0];
    typename TProtStack::all_fields_type writtenFields;
    es = stack.write_fields_cached(writtenFields, *msg, writeIter, actualBufSize);
    BOOST_CHECK(es == nil::marshalling::status_type::success);
    BOOST_CHECK(std::equal(buf, buf + actualBufSize, static_cast<const char *>(&outCheckBuf[0])));
    BOOST_CHECK(fields == writtenFields);
    return std::move(msg);
}

template<typename TProtStack>
typename TProtStack::msg_ptr_type vectorBackInsertReadWriteMsgTest(TProtStack &stack, const char *const buf,
                                                                   std::size_t bufSize,
                                                                   nil::marshalling::status_type expectedEs
                                                                   = nil::marshalling::status_type::success) {
    using msg_ptr_type = typename TProtStack::msg_ptr_type;

    msg_ptr_type msg;
    auto readIter = buf;
    auto es = stack.read(msg, readIter, bufSize);
    BOOST_CHECK(es == expectedEs);
    if (es != nil::marshalling::status_type::success) {
        return std::move(msg);
    }

    BOOST_CHECK(msg);

    auto actualBufSize = static_cast<std::size_t>(std::distance(buf, readIter));
    BOOST_CHECK(actualBufSize == stack.length(*msg));
    std::vector<char> outCheckBuf;
    auto writeIter = std::back_inserter(outCheckBuf);
    es = stack.write(*msg, writeIter, actualBufSize);
    if (es == nil::marshalling::status_type::update_required) {
        assert(!outCheckBuf.empty());
        auto updateIter = &outCheckBuf[0];
        es = stack.update(updateIter, actualBufSize);
    }
    BOOST_CHECK(es == nil::marshalling::status_type::success);
    BOOST_CHECK(outCheckBuf.size() == actualBufSize);
    BOOST_CHECK(outCheckBuf.size() == stack.length(*msg));
    bool resultAsExpected = std::equal(buf, buf + actualBufSize, outCheckBuf.cbegin());
    if (!resultAsExpected) {
        std::cout << "Original buffer:\n\t" << std::hex;
        std::copy_n(buf, actualBufSize, std::ostream_iterator<unsigned>(std::cout, " "));
        std::cout << "\n\nWritten buffer:\n\t";
        std::copy_n(&outCheckBuf[0], actualBufSize, std::ostream_iterator<unsigned>(std::cout, " "));
        std::cout << std::dec << std::endl;
    }
    BOOST_CHECK(resultAsExpected);
    return std::move(msg);
}

template<typename TProtStack, typename TMessage>
void common_write_read_msg_test(TProtStack &stack, TMessage msg, char *buf, std::size_t bufSize,
                                const char *expectedBuf,
                                nil::marshalling::status_type expectedEs = nil::marshalling::status_type::success) {
    auto writeIter = buf;
    auto es = stack.write(msg, writeIter, bufSize);
    BOOST_CHECK(es == expectedEs);
    if (es != nil::marshalling::status_type::success) {
        return;
    }

    assert(expectedBuf != nullptr);
    auto constBuf = static_cast<const char *>(buf);
    BOOST_CHECK(std::equal(constBuf, constBuf + bufSize, &expectedBuf[0]));

    using msg_ptr_type = typename TProtStack::msg_ptr_type;
    msg_ptr_type msgPtr;
    auto readIter = expectedBuf;
    es = stack.read(msgPtr, readIter, bufSize);
    BOOST_CHECK(es == nil::marshalling::status_type::success);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == msg.get_id());
    auto *castedMsg = dynamic_cast<TMessage *>(msgPtr.get());
    BOOST_CHECK(castedMsg != nullptr);
    BOOST_CHECK(*castedMsg == msg);
}

template<typename TProtStack, typename TMessage>
void vector_back_insert_write_read_msg_test(TProtStack &stack, TMessage msg, const char *expectedBuf,
                                            std::size_t bufSize,
                                            nil::marshalling::status_type expectedEs
                                            = nil::marshalling::status_type::success) {
    std::vector<char> buf;
    auto writeIter = std::back_inserter(buf);
    auto es = stack.write(msg, writeIter, buf.max_size());
    if (expectedEs != nil::marshalling::status_type::success) {
        BOOST_CHECK(es == expectedEs);
        return;
    }

    if (es == nil::marshalling::status_type::update_required) {
        auto updateIter = &buf[0];
        es = stack.update(updateIter, buf.size());
        BOOST_CHECK(es == nil::marshalling::status_type::success);
    }

    BOOST_CHECK(es == expectedEs);
    if (es != nil::marshalling::status_type::success) {
        return;
    }

    assert(expectedBuf != nullptr);
    BOOST_CHECK(buf.size() == bufSize);
    bool bufEquals = std::equal(buf.cbegin(), buf.cend(), &expectedBuf[0]);
    if (!bufEquals) {
        std::cout << "ERROR: Buffers are not equal:\nexpected: " << std::hex;
        std::copy_n(&expectedBuf[0], bufSize, std::ostream_iterator<unsigned>(std::cout, " "));
        std::cout << "\nwritten: ";
        std::copy(buf.cbegin(), buf.cend(), std::ostream_iterator<unsigned>(std::cout, " "));
        std::cout << std::dec << std::endl;
    }
    BOOST_CHECK(bufEquals);

    using msg_ptr_type = typename TProtStack::msg_ptr_type;
    msg_ptr_type msgPtr;
    const char *readIter = &buf[0];
    es = stack.read(msgPtr, readIter, buf.size());
    BOOST_CHECK(es == nil::marshalling::status_type::success);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == msg.get_id());
    auto *castedMsg = dynamic_cast<TMessage *>(msgPtr.get());
    BOOST_CHECK(castedMsg != nullptr);
    BOOST_CHECK(*castedMsg == msg);
}

template<typename TProtStack, typename TMsg>
void common_read_write_msg_direct_test(TProtStack &stack, TMsg &msg, const char *const buf, std::size_t bufSize,
                                       nil::marshalling::status_type expectedEs
                                       = nil::marshalling::status_type::success) {
    auto readIter = buf;
    auto es = stack.read(msg, readIter, bufSize);
    BOOST_CHECK(es == expectedEs);
    if (es != nil::marshalling::status_type::success) {
        return;
    }

    auto actualBufSize = static_cast<std::size_t>(std::distance(buf, readIter));
    BOOST_CHECK(actualBufSize == stack.length(msg));
    std::unique_ptr<char[]> outCheckBuf(new char[actualBufSize]);
    auto writeIter = &outCheckBuf[0];
    es = stack.write(msg, writeIter, actualBufSize);
    BOOST_CHECK(es == nil::marshalling::status_type::success);
    BOOST_CHECK(std::equal(buf, buf + actualBufSize, static_cast<const char *>(&outCheckBuf[0])));
}

template<typename TProtStack, typename TMsg>
void common_read_write_msg_direct_test(TProtStack &stack, typename TProtStack::all_fields_type &fields, TMsg &msg,
                                       const char *const buf, std::size_t bufSize,
                                       nil::marshalling::status_type expectedEs
                                       = nil::marshalling::status_type::success) {
    auto readIter = buf;
    auto es = stack.read_fields_cached(fields, msg, readIter, bufSize);
    BOOST_CHECK(es == expectedEs);
    if (es != nil::marshalling::status_type::success) {
        return;
    }

    auto actualBufSize = static_cast<std::size_t>(std::distance(buf, readIter));
    BOOST_CHECK(actualBufSize == stack.length(msg));
    std::unique_ptr<char[]> outCheckBuf(new char[actualBufSize]);
    typename TProtStack::all_fields_type writtenFields;
    auto writeIter = &outCheckBuf[0];
    es = stack.write_fields_cached(writtenFields, msg, writeIter, actualBufSize);
    BOOST_CHECK(es == nil::marshalling::status_type::success);
    BOOST_CHECK(fields == writtenFields);
    BOOST_CHECK(std::equal(buf, buf + actualBufSize, static_cast<const char *>(&outCheckBuf[0])));
}

#endif    // MARSHALLING_TEST_COMMON_HPP
