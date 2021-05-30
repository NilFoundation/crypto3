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

#define BOOST_TEST_MODULE marshalling_msg_data_layer_test

#include "test_common.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <memory>

#include <nil/marshalling/protocol/msg_data_layer.hpp>

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::big_endian,
                   nil::marshalling::option::read_iterator<const char *>,
                   nil::marshalling::option::write_iterator<char *>, nil::marshalling::option::length_info_interface>
    BigEndianTraits;

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::big_endian,
                   nil::marshalling::option::read_iterator<const char *>,
                   nil::marshalling::option::write_iterator<std::back_insert_iterator<std::vector<char>>>,
                   nil::marshalling::option::length_info_interface>
    BackInserterBigEndianTraits;

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::little_endian,
                   nil::marshalling::option::read_iterator<const char *>,
                   nil::marshalling::option::write_iterator<char *>, nil::marshalling::option::length_info_interface>
    LittleEndianTraits;

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::little_endian,
                   nil::marshalling::option::read_iterator<const char *>,
                   nil::marshalling::option::write_iterator<std::back_insert_iterator<std::vector<char>>>,
                   nil::marshalling::option::length_info_interface>
    BackInserterLittleEndianTraits;

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::big_endian>
    NonPolymorphicBigEndianTraits;

typedef nil::marshalling::message<BigEndianTraits> BeMessageBase;
typedef nil::marshalling::message<BackInserterBigEndianTraits> BackInsertBeMessageBase;
typedef nil::marshalling::message<LittleEndianTraits> LeMessageBase;
typedef nil::marshalling::message<BackInserterLittleEndianTraits> BackInsertLeMessageBase;
typedef nil::marshalling::message<NonPolymorphicBigEndianTraits> BeNonPolymorphicMessageBase;

typedef Message1<BeMessageBase> BeMsg1;
typedef Message1<BackInsertBeMessageBase> BackInsertBeMsg1;
typedef Message1<LeMessageBase> LeMsg1;
typedef Message1<BackInsertLeMessageBase> BackInsertLeMsg1;

typedef Message2<BeMessageBase> BeMsg2;
typedef Message2<LeMessageBase> LeMsg2;

typedef Message3<BeMessageBase> BeMsg3;
typedef Message3<LeMessageBase> LeMsg3;

typedef Message1<BeNonPolymorphicMessageBase> NonPolymorphicBeMsg1;

#ifndef CC_COMPILER_GCC47

template<typename TMessage>
class ProtocolStack : public nil::marshalling::protocol::msg_data_layer<> {
#ifdef MARSHALLING_MUST_DEFINE_BASE
    using Base = nil::marshalling::protocol::msg_data_layer<>;
#endif
public:
    MARSHALLING_PROTOCOL_LAYERS_ACCESS(payload);
};

#else
template<typename TMessage>
using ProtocolStack = nil::marshalling::protocol::msg_data_layer<>;
#endif

template<typename TMessage>
TMessage internal_read_write_test(const char *const buf, std::size_t bufSize,
                                  nil::marshalling::status_type expectedErrStatus
                                  = nil::marshalling::status_type::success) {
    typedef TMessage Message;

    typedef typename std::conditional<std::is_base_of<BeMessageBase, Message>::value, ProtocolStack<BeMessageBase>,
                                      ProtocolStack<LeMessageBase>>::type ProtStack;

    ProtStack stack;
#ifndef CC_COMPILER_GCC47
    static_cast<void>(stack.layer_payload());    // check generation of access func
#endif

    auto readIter = buf;
    std::unique_ptr<Message> msg(new Message);
    auto es = stack.read(msg, readIter, bufSize);
    BOOST_CHECK(es == expectedErrStatus);

    if (es == nil::marshalling::status_type::success) {
        auto diff = static_cast<std::size_t>(std::distance(buf, readIter));
        std::unique_ptr<char[]> outDataBuf(new char[diff]);
        auto writeIter = &outDataBuf[0];
        auto writeES = stack.write(*msg, writeIter, diff);
        BOOST_CHECK(writeES == nil::marshalling::status_type::success);
        BOOST_CHECK(std::equal(buf, buf + diff, &outDataBuf[0]));
    }

    return *msg;
}

template<typename TMessage>
TMessage internal_read_write_to_vector_test(const char *const buf, std::size_t bufSize,
                                            nil::marshalling::status_type expectedErrStatus
                                            = nil::marshalling::status_type::success) {
    typedef TMessage Message;

    typedef
        typename std::conditional<std::is_base_of<BackInsertBeMessageBase, Message>::value,
                                  ProtocolStack<BackInsertBeMessageBase>, ProtocolStack<BackInsertLeMessageBase>>::type
            ProtStack;

    ProtStack stack;
    static_cast<void>(stack);
    auto readIter = buf;
    std::unique_ptr<Message> msg(new Message);
    auto es = stack.read(msg, readIter, bufSize);
    BOOST_CHECK(es == expectedErrStatus);

    if (es == nil::marshalling::status_type::success) {
        auto diff = static_cast<std::size_t>(std::distance(buf, readIter));
        std::vector<char> outDataBuf;
        auto writeIter = std::back_inserter(outDataBuf);
        auto writeES = stack.write(*msg, writeIter, diff);
        BOOST_CHECK(writeES == nil::marshalling::status_type::success);
        BOOST_CHECK(diff == outDataBuf.size());
        BOOST_CHECK(std::equal(buf, buf + diff, &outDataBuf[0]));
    }

    return *msg;
}

template<typename TMessage>
TMessage internal_read_write_cached_test(const char *const buf, std::size_t bufSize,
                                         nil::marshalling::status_type expectedErrStatus
                                         = nil::marshalling::status_type::success) {
    using Interface = typename std::decay<decltype(nil::marshalling::to_message(std::declval<TMessage>()))>::type;
    using ProtStack = ProtocolStack<Interface>;

    ProtStack stack;
    static_cast<void>(stack);
    typename ProtStack::all_fields_type allFields;
    auto readIter = buf;
    std::unique_ptr<TMessage> msg(new TMessage);
    auto es = stack.read_from_data_fields_cached(allFields, msg, readIter, bufSize);
    BOOST_CHECK(es == expectedErrStatus);
    auto &dataField = std::get<0>(allFields);
    auto &dataFieldVec = dataField.value();

    if (es == nil::marshalling::status_type::success) {
        auto diff = static_cast<std::size_t>(std::distance(buf, readIter));
        BOOST_CHECK(dataFieldVec.size() == diff);
        BOOST_CHECK(std::equal(buf, buf + diff, dataFieldVec.begin()));

        std::unique_ptr<char[]> outDataBuf(new char[diff]);
        auto writeIter = &outDataBuf[0];
        typename ProtStack::all_fields_type allOutFields;
        auto writeES = stack.write_fields_cached(allOutFields, *msg, writeIter, diff);
        BOOST_CHECK(writeES == nil::marshalling::status_type::success);
        BOOST_CHECK(std::equal(buf, buf + diff, &outDataBuf[0]));

        auto &outDataField = std::get<0>(allOutFields);
        BOOST_CHECK(dataField == outDataField);
    }

    return *msg;
}

template<typename TMessage>
void internal_write_read_test(const TMessage &msg, char *const buf, std::size_t bufSize, const char *expectedBuf,
                              nil::marshalling::status_type expectedErrStatus
                              = nil::marshalling::status_type::success) {
    typedef TMessage Message;

    typedef typename std::conditional<std::is_base_of<BeMessageBase, Message>::value, ProtocolStack<BeMessageBase>,
                                      ProtocolStack<LeMessageBase>>::type ProtStack;

    ProtStack stack;
    static_cast<void>(stack);
    auto writeIter = buf;
    auto es = stack.write(msg, writeIter, bufSize);
    BOOST_CHECK(es == expectedErrStatus);

    if (es == nil::marshalling::status_type::success) {
        auto diff = static_cast<std::size_t>(std::distance(buf, writeIter));
        BOOST_CHECK(expectedBuf != 0);
        BOOST_CHECK(std::equal(expectedBuf, expectedBuf + diff, buf));

        std::unique_ptr<Message> readMsgPtr(new Message);
        auto readIter = static_cast<const char *>(buf);
        auto readES = stack.read(readMsgPtr, readIter, diff);
        BOOST_CHECK(readES == nil::marshalling::status_type::success);
        BOOST_CHECK(msg == *readMsgPtr);
    }
}

template<typename TMessage>
void internal_direct_read_write_test(TMessage &msg, const char *const buf, std::size_t bufSize,
                                     nil::marshalling::status_type expectedErrStatus
                                     = nil::marshalling::status_type::success) {
    using InterfaceType = typename std::decay<decltype(nil::marshalling::to_message(msg))>::type;
    using ProtStack = ProtocolStack<InterfaceType>;
    ProtStack stack;
    static_cast<void>(stack);
    auto readIter = buf;
    auto es = stack.read(msg, readIter, bufSize);
    BOOST_CHECK(es == expectedErrStatus);

    if (es == nil::marshalling::status_type::success) {
        auto diff = static_cast<std::size_t>(std::distance(buf, readIter));
        std::unique_ptr<char[]> outDataBuf(new char[diff]);
        auto writeIter = &outDataBuf[0];
        auto writeES = stack.write(msg, writeIter, diff);
        BOOST_CHECK(writeES == nil::marshalling::status_type::success);
        BOOST_CHECK(std::equal(buf, buf + diff, &outDataBuf[0]));
    }
}

BOOST_AUTO_TEST_SUITE(msg_data_layer_test_suite)

BOOST_AUTO_TEST_CASE(test1) {
    static const char Buf[] = {0x01, 0x02};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    auto msg = internal_read_write_test<BeMsg1>(Buf, BufSize);
    BOOST_CHECK(std::get<0>(msg.fields()).value() == 0x0102);
    auto msg2 = internal_read_write_to_vector_test<BackInsertBeMsg1>(Buf, BufSize);
    BOOST_CHECK(std::get<0>(msg2.fields()).value() == 0x0102);
    auto msg3 = internal_read_write_cached_test<BeMsg1>(Buf, BufSize);
    BOOST_CHECK(std::get<0>(msg3.fields()).value() == 0x0102);
}

BOOST_AUTO_TEST_CASE(test2) {
    BeMsg1 msg;
    std::get<0>(msg.fields()).value() = 0x0203;

    static const char ExpectedBuf[] = {0x02, 0x03};

    static const std::size_t BufSize = std::extent<decltype(ExpectedBuf)>::value;
    char buf[BufSize] = {0};

    internal_write_read_test(msg, buf, BufSize, &ExpectedBuf[0]);
}

BOOST_AUTO_TEST_CASE(test3) {
    const char buf[] = {0};

    auto msg = internal_read_write_test<BeMsg2>(buf, 0);
    static_cast<void>(msg);
}

BOOST_AUTO_TEST_CASE(test4) {
    LeMsg1 msg;
    std::get<0>(msg.fields()).value() = 0x0203;

    char buf[1] = {0};
    const std::size_t bufSize = std::extent<decltype(buf)>::value;

    internal_write_read_test(msg, buf, bufSize, nullptr, nil::marshalling::status_type::buffer_overflow);
}

BOOST_AUTO_TEST_CASE(test5) {
    static const char Buf[] = {0x01, 0x02};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    NonPolymorphicBeMsg1 msg;
    internal_direct_read_write_test(msg, Buf, BufSize);
    BOOST_CHECK(msg.field_value1().value() == 0x0102);
}

BOOST_AUTO_TEST_SUITE_END()