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

#define BOOST_TEST_MODULE marshalling_msg_id_layer_test

#include "test_common.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>

#include <nil/marshalling/types/enum_value.hpp>

#include <nil/marshalling/protocol/msg_data_layer.hpp>
#include <nil/marshalling/protocol/msg_id_layer.hpp>

struct common_traits {
    typedef message_type msg_id_type;
    typedef const char *read_iterator;
    typedef char *write_iterator;
};

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::id_info_interface,
                   nil::marshalling::option::read_iterator<const char *>,
                   nil::marshalling::option::write_iterator<char *>, nil::marshalling::option::valid_check_interface,
                   nil::marshalling::option::length_info_interface>
    common_options;

typedef std::tuple<nil::marshalling::option::big_endian, common_options> BeTraits;

typedef std::tuple<nil::marshalling::option::little_endian, common_options> LeTraits;

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::big_endian>
    NonPolymorphicBigEndianTraits;

typedef TestMessageBase<BeTraits> BeMsgBase;
typedef TestMessageBase<LeTraits> LeMsgBase;
typedef nil::marshalling::message<NonPolymorphicBigEndianTraits> BeNonPolymorphicMessageBase;

typedef BeMsgBase::field_type BeField;
typedef LeMsgBase::field_type LeField;

typedef Message1<BeMsgBase> BeMsg1;
typedef Message1<LeMsgBase> LeMsg1;
typedef Message2<BeMsgBase> BeMsg2;
typedef Message2<LeMsgBase> LeMsg2;
typedef Message3<BeMsgBase> BeMsg3;
typedef Message3<LeMsgBase> LeMsg3;
typedef Message1<BeNonPolymorphicMessageBase> NonPolymorphicBeMsg1;
typedef Message2<BeNonPolymorphicMessageBase> NonPolymorphicBeMsg2;

template<typename TField>
using Field1 = nil::marshalling::types::enum_value<TField, message_type, nil::marshalling::option::fixed_length<1>>;

template<typename TField>
using Field2 = nil::marshalling::types::enum_value<TField, message_type, nil::marshalling::option::fixed_length<2>>;

template<typename TField>
using Field3 = nil::marshalling::types::enum_value<TField, message_type, nil::marshalling::option::fixed_length<3>>;

typedef Field1<BeField> BeField1;
typedef Field1<LeField> LeField1;
typedef Field2<BeField> BeField2;
typedef Field2<LeField> LeField2;
typedef Field3<BeField> BeField3;
typedef Field3<LeField> LeField3;

template<typename TField, typename TMessage>
class ProtocolStack : public nil::marshalling::protocol::msg_id_layer<TField, TMessage, all_messages_type<TMessage>,
                                                                      nil::marshalling::protocol::msg_data_layer<>> {
#ifdef MARSHALLING_MUST_DEFINE_BASE
    using Base = nil::marshalling::protocol::msg_id_layer<TField, TMessage, all_messages_type<TMessage>,
                                                          nil::marshalling::protocol::msg_data_layer<>>;
#endif
public:
    MARSHALLING_PROTOCOL_LAYERS_ACCESS_OUTER(id, payload);
};

template<typename TField, typename TMessage>
class InPlaceProtocolStack
    : public nil::marshalling::protocol::msg_id_layer<TField, TMessage, all_messages_type<TMessage>,
                                                      nil::marshalling::protocol::msg_data_layer<>,
                                                      nil::marshalling::option::in_place_allocation> {
#ifdef MARSHALLING_MUST_DEFINE_BASE
    using Base = nil::marshalling::protocol::msg_id_layer<TField, TMessage, all_messages_type<TMessage>,
                                                          nil::marshalling::protocol::msg_data_layer<>,
                                                          nil::marshalling::option::in_place_allocation>;
#endif
public:
    MARSHALLING_PROTOCOL_LAYERS_ACCESS(payload, id);
};

BOOST_AUTO_TEST_SUITE(msg_id_layer_test_suite)

BOOST_AUTO_TEST_CASE(test1) {
    static const char Buf[] = {MessageType1, 0x01, 0x02};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    ProtocolStack<BeField1, BeMsgBase> stack;
    static_cast<void>(stack.layer_id());
    auto &payloadLayer = stack.layer_payload();
    using PayloadLayerType = typename std::decay<decltype(payloadLayer)>::type;
    static_assert(nil::marshalling::protocol::is_msg_data_layer<PayloadLayerType>(), "Invalid layer");

    auto &idLayer = static_cast<const ProtocolStack<BeField1, BeMsgBase> &>(stack).layer_id();
    using IdLayerType = typename std::decay<decltype(idLayer)>::type;
    static_assert(nil::marshalling::protocol::is_msg_id_layer<IdLayerType>(), "Invalid layer");

    auto msgPtr = common_read_write_msg_test(stack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == MessageType1);
    auto &msg1 = dynamic_cast<BeMsg1 &>(*msgPtr);
    BOOST_CHECK(std::get<0>(msg1.fields()).value() == 0x0102);

    InPlaceProtocolStack<BeField1, BeMsgBase> inPlaceStack;
    auto &inPlacePayloadLayer = inPlaceStack.layer_payload();
    using InPlacePayloadLayerType = typename std::decay<decltype(inPlacePayloadLayer)>::type;
    static_assert(nil::marshalling::protocol::is_msg_data_layer<InPlacePayloadLayerType>(), "Invalid layer");

    auto &inPlaceIdLayer = static_cast<const InPlaceProtocolStack<BeField1, BeMsgBase> &>(inPlaceStack).layer_id();
    using InPlaceIdLayerType = typename std::decay<decltype(inPlaceIdLayer)>::type;
    static_assert(nil::marshalling::protocol::is_msg_id_layer<InPlaceIdLayerType>(), "Invalid layer");

    auto msgPtr2 = common_read_write_msg_test(inPlaceStack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr2);
    BOOST_CHECK(msgPtr2->get_id() == MessageType1);
    auto &msg2 = dynamic_cast<BeMsg1 &>(*msgPtr2);
    BOOST_CHECK(std::get<0>(msg2.fields()).value() == 0x0102);

    BOOST_CHECK(msg1 == msg2);

    auto msgPtr3
        = common_read_write_msg_test(inPlaceStack, &Buf[0], BufSize, nil::marshalling::status_type::msg_alloc_failure);
    BOOST_CHECK(!msgPtr3);
}

BOOST_AUTO_TEST_CASE(test2) {
    BeMsg1 msg;
    std::get<0>(msg.fields()).value() = 0x0203;

    static const char ExpectedBuf[] = {0x0, MessageType1, 0x02, 0x03};

    static const std::size_t BufSize = std::extent<decltype(ExpectedBuf)>::value;

    char buf[BufSize] = {0};

    ProtocolStack<BeField2, BeMsgBase> stack;
    common_write_read_msg_test(stack, msg, buf, BufSize, &ExpectedBuf[0]);

    InPlaceProtocolStack<BeField2, BeMsgBase> inPlaceStack;
    common_write_read_msg_test(inPlaceStack, msg, buf, BufSize, &ExpectedBuf[0]);
}

BOOST_AUTO_TEST_CASE(test3) {
    static const char Buf[] = {MessageType2, 0, 0};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    ProtocolStack<LeField3, LeMsgBase> stack;

    auto msgPtr = common_read_write_msg_test(stack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == MessageType2);
    auto &msg1 = dynamic_cast<LeMsg2 &>(*msgPtr);

    InPlaceProtocolStack<LeField3, LeMsgBase> inPlaceStack;
    auto msgPtr2 = common_read_write_msg_test(inPlaceStack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr2);
    BOOST_CHECK(msgPtr2->get_id() == MessageType2);
    auto &msg2 = dynamic_cast<LeMsg2 &>(*msgPtr2);
    BOOST_CHECK(msg1 == msg2);

    auto msgPtr3
        = common_read_write_msg_test(inPlaceStack, &Buf[0], BufSize, nil::marshalling::status_type::msg_alloc_failure);
    BOOST_CHECK(!msgPtr3);
}

BOOST_AUTO_TEST_CASE(test4) {
    static const char Buf[] = {0x0, UnusedValue1, 0x00, 0x00};

    static const auto BufSize = std::extent<decltype(Buf)>::value;

    ProtocolStack<BeField2, BeMsgBase> stack;
    auto msgPtr = common_read_write_msg_test(stack, Buf, BufSize, nil::marshalling::status_type::invalid_msg_id);
    BOOST_CHECK(!msgPtr);

    InPlaceProtocolStack<BeField2, BeMsgBase> inPlaceStack;
    auto inPlaceMsgPtr
        = common_read_write_msg_test(inPlaceStack, Buf, BufSize, nil::marshalling::status_type::invalid_msg_id);
    BOOST_CHECK(!inPlaceMsgPtr);
}

BOOST_AUTO_TEST_CASE(test5) {
    BeMsg1 msg;
    std::get<0>(msg.fields()).value() = 0x0203;

    char buf[2] = {0};
    static const auto BufSize = std::extent<decltype(buf)>::value;

    ProtocolStack<BeField3, BeMsgBase> stack;
    common_write_read_msg_test(stack, msg, buf, BufSize, nullptr, nil::marshalling::status_type::buffer_overflow);

    InPlaceProtocolStack<BeField3, BeMsgBase> inPlaceStack;
    common_write_read_msg_test(inPlaceStack, msg, buf, BufSize, nullptr,
                               nil::marshalling::status_type::buffer_overflow);
}

BOOST_AUTO_TEST_CASE(test6) {
    ProtocolStack<BeField2, BeMsgBase> stack;

    auto msgPtr = stack.create_msg(MessageType3);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == MessageType3);
    BOOST_CHECK(!msgPtr->valid());
    auto *msg3 = dynamic_cast<BeMsg3 *>(msgPtr.get());
    BOOST_CHECK(msg3 != nullptr);
}

BOOST_AUTO_TEST_CASE(test7) {
    static const char Buf[] = {MessageType1, 0x0, 0x01, 0x02};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    typedef ProtocolStack<LeField2, LeMsgBase> ProtStack;
    ProtStack::all_fields_type fields;
    ProtStack stack;

    auto msgPtr = common_read_write_msg_test(stack, fields, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == MessageType1);
    auto &msg1 = dynamic_cast<LeMsg1 &>(*msgPtr);
    BOOST_CHECK(std::get<0>(msg1.fields()).value() == 0x0201);
    BOOST_CHECK(stack.access_cached_field(fields).value() == MessageType1);
    BOOST_CHECK(stack.next_layer().access_cached_field(fields).value() == std::vector<std::uint8_t>({0x01, 0x02}));

    typedef InPlaceProtocolStack<LeField2, LeMsgBase> InPlaceProtStack;
    InPlaceProtStack::all_fields_type fields2;
    InPlaceProtStack inPlaceStack;
    auto msgPtr2 = common_read_write_msg_test(inPlaceStack, fields2, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr2);
    BOOST_CHECK(msgPtr2->get_id() == MessageType1);
    auto &msg2 = dynamic_cast<LeMsg1 &>(*msgPtr2);
    BOOST_CHECK(std::get<0>(msg2.fields()).value() == 0x0201);

    BOOST_CHECK(msg1 == msg2);
    BOOST_CHECK(fields == fields2);
}

BOOST_AUTO_TEST_CASE(test8) {
    static const char Buf[] = {MessageType1, 0x01, 0x02};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    using ProtStack = ProtocolStack<BeField1, BeNonPolymorphicMessageBase>;
    ProtStack stack;
    NonPolymorphicBeMsg1 msg;
    BOOST_CHECK(msg.eval_get_id() == MessageType1);
    common_read_write_msg_direct_test(stack, msg, &Buf[0], BufSize);
    BOOST_CHECK(std::get<0>(msg.fields()).value() == 0x0102);

    ProtStack::all_fields_type fields;
    common_read_write_msg_direct_test(stack, fields, msg, &Buf[0], BufSize);
    BOOST_CHECK(std::get<0>(fields).value() == MessageType1);

    NonPolymorphicBeMsg2 msg2;
    BOOST_CHECK(msg2.eval_get_id() == MessageType2);
    common_read_write_msg_direct_test(stack, msg2, &Buf[0], BufSize, nil::marshalling::status_type::invalid_msg_id);

    ProtStack::all_fields_type fields2;
    std::get<0>(fields2).value() = MessageType5;    // just to make sure it is updated.
    common_read_write_msg_direct_test(stack, fields2, msg2, &Buf[0], BufSize,
                                      nil::marshalling::status_type::invalid_msg_id);
    BOOST_CHECK(std::get<0>(fields2).value() == MessageType1);
}

BOOST_AUTO_TEST_SUITE_END()