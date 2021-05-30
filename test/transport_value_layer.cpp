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

#define BOOST_TEST_MODULE marshalling_transport_value_layer

#include "test_common.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>

#include <nil/marshalling/types/enum_value.hpp>

#include <nil/marshalling/protocol/msg_size_layer.hpp>
#include <nil/marshalling/protocol/transport_value_layer.hpp>
#include <nil/marshalling/protocol/msg_id_layer.hpp>
#include <nil/marshalling/protocol/msg_data_layer.hpp>

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::id_info_interface,
                   nil::marshalling::option::big_endian, nil::marshalling::option::read_iterator<const char *>,
                   nil::marshalling::option::write_iterator<char *>, nil::marshalling::option::length_info_interface>
    BeOptions;

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::id_info_interface,
                   nil::marshalling::option::big_endian, nil::marshalling::option::read_iterator<const char *>,
                   nil::marshalling::option::write_iterator<std::back_insert_iterator<std::vector<char>>>,
                   nil::marshalling::option::length_info_interface>
    BeBackInsertOptions;

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::big_endian>
    NonPolymorphicBigEndianTraits;

using FieldBase = nil::marshalling::field_type<nil::marshalling::option::big_endian>;

using VersionField
    = nil::marshalling::types::int_value<FieldBase, std::uint16_t, nil::marshalling::option::default_num_value<5>>;

typedef std::tuple<VersionField> ExtraVersionTransport;

template<typename TOptions = nil::marshalling::option::empty_option>
struct ExtraTransportMessageBase
    : public nil::marshalling::message<TOptions,
                                       nil::marshalling::option::extra_transport_fields<ExtraVersionTransport>> {
    using Base
        = nil::marshalling::message<TOptions, nil::marshalling::option::extra_transport_fields<ExtraVersionTransport>>;

public:
    MARSHALLING_MSG_TRANSPORT_FIELDS_ACCESS(version);
};

typedef ExtraTransportMessageBase<NonPolymorphicBigEndianTraits> BeNonPolymorphicMessageBase;

typedef Message1<BeNonPolymorphicMessageBase> NonPolymorphicBeMsg1;
typedef Message2<BeNonPolymorphicMessageBase> NonPolymorphicBeMsg2;

using SizeField = nil::marshalling::types::int_value<FieldBase, std::uint16_t>;

using IdField = nil::marshalling::types::enum_value<FieldBase, message_type, nil::marshalling::option::fixed_length<2>>;

template<typename TMessage>
using BeforeIdProtocolStack = nil::marshalling::protocol::msg_size_layer<
    SizeField, nil::marshalling::protocol::transport_value_layer<
                   VersionField, ExtraTransportMessageBase<>::TransportFieldIdx_version,
                   nil::marshalling::protocol::msg_id_layer<IdField, TMessage, all_messages_type<TMessage>,
                                                            nil::marshalling::protocol::msg_data_layer<>>>>;

template<typename TMessage>
using NoVersionProtocolStack = nil::marshalling::protocol::msg_size_layer<
    SizeField, nil::marshalling::protocol::msg_id_layer<IdField, TMessage, all_messages_type<TMessage>,
                                                        nil::marshalling::protocol::msg_data_layer<>>>;

template<typename TMessage, typename... TOpt>
using AfterIdProtocolStack = nil::marshalling::protocol::msg_size_layer<
    SizeField,
    nil::marshalling::protocol::msg_id_layer<IdField, TMessage, all_messages_type<TMessage>,
                                             nil::marshalling::protocol::transport_value_layer<
                                                 VersionField, ExtraTransportMessageBase<>::TransportFieldIdx_version,
                                                 nil::marshalling::protocol::msg_data_layer<>, TOpt...>>>;

BOOST_AUTO_TEST_SUITE(transport_value_layer_test_suite)

BOOST_AUTO_TEST_CASE(test1) {
    static const char Buf[] = {0x0, 0x6, 0x0, 0x4, 0x0, MessageType1, 0x01, 0x02};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    using MsgBase = ExtraTransportMessageBase<BeOptions>;
    using Stack = BeforeIdProtocolStack<MsgBase>;

    Stack stack;

    BOOST_CHECK(stack.length() == 6U);

    auto msgPtr = common_read_write_msg_test(stack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == MessageType1);
    BOOST_CHECK(msgPtr->transportField_version().value() == 4U);

    auto &msg1 = dynamic_cast<Message1<MsgBase> &>(*msgPtr);
    BOOST_CHECK(std::get<0>(msg1.fields()).value() == 0x0102);
}

BOOST_AUTO_TEST_CASE(test2) {

    static const char ExpectedBuf[] = {0x0, 0x6, 0x0, 0x5, 0x0, MessageType1, 0x01, 0x02};

    static const std::size_t BufSize = std::extent<decltype(ExpectedBuf)>::value;
    char buf[BufSize] = {0};

    using MsgBase = ExtraTransportMessageBase<BeOptions>;
    using Stack = BeforeIdProtocolStack<MsgBase>;

    Message1<MsgBase> msg;
    std::get<0>(msg.fields()).value() = 0x0102;

    Stack stack;
    common_write_read_msg_test(stack, msg, buf, BufSize, &ExpectedBuf[0]);
}

BOOST_AUTO_TEST_CASE(test3) {
    static const char Buf[] = {0x0, 0x6, 0x0, MessageType1, 0x0, 0x8, 0x01, 0x02};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    using MsgBase = ExtraTransportMessageBase<BeOptions>;
    using Stack = AfterIdProtocolStack<MsgBase>;

    Stack stack;

    BOOST_CHECK(stack.length() == 6U);

    auto msgPtr = common_read_write_msg_test(stack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == MessageType1);
    BOOST_CHECK(msgPtr->transportField_version().value() == 8U);

    auto &msg1 = dynamic_cast<Message1<MsgBase> &>(*msgPtr);
    BOOST_CHECK(std::get<0>(msg1.fields()).value() == 0x0102);
}

BOOST_AUTO_TEST_CASE(test4) {
    static const char Buf[] = {0x0, 0x6, 0x0, 0x4, 0x0, MessageType1, 0x01, 0x02};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    using Stack = BeforeIdProtocolStack<BeNonPolymorphicMessageBase>;

    Stack stack;

    BOOST_CHECK(stack.length() == 6U);

    NonPolymorphicBeMsg1 msg;
    common_read_write_msg_direct_test(stack, msg, &Buf[0], BufSize);
    BOOST_CHECK(std::get<0>(msg.fields()).value() == 0x0102);
    BOOST_CHECK(msg.transportField_version().value() == 4U);

    Stack::all_fields_type fields;
    common_read_write_msg_direct_test(stack, fields, msg, &Buf[0], BufSize);
    BOOST_CHECK(std::get<0>(fields).value() == 0x6);
    BOOST_CHECK(std::get<1>(fields).value() == 0x4);
    BOOST_CHECK(std::get<2>(fields).value() == MessageType1);
    BOOST_CHECK(std::get<3>(fields).value() == std::vector<std::uint8_t>(Buf + 6, Buf + 8));
    BOOST_CHECK(std::get<0>(msg.fields()).value() == 0x0102);
    BOOST_CHECK(msg.transportField_version().value() == 4U);

    NonPolymorphicBeMsg2 msg2;
    common_read_write_msg_direct_test(stack, msg2, &Buf[0], BufSize, nil::marshalling::status_type::invalid_msg_id);

    Stack::all_fields_type fields2;
    common_read_write_msg_direct_test(stack, fields2, msg2, &Buf[0], BufSize,
                                      nil::marshalling::status_type::invalid_msg_id);
    BOOST_CHECK(std::get<0>(fields2).value() == 0x6);
    BOOST_CHECK(std::get<1>(fields2).value() == 0x4);
    BOOST_CHECK(std::get<2>(fields2).value() == MessageType1);
}

BOOST_AUTO_TEST_CASE(test5) {
    static const char Buf[] = {0x0, 0x4, 0x0, MessageType1, 0x01, 0x02};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    using MsgBase = ExtraTransportMessageBase<BeOptions>;
    using Stack = AfterIdProtocolStack<MsgBase, nil::marshalling::option::pseudo_value>;

    Stack stack;
    BOOST_CHECK(stack.length() == 4U);

    auto msgPtr = common_read_write_msg_test(stack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == MessageType1);
    BOOST_CHECK(msgPtr->transportField_version().value() == 5U);

    stack.next_layer().next_layer().pseudo_field().value() = 8U;
    auto msgPtr2 = common_read_write_msg_test(stack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr2);
    BOOST_CHECK(msgPtr2->get_id() == MessageType1);
    BOOST_CHECK(msgPtr2->transportField_version().value() == 8U);
}

BOOST_AUTO_TEST_SUITE_END()