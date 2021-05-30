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

#define BOOST_TEST_MODULE marshalling_msg_size_layer_test

#include "test_common.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <nil/marshalling/types/enum_value.hpp>
#include <nil/marshalling/protocol/msg_size_layer.hpp>
#include <nil/marshalling/protocol/msg_id_layer.hpp>
#include <nil/marshalling/protocol/msg_data_layer.hpp>
#include <nil/marshalling/generic_message.hpp>

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::id_info_interface,
                   nil::marshalling::option::read_iterator<const char *>,
                   nil::marshalling::option::valid_check_interface, nil::marshalling::option::length_info_interface>
    common_options;

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::id_info_interface,
                   nil::marshalling::option::read_iterator<const char *>,
                   nil::marshalling::option::valid_check_interface>
    NoLengthOptions;

typedef std::tuple<nil::marshalling::option::big_endian, nil::marshalling::option::write_iterator<char *>,
                   common_options>
    BeTraits;

typedef std::tuple<nil::marshalling::option::big_endian, nil::marshalling::option::write_iterator<char *>,
                   NoLengthOptions>
    BeNoLengthTraits;

typedef std::tuple<nil::marshalling::option::big_endian,
                   nil::marshalling::option::write_iterator<std::back_insert_iterator<std::vector<char>>>,
                   common_options>
    BeBackInsertTraits;

typedef std::tuple<nil::marshalling::option::big_endian,
                   nil::marshalling::option::write_iterator<std::back_insert_iterator<std::vector<char>>>,
                   NoLengthOptions>
    BeNoLengthBackInsertTraits;

typedef std::tuple<nil::marshalling::option::little_endian, nil::marshalling::option::write_iterator<char *>,
                   common_options>
    LeTraits;

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::big_endian>
    NonPolymorphicBigEndianTraits;

typedef TestMessageBase<BeTraits> BeMsgBase;
typedef TestMessageBase<BeNoLengthTraits> BeNoLengthMsgBase;
typedef TestMessageBase<LeTraits> LeMsgBase;
typedef TestMessageBase<BeBackInsertTraits> BeBackInsertMsgBase;
typedef TestMessageBase<BeNoLengthBackInsertTraits> BeNoLengthBackInsertMsgBase;
typedef nil::marshalling::message<NonPolymorphicBigEndianTraits> BeNonPolymorphicMessageBase;

typedef BeMsgBase::field_type BeField;
typedef LeMsgBase::field_type LeField;
typedef BeBackInsertMsgBase::field_type BeBackInsertField;

typedef Message1<BeMsgBase> BeMsg1;
typedef Message1<BeNoLengthMsgBase> BeNoLengthMsg1;
typedef Message1<BeNoLengthBackInsertMsgBase> BeNoLengthBackInsertMsg1;
typedef Message1<LeMsgBase> LeMsg1;
typedef Message1<BeBackInsertMsgBase> BeBackInsertMsg1;
typedef Message2<BeMsgBase> BeMsg2;
typedef Message2<LeMsgBase> LeMsg2;
typedef Message3<BeMsgBase> BeMsg3;
typedef Message3<LeMsgBase> LeMsg3;
typedef Message3<BeBackInsertMsgBase> BeBackInsertMsg3;
typedef Message1<BeNonPolymorphicMessageBase> NonPolymorphicBeMsg1;
typedef Message2<BeNonPolymorphicMessageBase> NonPolymorphicBeMsg2;

template<typename TField, std::size_t TSize, std::size_t TOffset = 0>
using SizeField = nil::marshalling::types::int_value<TField, unsigned, nil::marshalling::option::fixed_length<TSize>,
                                                     nil::marshalling::option::num_value_ser_offset<TOffset>>;

template<typename TField>
using SizeField20 = SizeField<TField, 2, 0>;
using BeSizeField20 = SizeField20<BeField>;
using LeSizeField20 = SizeField20<LeField>;
using BeBackInsertSizeField20 = SizeField20<BeBackInsertField>;

template<typename TField>
using SizeField30 = SizeField<TField, 3, 0>;
using BeSizeField30 = SizeField30<BeField>;
using LeSizeField30 = SizeField30<LeField>;

template<typename TField>
using SizeField22 = SizeField<TField, 2, 2>;
using BeSizeField22 = SizeField22<BeField>;
using LeSizeField22 = SizeField22<LeField>;

template<typename TField, std::size_t TLen>
using IdField = nil::marshalling::types::enum_value<TField, message_type, nil::marshalling::option::fixed_length<TLen>>;

template<typename TField>
using IdField1 = IdField<TField, 1>;
using BeIdField1 = IdField1<BeField>;
using LeIdField1 = IdField1<LeField>;
using BeBackInsertIdField1 = IdField1<BeBackInsertField>;

template<typename TField>
using IdField2 = IdField<TField, 2>;
using BeIdField2 = IdField2<BeField>;
using LeIdField2 = IdField2<LeField>;

template<typename TSizeField, typename TIdField, typename TMessage>
class ProtocolStack
    : public nil::marshalling::protocol::msg_size_layer<
          TSizeField, nil::marshalling::protocol::msg_id_layer<TIdField, TMessage, all_messages_type<TMessage>,
                                                               nil::marshalling::protocol::msg_data_layer<>>> {
#ifdef MARSHALLING_MUST_DEFINE_BASE
    using Base = nil::marshalling::protocol::msg_size_layer<
        TSizeField, nil::marshalling::protocol::msg_id_layer<TIdField, TMessage, all_messages_type<TMessage>,
                                                             nil::marshalling::protocol::msg_data_layer<>>>;
#endif
public:
    MARSHALLING_PROTOCOL_LAYERS_ACCESS_INNER(payload, id, size);
};

template<typename TIdField, typename TSizeField, typename TMessage>
class RevProtocolStack
    : public nil::marshalling::protocol::msg_id_layer<
          TIdField, TMessage, all_messages_type<TMessage>,
          nil::marshalling::protocol::msg_size_layer<TSizeField, nil::marshalling::protocol::msg_data_layer<>>> {
#ifdef MARSHALLING_MUST_DEFINE_BASE
    using Base = nil::marshalling::protocol::msg_id_layer<
        TIdField, TMessage, all_messages_type<TMessage>,
        nil::marshalling::protocol::msg_size_layer<TSizeField, nil::marshalling::protocol::msg_data_layer<>>>;
#endif
public:
    MARSHALLING_PROTOCOL_LAYERS_ACCESS_OUTER(id, size, payload);
};

template<typename TSizeField, typename TIdField, typename TMessage>
using InPlaceProtocolStack = nil::marshalling::protocol::msg_size_layer<
    TSizeField, nil::marshalling::protocol::msg_id_layer<TIdField, TMessage, all_messages_type<TMessage>,
                                                         nil::marshalling::protocol::msg_data_layer<>,
                                                         nil::marshalling::option::in_place_allocation>>;

template<typename TMsgBase>
class GenericMsg : public nil::marshalling::generic_message<TMsgBase> {
    using Base = nil::marshalling::generic_message<TMsgBase>;

public:
    using msg_id_param_type = typename Base::msg_id_param_type;

    explicit GenericMsg(msg_id_param_type id) : Base(id) {
    }

    GenericMsg(const GenericMsg &) = default;

    const char *eval_name() const {
        return "Generic message";
    }
};

template<typename TSizeField, typename TIdField, typename TMessage>
using GenMsgProtocolStack = nil::marshalling::protocol::msg_size_layer<
    TSizeField, nil::marshalling::protocol::msg_id_layer<
                    TIdField, TMessage, all_messages_type<TMessage>, nil::marshalling::protocol::msg_data_layer<>,
                    nil::marshalling::option::support_generic_message<GenericMsg<TMessage>>>>;

BOOST_AUTO_TEST_SUITE(msg_size_layer_test_suite)

BOOST_AUTO_TEST_CASE(test1) {
    static const char Buf[] = {0x0, 0x3, MessageType1, 0x01, 0x02, static_cast<char>(0x3f)};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    ProtocolStack<BeSizeField20, BeIdField1, BeMsgBase> stack;
    auto &sizeLayer = stack.layer_size();
    using SizeLayerType = typename std::decay<decltype(sizeLayer)>::type;
    static_assert(nil::marshalling::protocol::is_msg_size_layer<SizeLayerType>(), "Invalid layer");

    auto &idLayer = stack.layer_id();
    using IdLayerType = typename std::decay<decltype(idLayer)>::type;
    static_assert(nil::marshalling::protocol::is_msg_id_layer<IdLayerType>(), "Invalid layer");

    auto &payloadLayer = stack.layer_payload();
    using PayloadLayerType = typename std::decay<decltype(payloadLayer)>::type;
    static_assert(nil::marshalling::protocol::is_msg_data_layer<PayloadLayerType>(), "Invalid layer");

    auto msgPtr = common_read_write_msg_test(stack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == MessageType1);
    auto &msg1 = dynamic_cast<BeMsg1 &>(*msgPtr);
    BOOST_CHECK(std::get<0>(msg1.fields()).value() == 0x0102);

    InPlaceProtocolStack<BeSizeField20, BeIdField1, BeMsgBase> inPlaceStack;
    auto msgPtr2 = common_read_write_msg_test(inPlaceStack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr2);
    BOOST_CHECK(msgPtr2->get_id() == MessageType1);
    auto &msg2 = dynamic_cast<BeMsg1 &>(*msgPtr2);
    BOOST_CHECK(std::get<0>(msg2.fields()).value() == 0x0102);

    BOOST_CHECK(msg1 == msg2);

    GenMsgProtocolStack<BeSizeField20, BeIdField1, BeMsgBase> genMsgStack;
    auto msgPtr3 = common_read_write_msg_test(genMsgStack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr3);
    BOOST_CHECK(msgPtr3->get_id() == MessageType1);
    auto &msg3 = dynamic_cast<BeMsg1 &>(*msgPtr2);
    BOOST_CHECK(std::get<0>(msg3.fields()).value() == 0x0102);

    BOOST_CHECK(msg1 == msg3);

    auto msgPtr4
        = common_read_write_msg_test(inPlaceStack, &Buf[0], BufSize, nil::marshalling::status_type::msg_alloc_failure);
    BOOST_CHECK(!msgPtr4);
}

BOOST_AUTO_TEST_CASE(test2) {
    LeMsg1 msg;
    std::get<0>(msg.fields()).value() = 0x0304;

    static const char ExpectedBuf[] = {0x4, 0x0, 0x0, MessageType1, 0x0, 0x04, 0x03};

    static const std::size_t BufSize = std::extent<decltype(ExpectedBuf)>::value;
    char buf[BufSize] = {0};

    ProtocolStack<LeSizeField30, LeIdField2, LeMsgBase> stack;
    common_write_read_msg_test(stack, msg, buf, BufSize, &ExpectedBuf[0]);

    InPlaceProtocolStack<LeSizeField30, LeIdField2, LeMsgBase> inPlaceStack;
    common_write_read_msg_test(inPlaceStack, msg, buf, BufSize, &ExpectedBuf[0]);
}

BOOST_AUTO_TEST_CASE(test3) {
    static const char Buf[] = {0x0, 0x2, MessageType1, 0x00, 0x00};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    ProtocolStack<BeSizeField20, BeIdField1, BeMsgBase> stack;
    auto msgPtr = common_read_write_msg_test(stack, &Buf[0], BufSize, nil::marshalling::status_type::protocol_error);
    BOOST_CHECK(!msgPtr);

    InPlaceProtocolStack<BeSizeField20, BeIdField1, BeMsgBase> inPlaceStack;
    auto msgPtr2
        = common_read_write_msg_test(inPlaceStack, &Buf[0], BufSize, nil::marshalling::status_type::protocol_error);
    BOOST_CHECK(!msgPtr2);
}

BOOST_AUTO_TEST_CASE(test4) {
    static const char Buf[] = {0x0};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    ProtocolStack<BeSizeField20, BeIdField1, BeMsgBase> stack;
    auto msgPtr = common_read_write_msg_test(stack, &Buf[0], BufSize, nil::marshalling::status_type::not_enough_data);
    BOOST_CHECK(!msgPtr);

    InPlaceProtocolStack<BeSizeField20, BeIdField1, BeMsgBase> inPlaceStack;
    auto msgPtr2
        = common_read_write_msg_test(inPlaceStack, &Buf[0], BufSize, nil::marshalling::status_type::not_enough_data);
    BOOST_CHECK(!msgPtr2);
}

BOOST_AUTO_TEST_CASE(test5) {
    LeMsg1 msg;
    std::get<0>(msg.fields()).value() = 0x0203;

    char buf[2] = {0};
    static const std::size_t BufSize = std::extent<decltype(buf)>::value;

    ProtocolStack<LeSizeField30, LeIdField2, LeMsgBase> stack;
    common_write_read_msg_test(stack, msg, buf, BufSize, nullptr, nil::marshalling::status_type::buffer_overflow);

    InPlaceProtocolStack<LeSizeField30, LeIdField2, LeMsgBase> inPlaceStack;
    common_write_read_msg_test(inPlaceStack, msg, buf, BufSize, nullptr,
                               nil::marshalling::status_type::buffer_overflow);
}

BOOST_AUTO_TEST_CASE(test6) {
    static const char Buf[] = {MessageType1, 0x0, 0x2, 0x01, 0x02, static_cast<char>(0x3f)};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    RevProtocolStack<BeIdField1, BeSizeField20, BeMsgBase> stack;
    auto &sizeLayer = stack.layer_size();
    using SizeLayerType = typename std::decay<decltype(sizeLayer)>::type;
    static_assert(nil::marshalling::protocol::is_msg_size_layer<SizeLayerType>(), "Invalid layer");

    auto &idLayer = stack.layer_id();
    using IdLayerType = typename std::decay<decltype(idLayer)>::type;
    static_assert(nil::marshalling::protocol::is_msg_id_layer<IdLayerType>(), "Invalid layer");

    auto &payloadLayer = stack.layer_payload();
    using PayloadLayerType = typename std::decay<decltype(payloadLayer)>::type;
    static_assert(nil::marshalling::protocol::is_msg_data_layer<PayloadLayerType>(), "Invalid layer");

    auto msgPtr = common_read_write_msg_test(stack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == MessageType1);
    auto &msg = dynamic_cast<BeMsg1 &>(*msgPtr);
    BOOST_CHECK(std::get<0>(msg.fields()).value() == 0x0102);
}

BOOST_AUTO_TEST_CASE(test7) {
    static const char Buf[] = {MessageType1, 0x0, 0x4, 0x01, 0x02};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    RevProtocolStack<BeIdField1, BeSizeField22, BeMsgBase> stack;
    auto &sizeLayer = stack.layer_size();
    using SizeLayerType = typename std::decay<decltype(sizeLayer)>::type;
    static_assert(nil::marshalling::protocol::is_msg_size_layer<SizeLayerType>(), "Invalid layer");

    auto &idLayer = stack.layer_id();
    using IdLayerType = typename std::decay<decltype(idLayer)>::type;
    static_assert(nil::marshalling::protocol::is_msg_id_layer<IdLayerType>(), "Invalid layer");

    auto &payloadLayer = stack.layer_payload();
    using PayloadLayerType = typename std::decay<decltype(payloadLayer)>::type;
    static_assert(nil::marshalling::protocol::is_msg_data_layer<PayloadLayerType>(), "Invalid layer");

    auto msgPtr = common_read_write_msg_test(stack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == MessageType1);
    auto &msg = dynamic_cast<BeMsg1 &>(*msgPtr);
    BOOST_CHECK(std::get<0>(msg.fields()).value() == 0x0102);
}

BOOST_AUTO_TEST_CASE(test8) {
    static const char Buf[] = {0x0, 0x3, MessageType1, 0x01, 0x02, static_cast<char>(0x3f)};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    ProtocolStack<BeBackInsertSizeField20, BeBackInsertIdField1, BeBackInsertMsgBase> stack;
    auto msgPtr = vectorBackInsertReadWriteMsgTest(stack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == MessageType1);
    auto &msg1 = dynamic_cast<BeBackInsertMsg1 &>(*msgPtr);
    BOOST_CHECK(std::get<0>(msg1.fields()).value() == 0x0102);

    InPlaceProtocolStack<BeBackInsertSizeField20, BeBackInsertIdField1, BeBackInsertMsgBase> inPlaceStack;
    auto msgPtr2 = vectorBackInsertReadWriteMsgTest(inPlaceStack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr2);
    BOOST_CHECK(msgPtr2->get_id() == MessageType1);
    auto &msg2 = dynamic_cast<BeBackInsertMsg1 &>(*msgPtr2);
    BOOST_CHECK(std::get<0>(msg2.fields()).value() == 0x0102);

    BOOST_CHECK(msg1 == msg2);

    auto msgPtr3 = vectorBackInsertReadWriteMsgTest(inPlaceStack, &Buf[0], BufSize,
                                                    nil::marshalling::status_type::msg_alloc_failure);
    BOOST_CHECK(!msgPtr3);
}

BOOST_AUTO_TEST_CASE(test9) {
    BeBackInsertMsg3 msg;
    BOOST_CHECK(!msg.valid());
    auto &fields = msg.fields();
    std::get<0>(fields).value() = 0x01020304;
    std::get<1>(fields).value() = 0x05;
    std::get<2>(fields).value() = 0x0607;
    std::get<3>(fields).value() = 0x08090a;

    static const char ExpectedBuf[] = {0x0, 0xb, MessageType3, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa};
    static const std::size_t BufSize = std::extent<decltype(ExpectedBuf)>::value;

    ProtocolStack<BeBackInsertSizeField20, BeBackInsertIdField1, BeBackInsertMsgBase> stack;
    vector_back_insert_write_read_msg_test(stack, msg, ExpectedBuf, BufSize);
}

BOOST_AUTO_TEST_CASE(test10) {
    RevProtocolStack<BeIdField1, BeSizeField22, BeMsgBase> stack;
    auto msgPtr1 = stack.create_msg(MessageType1);
    BOOST_CHECK(msgPtr1);
    BOOST_CHECK(msgPtr1->get_id() == MessageType1);
    auto msgPtr2 = stack.create_msg(MessageType2);
    BOOST_CHECK(msgPtr2);
    BOOST_CHECK(msgPtr2->get_id() == MessageType2);
    auto msgPtr3 = stack.create_msg(MessageType3);
    BOOST_CHECK(msgPtr3);
    BOOST_CHECK(msgPtr3->get_id() == MessageType3);
}

BOOST_AUTO_TEST_CASE(test11) {
    static const char Buf[] = {0x0, 0xb, MessageType3, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa};
    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    using ProtStack = ProtocolStack<BeSizeField20, BeIdField1, BeMsgBase>;
    ProtStack stack;

    using all_fields_type = ProtStack::all_fields_type;
    all_fields_type fields;

    auto msgPtr = common_read_write_msg_test(stack, fields, Buf, BufSize);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == MessageType3);

    BOOST_CHECK(std::get<0>(fields).value() == 0x0b);
    BOOST_CHECK(std::get<1>(fields).value() == MessageType3);

    auto &msg = dynamic_cast<BeMsg3 &>(*msgPtr);
    auto &msgFields = msg.fields();
    BOOST_CHECK(std::get<0>(msgFields).value() == 0x01020304);
    BOOST_CHECK(std::get<1>(msgFields).value() == 0x05);
    BOOST_CHECK(std::get<2>(msgFields).value() == 0x0607);
    BOOST_CHECK(std::get<3>(msgFields).value() == 0x08090a);
}

BOOST_AUTO_TEST_CASE(test12) {
    BeNoLengthMsg1 msg;
    std::get<0>(msg.fields()).value() = 0x0304;

    static const char ExpectedBuf[] = {0x0, 0x3, MessageType1, 0x03, 0x04};

    static const std::size_t BufSize = std::extent<decltype(ExpectedBuf)>::value;
    char buf[BufSize] = {0};

    ProtocolStack<BeSizeField20, BeIdField1, BeNoLengthMsgBase> stack;
    common_write_read_msg_test(stack, msg, buf, BufSize, &ExpectedBuf[0]);
}

BOOST_AUTO_TEST_CASE(test13) {
    BeNoLengthBackInsertMsg1 msg;
    std::get<0>(msg.fields()).value() = 0x0304;

    static const char ExpectedBuf[] = {0x0, 0x4, 0x0, MessageType1, 0x03, 0x04};

    static const std::size_t BufSize = std::extent<decltype(ExpectedBuf)>::value;
    ProtocolStack<BeSizeField20, BeIdField2, BeNoLengthBackInsertMsgBase> stack;
    vector_back_insert_write_read_msg_test(stack, msg, ExpectedBuf, BufSize);
}

BOOST_AUTO_TEST_CASE(test14) {
    static const char Buf[] = {0x0, 0x3, UnusedValue1, 0x01, 0x02, static_cast<char>(0x3f)};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    GenMsgProtocolStack<BeSizeField20, BeIdField1, BeMsgBase> stack;
    auto msgPtr = common_read_write_msg_test(stack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == UnusedValue1);

    auto &msg1 = dynamic_cast<GenericMsg<BeMsgBase> &>(*msgPtr);
    BOOST_CHECK(msg1.field_data().value().size() == 2U);
    BOOST_CHECK(msg1.field_data().value()[0] == 0x01);
    BOOST_CHECK(msg1.field_data().value()[1] == 0x02);
}

BOOST_AUTO_TEST_CASE(test15) {
    static const char Buf[] = {0x0, 0x3, MessageType1, 0x01, 0x02, static_cast<char>(0x3f)};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    using ProtStack = ProtocolStack<BeSizeField20, BeIdField1, BeNonPolymorphicMessageBase>;
    ProtStack stack;
    NonPolymorphicBeMsg1 msg;
    common_read_write_msg_direct_test(stack, msg, &Buf[0], BufSize);
    BOOST_CHECK(std::get<0>(msg.fields()).value() == 0x0102);

    ProtStack::all_fields_type fields;
    common_read_write_msg_direct_test(stack, fields, msg, &Buf[0], BufSize);
    BOOST_CHECK(std::get<0>(fields).value() == 3U);
    BOOST_CHECK(std::get<1>(fields).value() == MessageType1);

    NonPolymorphicBeMsg2 msg2;
    common_read_write_msg_direct_test(stack, msg2, &Buf[0], BufSize, nil::marshalling::status_type::invalid_msg_id);

    ProtStack::all_fields_type fields2;
    common_read_write_msg_direct_test(stack, fields2, msg2, &Buf[0], BufSize,
                                      nil::marshalling::status_type::invalid_msg_id);

    BOOST_CHECK(std::get<0>(fields2).value() == 3U);
    BOOST_CHECK(std::get<1>(fields2).value() == MessageType1);
}

BOOST_AUTO_TEST_SUITE_END()