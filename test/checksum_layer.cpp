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

#define BOOST_TEST_MODULE marshalling_checksum_layer_test

#include "test_common.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <iterator>

#include <nil/marshalling/types/enum_value.hpp>

#include <nil/marshalling/protocol/checksum_layer.hpp>
#include <nil/marshalling/protocol/msg_size_layer.hpp>
#include <nil/marshalling/protocol/msg_id_layer.hpp>
#include <nil/marshalling/protocol/sync_prefix_layer.hpp>
#include <nil/marshalling/protocol/checksum/basic_sum.hpp>
#include <nil/marshalling/protocol/checksum/crc.hpp>
#include <nil/marshalling/protocol/msg_data_layer.hpp>
#include <nil/marshalling/protocol/checksum_prefix_layer.hpp>

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::id_info_interface,
                   nil::marshalling::option::big_endian, nil::marshalling::option::read_iterator<const char *>,
                   nil::marshalling::option::write_iterator<char *>, nil::marshalling::option::length_info_interface>
    BeTraits;

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::id_info_interface,
                   nil::marshalling::option::big_endian, nil::marshalling::option::read_iterator<const char *>,
                   nil::marshalling::option::write_iterator<std::back_insert_iterator<std::vector<char>>>,
                   nil::marshalling::option::length_info_interface>
    BeBackInsertTraits;

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::id_info_interface,
                   nil::marshalling::option::little_endian, nil::marshalling::option::read_iterator<const char *>,
                   nil::marshalling::option::write_iterator<char *>, nil::marshalling::option::length_info_interface>
    LeTraits;

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, nil::marshalling::option::big_endian>
    NonPolymorphicBigEndianTraits;

typedef TestMessageBase<BeTraits> BeMsgBase;
typedef TestMessageBase<LeTraits> LeMsgBase;
typedef TestMessageBase<BeBackInsertTraits> BeBackInsertMsgBase;
typedef nil::marshalling::message<NonPolymorphicBigEndianTraits> BeNonPolymorphicMessageBase;

typedef BeMsgBase::field_type BeField;
typedef LeMsgBase::field_type LeField;
typedef BeBackInsertMsgBase::field_type BeBackInsertField;

typedef Message1<BeMsgBase> BeMsg1;
typedef Message1<LeMsgBase> LeMsg1;
typedef Message1<BeBackInsertMsgBase> BeBackInsertMsg1;
typedef Message2<BeMsgBase> BeMsg2;
typedef Message2<LeMsgBase> LeMsg2;
typedef Message3<BeMsgBase> BeMsg3;
typedef Message3<LeMsgBase> LeMsg3;
typedef Message3<BeBackInsertMsgBase> BeBackInsertMsg3;

typedef Message1<BeNonPolymorphicMessageBase> NonPolymorphicBeMsg1;
typedef Message2<BeNonPolymorphicMessageBase> NonPolymorphicBeMsg2;

template<typename TField, std::size_t TSize>
using SyncField = nil::marshalling::types::int_value<TField, unsigned, nil::marshalling::option::fixed_length<TSize>,
                                                     nil::marshalling::option::default_num_value<0xabcd>>;

template<typename TField>
using SyncField2 = SyncField<TField, 2>;
using BeSyncField2 = SyncField2<BeField>;
using LeSyncField2 = SyncField2<LeField>;
using BeBackInsertSyncField2 = SyncField2<BeBackInsertField>;

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

template<typename TField, std::size_t TLen>
using ChecksumField
    = nil::marshalling::types::int_value<TField, typename nil::marshalling::processing::size_to_type<TLen>::type>;

template<typename TField>
using ChecksumField1 = ChecksumField<TField, 1U>;
using BeChecksumField1 = ChecksumField1<BeField>;
using LeChecksumField1 = ChecksumField1<LeField>;
using BeBackInsertChecksumField1 = ChecksumField1<BeBackInsertField>;

template<typename TSyncField, typename TChecksumField, typename TSizeField, typename TIdField, typename TMessage>
struct ProtocolStack
    : public nil::marshalling::protocol::sync_prefix_layer<
          TSyncField,
          nil::marshalling::protocol::checksum_layer<
              TChecksumField, nil::marshalling::protocol::checksum::basic_sum<>,
              nil::marshalling::protocol::msg_size_layer<
                  TSizeField,
                  nil::marshalling::protocol::msg_id_layer<TIdField, TMessage, all_messages_type<TMessage>,
                                                           nil::marshalling::protocol::msg_data_layer<>>>>> {
#ifdef MARSHALLING_MUST_DEFINE_BASE
    using Base = nil::marshalling::protocol::sync_prefix_layer<
        TSyncField,
        nil::marshalling::protocol::checksum_layer<
            TChecksumField, nil::marshalling::protocol::checksum::basic_sum<>,
            nil::marshalling::protocol::msg_size_layer<
                TSizeField, nil::marshalling::protocol::msg_id_layer<TIdField, TMessage, all_messages_type<TMessage>,
                                                                     nil::marshalling::protocol::msg_data_layer<>>>>>;
#endif
public:
    MARSHALLING_PROTOCOL_LAYERS_ACCESS_OUTER(sync, checksum, size, id, payload);
};

template<typename TSyncField, typename TChecksumField, typename TSizeField, typename TIdField, typename TMessage>
using ProtocolStackVerifyBefore = nil::marshalling::protocol::sync_prefix_layer<
    TSyncField,
    nil::marshalling::protocol::checksum_layer<
        TChecksumField, nil::marshalling::protocol::checksum::basic_sum<>,
        nil::marshalling::protocol::msg_size_layer<
            TSizeField, nil::marshalling::protocol::msg_id_layer<TIdField, TMessage, all_messages_type<TMessage>,
                                                                 nil::marshalling::protocol::msg_data_layer<>>>,
        nil::marshalling::option::checksum_layer_verify_before_read>>;

template<typename TSyncField, typename TChecksumField, typename TSizeField, typename TIdField, typename TMessage>
class ProtocolPrefixStack
    : public nil::marshalling::protocol::sync_prefix_layer<
          TSyncField,
          nil::marshalling::protocol::checksum_prefix_layer<
              TChecksumField, nil::marshalling::protocol::checksum::basic_sum<>,
              nil::marshalling::protocol::msg_size_layer<
                  TSizeField, nil::marshalling::protocol::msg_id_layer<TIdField, TMessage, all_messages_type<TMessage>,
                                                                       nil::marshalling::protocol::msg_data_layer<>>

                  >>> {
#ifdef MARSHALLING_MUST_DEFINE_BASE
    using Base = nil::marshalling::protocol::sync_prefix_layer<
        TSyncField,
        nil::marshalling::protocol::checksum_prefix_layer<
            TChecksumField, nil::marshalling::protocol::checksum::basic_sum<>,
            nil::marshalling::protocol::msg_size_layer<
                TSizeField, nil::marshalling::protocol::msg_id_layer<TIdField, TMessage, all_messages_type<TMessage>,
                                                                     nil::marshalling::protocol::msg_data_layer<>>>>>;
#endif
public:
    MARSHALLING_PROTOCOL_LAYERS_ACCESS_INNER(payload, id, size, checksum, sync);
};

BOOST_AUTO_TEST_SUITE(checksum_layer_test_suite)

BOOST_AUTO_TEST_CASE(test1) {
    static const char Buf[]
        = {(char)0xab, (char)0xcd, 0x0, 0x3, MessageType1, 0x01, 0x02, 0x06, static_cast<char>(0x3f)};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    typedef ProtocolStack<BeSyncField2, BeChecksumField1, BeSizeField20, BeIdField1, BeMsgBase> Stack;

    Stack stack;

    auto &syncLayer = stack.layer_sync();
    using SyncLayerType = typename std::decay<decltype(syncLayer)>::type;
    static_assert(nil::marshalling::protocol::is_sync_prefix_layer<SyncLayerType>(), "Invalid layer");

    auto &checksumLayer = stack.layer_checksum();
    using ChecksumLayerType = typename std::decay<decltype(checksumLayer)>::type;
    static_assert(nil::marshalling::protocol::is_checksum_layer<ChecksumLayerType>(), "Invalid layer");

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
}

BOOST_AUTO_TEST_CASE(test2) {
    LeMsg1 msg;
    std::get<0>(msg.fields()).value() = 0x0304;

    static const char ExpectedBuf[] = {(char)0xcd, (char)0xab, 0x4, 0x0, 0x0, MessageType1, 0x0, 0x04, 0x03, 0x0b};

    static const std::size_t BufSize = std::extent<decltype(ExpectedBuf)>::value;
    char buf[BufSize] = {0};

    typedef ProtocolStack<LeSyncField2, LeChecksumField1, LeSizeField30, LeIdField2, LeMsgBase> Stack;

    Stack stack;
    common_write_read_msg_test(stack, msg, buf, BufSize, &ExpectedBuf[0]);
}

BOOST_AUTO_TEST_CASE(test3) {
    static const char Buf[]
        = {(char)0xab, (char)0xcd, 0x0, 0x3, MessageType1, 0x01, 0x02, 0x07, static_cast<char>(0x3f)};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    typedef ProtocolStack<BeSyncField2, BeChecksumField1, BeSizeField20, BeIdField1, BeMsgBase> Stack;

    Stack stack;

    auto msgPtr = common_read_write_msg_test(stack, &Buf[0], BufSize, nil::marshalling::status_type::protocol_error);
    BOOST_CHECK(!msgPtr);
}

BOOST_AUTO_TEST_CASE(test4) {
    static const char Buf[] = {(char)0xab, (char)0xcd, 0x0, 0x3, MessageType1, 0x01, 0x02};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    typedef ProtocolStack<BeSyncField2, BeChecksumField1, BeSizeField20, BeIdField1, BeMsgBase> Stack;

    Stack stack;

    auto msgPtr = common_read_write_msg_test(stack, &Buf[0], BufSize, nil::marshalling::status_type::not_enough_data);
    BOOST_CHECK(!msgPtr);
}

//
BOOST_AUTO_TEST_CASE(test5) {
    LeMsg1 msg;
    std::get<0>(msg.fields()).value() = 0x0203;

    char buf[9] = {0};
    static const std::size_t BufSize = std::extent<decltype(buf)>::value;

    typedef ProtocolStack<LeSyncField2, LeChecksumField1, LeSizeField30, LeIdField2, LeMsgBase> Stack;

    Stack stack;
    common_write_read_msg_test(stack, msg, buf, BufSize, nullptr, nil::marshalling::status_type::buffer_overflow);
}

BOOST_AUTO_TEST_CASE(test6) {
    static const char Buf[]
        = {(char)0xab, (char)0xcd, 0x0, 0x3, MessageType1, 0x01, 0x02, 0x06, static_cast<char>(0x3f)};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    typedef ProtocolStack<BeBackInsertSyncField2, BeBackInsertChecksumField1, BeBackInsertSizeField20,
                          BeBackInsertIdField1, BeBackInsertMsgBase>
        Stack;

    Stack stack;

    auto msgPtr = vectorBackInsertReadWriteMsgTest(stack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == MessageType1);
    auto &msg1 = dynamic_cast<BeBackInsertMsg1 &>(*msgPtr);
    BOOST_CHECK(std::get<0>(msg1.fields()).value() == 0x0102);
}

BOOST_AUTO_TEST_CASE(test7) {
    //    auto& table =
    //    nil::marshalling::protocol::checksum::detail::crc_init_table<std::uint32_t,
    //    0x04C11DB7>::get(); for (auto byte : table) {
    //        std::cout << "0x" << std::setfill('0') << std::setw(8) << std::hex
    //        << (unsigned)byte << ", ";
    //    }

    static const std::vector<std::uint8_t> Data = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};

    {
        auto iter = &Data[0];
        auto val = nil::marshalling::protocol::checksum::crc_ccitt()(iter, Data.size());
        BOOST_CHECK(val == 0x29b1);
    }

    {
        auto iter = &Data[0];
        auto val = nil::marshalling::protocol::checksum::crc_16()(iter, Data.size());
        BOOST_CHECK(val == 0xbb3d);
    }

    {
        auto iter = &Data[0];
        auto val = nil::marshalling::protocol::checksum::crc_32()(iter, Data.size());
        BOOST_CHECK(val == 0xcbf43926);
    }
}

BOOST_AUTO_TEST_CASE(test8) {
    static const char Buf[] = {(char)0xab, (char)0xcd, 0x0, 0x3, MessageType1, 0x01, 0x02, 0x06};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    typedef ProtocolStackVerifyBefore<BeSyncField2, BeChecksumField1, BeSizeField20, BeIdField1, BeMsgBase> Stack;

    Stack stack;

    auto msgPtr = common_read_write_msg_test(stack, &Buf[0], BufSize);
    BOOST_CHECK(msgPtr);
    BOOST_CHECK(msgPtr->get_id() == MessageType1);
    auto &msg = dynamic_cast<BeMsg1 &>(*msgPtr);
    BOOST_CHECK(std::get<0>(msg.fields()).value() == 0x0102);
}

BOOST_AUTO_TEST_CASE(test9) {
    static const char Buf[]
        = {(char)0xab, (char)0xcd, 0x06, 0x0, 0x3, MessageType1, 0x01, 0x02, static_cast<char>(0x3f)};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    typedef ProtocolPrefixStack<BeSyncField2, BeChecksumField1, BeSizeField20, BeIdField1, BeMsgBase> Stack;

    Stack stack;

    auto &syncLayer = stack.layer_sync();
    using SyncLayerType = typename std::decay<decltype(syncLayer)>::type;
    static_assert(nil::marshalling::protocol::is_sync_prefix_layer<SyncLayerType>(), "Invalid layer");

    auto &checksumLayer = stack.layer_checksum();
    using ChecksumLayerType = typename std::decay<decltype(checksumLayer)>::type;
    static_assert(nil::marshalling::protocol::is_checksum_prefix_layer<ChecksumLayerType>(), "Invalid layer");

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
}

BOOST_AUTO_TEST_CASE(test10) {
    static const char Buf[]
        = {(char)0xab, (char)0xcd, 0x0, 0x3, MessageType1, 0x01, 0x02, 0x06, static_cast<char>(0x3f)};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    typedef ProtocolStack<BeSyncField2, BeChecksumField1, BeSizeField20, BeIdField1, BeNonPolymorphicMessageBase> Stack;

    Stack stack;
    NonPolymorphicBeMsg1 msg;
    common_read_write_msg_direct_test(stack, msg, &Buf[0], BufSize);
    BOOST_CHECK(msg.field_value1().value() == 0x0102);

    Stack::all_fields_type fields;
    common_read_write_msg_direct_test(stack, fields, msg, &Buf[0], BufSize);
    BOOST_CHECK(std::get<0>(fields).value() == 0xabcd);
    BOOST_CHECK(std::get<1>(fields).value() == 6U);    // checksum
    BOOST_CHECK(std::get<2>(fields).value() == 3U);
    BOOST_CHECK(std::get<3>(fields).value() == MessageType1);
    BOOST_CHECK(std::get<4>(fields).value() == std::vector<std::uint8_t>(Buf + 5, Buf + 7));

    NonPolymorphicBeMsg2 msg2;
    common_read_write_msg_direct_test(stack, msg2, &Buf[0], BufSize, nil::marshalling::status_type::invalid_msg_id);

    Stack::all_fields_type fields2;
    common_read_write_msg_direct_test(stack, fields2, msg2, &Buf[0], BufSize,
                                      nil::marshalling::status_type::invalid_msg_id);
    BOOST_CHECK(std::get<0>(fields2).value() == 0xabcd);
    BOOST_CHECK(std::get<2>(fields2).value() == 3U);
    BOOST_CHECK(std::get<3>(fields2).value() == MessageType1);
}

BOOST_AUTO_TEST_SUITE_END()