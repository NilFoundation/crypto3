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

#define BOOST_TEST_MODULE marshalling_message_test

#include "test_common.hpp"

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <nil/marshalling/empty_handler.hpp>
#include <nil/marshalling/generic_handler.hpp>
#include <nil/marshalling/generic_message.hpp>
#include <nil/marshalling/status_type.hpp>

template<typename TMessage>
TMessage internal_read_write_test(typename TMessage::read_iterator const buf,
                                  std::size_t bufSize,
                                  nil::marshalling::status_type expected_status
                                  = nil::marshalling::status_type::success) {
    TMessage msg;

    typename TMessage::read_iterator readIter = buf;
    nil::marshalling::status_type es = msg.read(readIter, bufSize);
    BOOST_CHECK(es == expected_status);

    if (es == nil::marshalling::status_type::success) {
        auto diff = static_cast<unsigned>(std::distance(buf, readIter));
        BOOST_CHECK(0 < diff);

        typedef typename TMessage::write_iterator write_iterator;
        typedef typename std::decay<decltype(*(std::declval<write_iterator>()))>::type CharType;

        std::unique_ptr<CharType[]> outDataBuf(new CharType[diff]);
        auto writeIter = &outDataBuf[0];
        nil::marshalling::status_type write_es = msg.write(writeIter, diff);

        BOOST_CHECK(write_es == nil::marshalling::status_type::success);
        BOOST_CHECK(std::equal(buf, buf + diff, static_cast<const CharType *>(&outDataBuf[0])));
    }
    return msg;
}

template<typename TMessage>
void internal_write_read_test(TMessage &msg,
                              typename TMessage::write_iterator const buf,
                              std::size_t bufSize,
                              nil::marshalling::status_type expected_status
                              = nil::marshalling::status_type::success) {
    typename TMessage::write_iterator writeIter = buf;
    nil::marshalling::status_type es = msg.write(writeIter, bufSize);
    BOOST_CHECK(es == expected_status);

    if (es == nil::marshalling::status_type::success) {
        auto diff = static_cast<std::size_t>(std::distance(buf, writeIter));
        TMessage readMsg;
        auto readIter = static_cast<const std::uint8_t *>(buf);
        nil::marshalling::status_type read_es = readMsg.read(readIter, diff);

        BOOST_CHECK(read_es == nil::marshalling::status_type::success);
        BOOST_CHECK(msg == readMsg);
    }
}

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, 
                   nil::marshalling::option::id_info_interface,
                   nil::marshalling::option::read_iterator<const std::uint8_t *>,
                   nil::marshalling::option::write_iterator<std::uint8_t *>,
                   nil::marshalling::option::valid_check_interface, 
                   nil::marshalling::option::length_info_interface,
                   nil::marshalling::option::handler<nil::marshalling::empty_handler>,
                   nil::marshalling::option::name_interface>
    common_options;

typedef nil::marshalling::message<nil::marshalling::option::big_endian, 
                                  common_options> BeMessageBase;
typedef nil::marshalling::message<nil::marshalling::option::little_endian, 
                                  common_options> LeMessageBase;

static_assert(std::has_virtual_destructor<BeMessageBase>::value,
              "BeMessageBase is expected to have virtual destructor");

static_assert(std::has_virtual_destructor<LeMessageBase>::value,
              "LeMessageBase is expected to have virtual destructor");

static_assert(BeMessageBase::has_msg_id_type(), "Wrong interface");
static_assert(BeMessageBase::has_endian(), "Wrong interface");
static_assert(BeMessageBase::has_get_id(), "Wrong interface");
static_assert(BeMessageBase::has_read(), "Wrong interface");
static_assert(BeMessageBase::has_write(), "Wrong interface");
static_assert(BeMessageBase::has_valid(), "Wrong interface");
static_assert(BeMessageBase::has_length(), "Wrong interface");
static_assert(!BeMessageBase::has_refresh(), "Wrong interface");
static_assert(BeMessageBase::has_dispatch(), "Wrong interface");
static_assert(!BeMessageBase::has_transport_fields(), "Wrong interface");
static_assert(!BeMessageBase::has_version_in_transport_fields(), "Wrong interface");

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>> BasicCommonOptions;

typedef nil::marshalling::message<nil::marshalling::option::big_endian, 
                                  BasicCommonOptions> BeBasicMessageBase;

static_assert(!std::has_virtual_destructor<BeBasicMessageBase>::value,
              "BeBasicMessageBase is expected to NOT have virtual destructor");

static_assert(BeBasicMessageBase::has_msg_id_type(), "Wrong interface");
static_assert(BeBasicMessageBase::has_endian(), "Wrong interface");
static_assert(!BeBasicMessageBase::has_get_id(), "Wrong interface");
static_assert(!BeBasicMessageBase::has_read(), "Wrong interface");
static_assert(!BeBasicMessageBase::has_write(), "Wrong interface");
static_assert(!BeBasicMessageBase::has_valid(), "Wrong interface");
static_assert(!BeBasicMessageBase::has_length(), "Wrong interface");
static_assert(!BeBasicMessageBase::has_refresh(), "Wrong interface");
static_assert(!BeBasicMessageBase::has_dispatch(), "Wrong interface");
static_assert(!BeBasicMessageBase::has_transport_fields(), "Wrong interface");
static_assert(!BeBasicMessageBase::has_version_in_transport_fields(), "Wrong interface");

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>,
                   nil::marshalling::option::read_iterator<const std::uint8_t *>>
    ReadOnlyCommonOptions;

typedef nil::marshalling::message<nil::marshalling::option::big_endian, 
                                  ReadOnlyCommonOptions> BeReadOnlyMessageBase;

static_assert(std::has_virtual_destructor<BeReadOnlyMessageBase>::value,
              "BeReadOnlyMessageBase is expected to have virtual destructor");

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>,
                   nil::marshalling::option::write_iterator<std::back_insert_iterator<std::vector<std::uint8_t>>>>
    WriteOnlyCommonOptions;

typedef nil::marshalling::message<nil::marshalling::option::big_endian, 
                                  WriteOnlyCommonOptions> BeWriteOnlyMessageBase;

static_assert(BeWriteOnlyMessageBase::has_msg_id_type(), "Wrong interface");
static_assert(BeWriteOnlyMessageBase::has_endian(), "Wrong interface");
static_assert(!BeWriteOnlyMessageBase::has_get_id(), "Wrong interface");
static_assert(!BeWriteOnlyMessageBase::has_read(), "Wrong interface");
static_assert(BeWriteOnlyMessageBase::has_write(), "Wrong interface");
static_assert(!BeWriteOnlyMessageBase::has_valid(), "Wrong interface");
static_assert(!BeWriteOnlyMessageBase::has_length(), "Wrong interface");
static_assert(!BeWriteOnlyMessageBase::has_refresh(), "Wrong interface");
static_assert(!BeWriteOnlyMessageBase::has_dispatch(), "Wrong interface");
static_assert(!BeWriteOnlyMessageBase::has_transport_fields(), "Wrong interface");
static_assert(!BeWriteOnlyMessageBase::has_version_in_transport_fields(), "Wrong interface");

static_assert(std::has_virtual_destructor<BeWriteOnlyMessageBase>::value,
              "BeWriteOnlyMessageBase is expected to have virtual destructor");

typedef std::tuple<nil::marshalling::option::msg_id_type<message_type>, 
                   nil::marshalling::option::length_info_interface>
    LengthOnlyCommonOptions;

typedef nil::marshalling::message<nil::marshalling::option::big_endian, 
                                  LengthOnlyCommonOptions>
    BeLengthOnlyMessageBase;

static_assert(BeLengthOnlyMessageBase::has_msg_id_type(), "Wrong interface");
static_assert(BeLengthOnlyMessageBase::has_endian(), "Wrong interface");
static_assert(!BeLengthOnlyMessageBase::has_get_id(), "Wrong interface");
static_assert(!BeLengthOnlyMessageBase::has_read(), "Wrong interface");
static_assert(!BeLengthOnlyMessageBase::has_write(), "Wrong interface");
static_assert(!BeLengthOnlyMessageBase::has_valid(), "Wrong interface");
static_assert(BeLengthOnlyMessageBase::has_length(), "Wrong interface");
static_assert(!BeLengthOnlyMessageBase::has_refresh(), "Wrong interface");
static_assert(!BeLengthOnlyMessageBase::has_dispatch(), "Wrong interface");
static_assert(!BeLengthOnlyMessageBase::has_transport_fields(), "Wrong interface");
static_assert(!BeLengthOnlyMessageBase::has_version_in_transport_fields(), "Wrong interface");

static_assert(std::has_virtual_destructor<BeLengthOnlyMessageBase>::value,
              "BeLengthOnlyMessageBase is expected to have virtual destructor");

typedef Message1<BeMessageBase> BeMsg1;
typedef Message1<LeMessageBase> LeMsg1;
typedef Message1<BeBasicMessageBase> BeBasicMsg1;
typedef Message1<BeReadOnlyMessageBase> BeReadOnlyMsg1;
typedef Message1<BeWriteOnlyMessageBase> BeWriteOnlyMsg1;
typedef Message1<BeLengthOnlyMessageBase> BeLengthOnlyMsg1;

typedef Message3<BeMessageBase> BeMsg3;
typedef Message3<LeMessageBase> LeMsg3;

typedef nil::marshalling::message<common_options, 
                                  nil::marshalling::option::big_endian,
                                  nil::marshalling::option::refresh_interface>
    BeRefreshableMessageBase;

static_assert(BeRefreshableMessageBase::has_msg_id_type(), "Wrong interface");
static_assert(BeRefreshableMessageBase::has_endian(), "Wrong interface");
static_assert(BeRefreshableMessageBase::has_get_id(), "Wrong interface");
static_assert(BeRefreshableMessageBase::has_read(), "Wrong interface");
static_assert(BeRefreshableMessageBase::has_write(), "Wrong interface");
static_assert(BeRefreshableMessageBase::has_valid(), "Wrong interface");
static_assert(BeRefreshableMessageBase::has_length(), "Wrong interface");
static_assert(BeRefreshableMessageBase::has_refresh(), "Wrong interface");
static_assert(BeRefreshableMessageBase::has_dispatch(), "Wrong interface");
static_assert(!BeRefreshableMessageBase::has_transport_fields(), "Wrong interface");
static_assert(!BeRefreshableMessageBase::has_version_in_transport_fields(), "Wrong interface");

static_assert(std::has_virtual_destructor<BeRefreshableMessageBase>::value,
              "BeRefreshableMessageBase is expected to have virtual destructor");

typedef Message4<BeRefreshableMessageBase> BeMsg4;

typedef nil::marshalling::message<nil::marshalling::option::big_endian,
                                  nil::marshalling::option::read_iterator<const std::uint8_t *>,
                                  nil::marshalling::option::write_iterator<std::uint8_t *>>
    NoIdMsgBase;

static_assert(!NoIdMsgBase::has_msg_id_type(), "Wrong interface");
static_assert(NoIdMsgBase::has_endian(), "Wrong interface");
static_assert(!NoIdMsgBase::has_get_id(), "Wrong interface");
static_assert(NoIdMsgBase::has_read(), "Wrong interface");
static_assert(NoIdMsgBase::has_write(), "Wrong interface");
static_assert(!NoIdMsgBase::has_valid(), "Wrong interface");
static_assert(!NoIdMsgBase::has_length(), "Wrong interface");
static_assert(!NoIdMsgBase::has_refresh(), "Wrong interface");
static_assert(!NoIdMsgBase::has_dispatch(), "Wrong interface");
static_assert(!NoIdMsgBase::has_transport_fields(), "Wrong interface");
static_assert(!NoIdMsgBase::has_version_in_transport_fields(), "Wrong interface");

static_assert(std::has_virtual_destructor<NoIdMsgBase>::value, "NoIdMsgBase is expected to have virtual destructor");

typedef Message1<NoIdMsgBase> NoIdMsg1;

typedef nil::marshalling::message<nil::marshalling::option::read_iterator<const std::uint8_t *>,
                                  nil::marshalling::option::write_iterator<std::uint8_t *>>
    NoEndianMsgBase;

static_assert(!NoEndianMsgBase::has_msg_id_type(), "Wrong interface");
static_assert(!NoEndianMsgBase::has_endian(), "Wrong interface");
static_assert(!NoEndianMsgBase::has_get_id(), "Wrong interface");
static_assert(NoEndianMsgBase::has_read(), "Wrong interface");
static_assert(NoEndianMsgBase::has_write(), "Wrong interface");
static_assert(!NoEndianMsgBase::has_valid(), "Wrong interface");
static_assert(!NoEndianMsgBase::has_length(), "Wrong interface");
static_assert(!NoEndianMsgBase::has_refresh(), "Wrong interface");
static_assert(!NoEndianMsgBase::has_dispatch(), "Wrong interface");
static_assert(!NoEndianMsgBase::has_transport_fields(), "Wrong interface");
static_assert(!NoEndianMsgBase::has_version_in_transport_fields(), "Wrong interface");

typedef Message5<NoIdMsgBase> NoEndianMsg5;

class BoolHandler;

typedef nil::marshalling::message<nil::marshalling::option::msg_id_type<message_type>,
                                  nil::marshalling::option::handler<BoolHandler>,
                                  nil::marshalling::option::id_info_interface, 
                                  nil::marshalling::option::big_endian>
    BoolHandlerMsgBase;

typedef Message1<BoolHandlerMsgBase> BoolHandlerMsg1;
typedef Message2<BoolHandlerMsgBase> BoolHandlerMsg2;
typedef Message3<BoolHandlerMsgBase> BoolHandlerMsg3;

typedef std::tuple<BoolHandlerMsg1, BoolHandlerMsg2, BoolHandlerMsg3> BoolHandlerAllMessages;

class BoolHandler : public nil::marshalling::generic_handler<BoolHandlerMsgBase, 
                                                             BoolHandlerAllMessages, 
                                                             bool> {
    using Base = nil::marshalling::generic_handler<BoolHandlerMsgBase, 
                                                   BoolHandlerAllMessages, 
                                                   bool>;

public:
    using Base::handle;

    virtual bool handle(BoolHandlerMsgBase &msg) override {
        m_lastId = msg.get_id();
        return true;
    }

    BoolHandlerMsgBase::msg_id_type getLastId() const {
        return m_lastId;
    }

private:
    BoolHandlerMsgBase::msg_id_type m_lastId = BoolHandlerMsgBase::msg_id_type();
};

static_assert(BoolHandlerMsgBase::has_msg_id_type(), "Wrong interface");
static_assert(BoolHandlerMsgBase::has_endian(), "Wrong interface");
static_assert(BoolHandlerMsgBase::has_get_id(), "Wrong interface");
static_assert(!BoolHandlerMsgBase::has_read(), "Wrong interface");
static_assert(!BoolHandlerMsgBase::has_write(), "Wrong interface");
static_assert(!BoolHandlerMsgBase::has_valid(), "Wrong interface");
static_assert(!BoolHandlerMsgBase::has_length(), "Wrong interface");
static_assert(!BoolHandlerMsgBase::has_refresh(), "Wrong interface");
static_assert(BoolHandlerMsgBase::has_dispatch(), "Wrong interface");
static_assert(!BoolHandlerMsgBase::has_transport_fields(), "Wrong interface");
static_assert(!BoolHandlerMsgBase::has_version_in_transport_fields(), "Wrong interface");

typedef std::tuple<
    nil::marshalling::types::int_value<nil::marshalling::field_type<nil::marshalling::option::big_endian>,
                                       std::uint16_t, 
                                       nil::marshalling::option::default_num_value<5>>>
    ExtraVersionTransport;

struct ExtraTransportMessageBase
    : public nil::marshalling::message<nil::marshalling::option::big_endian,
                                       common_options,
                                       nil::marshalling::option::extra_transport_fields<ExtraVersionTransport>,
                                       nil::marshalling::option::version_in_extra_transport_fields<0>,
                                       nil::marshalling::option::refresh_interface> {

    using Base = nil::marshalling::message<nil::marshalling::option::big_endian,
                                           common_options,
                                           nil::marshalling::option::extra_transport_fields<ExtraVersionTransport>,
                                           nil::marshalling::option::version_in_extra_transport_fields<0>,
                                           nil::marshalling::option::refresh_interface>;

public:
    MARSHALLING_MSG_TRANSPORT_FIELDS_ACCESS(version);
};

static_assert(ExtraTransportMessageBase::has_msg_id_type(), "Wrong interface");
static_assert(ExtraTransportMessageBase::has_endian(), "Wrong interface");
static_assert(ExtraTransportMessageBase::has_get_id(), "Wrong interface");
static_assert(ExtraTransportMessageBase::has_read(), "Wrong interface");
static_assert(ExtraTransportMessageBase::has_write(), "Wrong interface");
static_assert(ExtraTransportMessageBase::has_valid(), "Wrong interface");
static_assert(ExtraTransportMessageBase::has_length(), "Wrong interface");
static_assert(ExtraTransportMessageBase::has_refresh(), "Wrong interface");
static_assert(ExtraTransportMessageBase::has_dispatch(), "Wrong interface");
static_assert(ExtraTransportMessageBase::has_transport_fields(), "Wrong interface");
static_assert(ExtraTransportMessageBase::has_version_in_transport_fields(), "Wrong interface");

BOOST_AUTO_TEST_SUITE(message_test_suite)

BOOST_AUTO_TEST_CASE(custom_test1) {
    static const std::uint8_t Buf[] = {0x01, 0x02};
    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    BeMsg1 beMsg = internal_read_write_test<BeMsg1>(&Buf[0], BufSize);
    auto value = std::get<0>(beMsg.fields()).value();
    BOOST_CHECK(value == 0x0102);
    BOOST_CHECK(beMsg.valid());

    LeMsg1 leMsg = internal_read_write_test<LeMsg1>(&Buf[0], BufSize);
    value = std::get<0>(leMsg.fields()).value();
    BOOST_CHECK(value == 0x0201);
    BOOST_CHECK(leMsg.valid());
}

BOOST_AUTO_TEST_CASE(test1) {
    static const std::uint8_t Buf[] = {0x01, 0x02};
    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    BeMsg1 beMsg = internal_read_write_test<BeMsg1>(&Buf[0], BufSize);
    auto value = std::get<0>(beMsg.fields()).value();
    BOOST_CHECK(value == 0x0102);
    BOOST_CHECK(beMsg.valid());
    BOOST_CHECK(beMsg.name() == "Message1");

    LeMsg1 leMsg = internal_read_write_test<LeMsg1>(&Buf[0], BufSize);
    value = std::get<0>(leMsg.fields()).value();
    BOOST_CHECK(value == 0x0201);
    BOOST_CHECK(leMsg.valid());
    BOOST_CHECK(leMsg.name() == "Message1");
}

BOOST_AUTO_TEST_CASE(test2) {
    static const std::uint8_t ExpectecedBeBuf[] = {0x01, 0x02};

    BeMsg1 beMsg;
    BOOST_CHECK(beMsg.valid());
    std::get<0>(beMsg.fields()).value() = 0x0102;
    std::uint8_t beBuf[2] = {0};
    static const std::size_t BeBufSize = std::extent<decltype(beBuf)>::value;
    internal_write_read_test(beMsg, &beBuf[0], BeBufSize);
    BOOST_CHECK(
        std::equal(&ExpectecedBeBuf[0], 
                   &ExpectecedBeBuf[0] + BeBufSize, 
                   static_cast<const std::uint8_t *>(&beBuf[0])));

    static const std::uint8_t ExpectecedLeBuf[] = {0x02, 0x01};

    LeMsg1 leMsg;
    std::get<0>(leMsg.fields()).value() = 0x0102;
    BOOST_CHECK(leMsg.valid());
    std::uint8_t leBuf[2] = {0};
    static const std::size_t LeBufSize = std::extent<decltype(leBuf)>::value;
    internal_write_read_test(leMsg, leBuf, LeBufSize);
    BOOST_CHECK(
        std::equal(&ExpectecedLeBuf[0], 
                   &ExpectecedLeBuf[0] + LeBufSize, 
                   static_cast<const std::uint8_t *>(&leBuf[0])));
}

BOOST_AUTO_TEST_CASE(test3) {
    static const std::uint8_t Buf[] = {0x01};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    BeMsg1 beMsg = internal_read_write_test<BeMsg1>(Buf, 
                                                  BufSize, 
                                                  nil::marshalling::status_type::not_enough_data);

    LeMsg1 leMsg = internal_read_write_test<LeMsg1>(Buf, 
                                                  BufSize, 
                                                  nil::marshalling::status_type::not_enough_data);
}

BOOST_AUTO_TEST_CASE(test4) {
    std::uint8_t buf[1] = {0};

    static const std::size_t BufSize = std::extent<decltype(buf)>::value;

    BeMsg1 beMsg;
    std::get<0>(beMsg.fields()).value() = 0x0102;
    internal_write_read_test(beMsg, 
                             buf, 
                             BufSize, 
                             nil::marshalling::status_type::buffer_overflow);

    LeMsg1 leMsg;
    std::get<0>(leMsg.fields()).value() = 0x0102;
    internal_write_read_test(leMsg, 
                             buf, 
                             BufSize, 
                             nil::marshalling::status_type::buffer_overflow);
}

BOOST_AUTO_TEST_CASE(test5) {
    static const std::uint8_t Buf[] = {0x01, 0x02, 0x3, 0x4, 
                                       (std::uint8_t)-5, 0xde, 0xad, 0x00, 
                                       0xaa, 0xff};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    BeMsg3 beMsg;
    BOOST_CHECK(!beMsg.valid());    // there is invalid field
    beMsg = internal_read_write_test<BeMsg3>(Buf, BufSize);

    BOOST_CHECK(std::get<0>(beMsg.fields()).value() == 0x01020304);
    BOOST_CHECK(std::get<1>(beMsg.fields()).value() == -5);
    BOOST_CHECK(std::get<2>(beMsg.fields()).value() == 0xdead);
    BOOST_CHECK(std::get<3>(beMsg.fields()).value() == 0xaaff);
    BOOST_CHECK(beMsg.length() == 10);
    BOOST_CHECK(beMsg.valid());
    BOOST_CHECK(beMsg.name() == "Message3");
    BOOST_CHECK(beMsg.eval_name() == "Message3");

    LeMsg3 leMsg;
    BOOST_CHECK(!leMsg.valid());
    leMsg = internal_read_write_test<LeMsg3>(Buf, BufSize);

    BOOST_CHECK(std::get<0>(leMsg.fields()).value() == 0x04030201);
    BOOST_CHECK(std::get<1>(leMsg.fields()).value() == -5);
    BOOST_CHECK(std::get<2>(leMsg.fields()).value() == 0xadde);
    BOOST_CHECK(std::get<3>(leMsg.fields()).value() == 0xffaa00);
    BOOST_CHECK(leMsg.length() == 10);
    BOOST_CHECK(leMsg.valid());
    BOOST_CHECK(leMsg.name() == "Message3");
}

BOOST_AUTO_TEST_CASE(test6) {
    std::uint8_t buf[4] = {0};
    static const std::size_t BufSize = std::extent<decltype(buf)>::value;

    BeMsg3 beMsg;
    internal_write_read_test(beMsg, 
                             buf, 
                             BufSize, 
                             nil::marshalling::status_type::buffer_overflow);

    LeMsg3 leMsg;
    internal_write_read_test(leMsg, 
                             buf, 
                             BufSize, 
                             nil::marshalling::status_type::buffer_overflow);
}

BOOST_AUTO_TEST_CASE(test7) {
    BeBasicMsg1 msg1;
    BOOST_CHECK(msg1.eval_get_id() == MessageType1);

    BeReadOnlyMsg1 msg2;
    BOOST_CHECK(msg2.eval_get_id() == MessageType1);
    static const std::uint8_t Data1[] = {0x1, 0x2};
    static const auto Data1Size = std::extent<decltype(Data1)>::value;
    BeReadOnlyMsg1::read_iterator readIter = &Data1[0];
    nil::marshalling::status_type es = msg2.read(readIter, Data1Size);

    BOOST_CHECK(es == nil::marshalling::status_type::success);
    BOOST_CHECK(std::get<0>(msg2.fields()).value() == 0x0102);

    BeWriteOnlyMsg1 msg3;
    BOOST_CHECK(msg3.eval_get_id() == MessageType1);
    std::get<0>(msg3.fields()).value() = 0x0102;
    std::vector<std::uint8_t> outData;
    BeWriteOnlyMsg1::write_iterator writeIter = std::back_inserter(outData);
    es = msg3.write(writeIter, outData.max_size());
    BOOST_CHECK(es == nil::marshalling::status_type::success);
    BOOST_CHECK(outData.size() == 2U);
    BOOST_CHECK(outData[0] == 0x1);
    BOOST_CHECK(outData[1] == 0x2);

    BeLengthOnlyMsg1 msg4;
    BOOST_CHECK(msg4.eval_get_id() == MessageType1);
    BOOST_CHECK(msg4.length() == 2U);
}

BOOST_AUTO_TEST_CASE(test8) {
    BeMsg4 msg;
    BOOST_CHECK(msg.eval_get_id() == MessageType4);
    BOOST_CHECK(msg.length() == 1U);
    BOOST_CHECK(msg.name() == "Message4");

    std::vector<std::uint8_t> outData;
    outData.resize(msg.length());
    BeMsg4::write_iterator writeIter = &outData[0];

    internal_write_read_test(msg, writeIter, outData.size());

    auto &mask = std::get<0>(msg.fields());
    mask.value() = 0x1;
    bool refreshResult = msg.refresh();
    BOOST_CHECK(refreshResult);
    BOOST_CHECK(msg.length() == 3U);
    BOOST_CHECK(msg.field_value2().get_mode() == nil::marshalling::types::optional_mode::exists);

    outData.clear();
    outData.resize(msg.length());
    writeIter = &outData[0];
    internal_write_read_test(msg, writeIter, outData.size());
}

BOOST_AUTO_TEST_CASE(test9) {
    static const std::uint8_t Buf[] = {0x12, 0x34};
    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    NoIdMsg1 msg1 = internal_read_write_test<NoIdMsg1>(&Buf[0], BufSize);
    auto value = std::get<0>(msg1.fields()).value();
    BOOST_CHECK(value == 0x1234);
}

BOOST_AUTO_TEST_CASE(test10) {
    static const std::uint8_t Buf[] = {0x12, 0x34, 0xff};
    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    NoEndianMsg5 msg = internal_read_write_test<NoEndianMsg5>(&Buf[0], BufSize);
    auto value1 = std::get<0>(msg.fields()).value();
    auto value2 = std::get<1>(msg.fields()).value();
    BOOST_CHECK(value1 == 0x1234);
    BOOST_CHECK(value2 == -1);
}

BOOST_AUTO_TEST_CASE(test11) {
    typedef nil::marshalling::message<nil::marshalling::option::big_endian,
                                      nil::marshalling::option::msg_id_type<message_type>>
        Msg1;

    static_assert(!std::has_virtual_destructor<Msg1>::value, "Error");

    typedef nil::marshalling::message<nil::marshalling::option::big_endian,
                                      nil::marshalling::option::msg_id_type<message_type>,
                                      nil::marshalling::option::read_iterator<const char *>>
        Msg2;

    static_assert(std::has_virtual_destructor<Msg2>::value, "Error");

    typedef nil::marshalling::message<
        nil::marshalling::option::big_endian, 
        nil::marshalling::option::msg_id_type<message_type>,
        nil::marshalling::option::read_iterator<const char *>, 
        nil::marshalling::option::no_virtual_destructor>
        Msg3;

    static_assert(!std::has_virtual_destructor<Msg3>::value, "Error");

    typedef nil::marshalling::message<nil::marshalling::option::big_endian,
                                      nil::marshalling::option::msg_id_type<message_type>,
                                      nil::marshalling::option::write_iterator<char *>>
        Msg4;

    static_assert(std::has_virtual_destructor<Msg4>::value, "Error");

    typedef nil::marshalling::message<
        nil::marshalling::option::big_endian, 
        nil::marshalling::option::msg_id_type<message_type>,
        nil::marshalling::option::write_iterator<char *>, 
        nil::marshalling::option::no_virtual_destructor>
        Msg5;

    static_assert(!std::has_virtual_destructor<Msg5>::value, "Error");

    typedef nil::marshalling::message<nil::marshalling::option::big_endian,
                                      nil::marshalling::option::msg_id_type<message_type>,
                                      nil::marshalling::option::id_info_interface>
        Msg6;

    static_assert(std::has_virtual_destructor<Msg6>::value, "Error");

    typedef nil::marshalling::message<
        nil::marshalling::option::big_endian, 
        nil::marshalling::option::msg_id_type<message_type>,
        nil::marshalling::option::id_info_interface, 
        nil::marshalling::option::no_virtual_destructor>
        Msg7;

    static_assert(!std::has_virtual_destructor<Msg7>::value, "Error");

    typedef nil::marshalling::message<nil::marshalling::option::big_endian,
                                      nil::marshalling::option::msg_id_type<message_type>,
                                      nil::marshalling::option::valid_check_interface>
        Msg8;

    static_assert(std::has_virtual_destructor<Msg8>::value, "Error");

    typedef nil::marshalling::message<
        nil::marshalling::option::big_endian, 
        nil::marshalling::option::msg_id_type<message_type>,
        nil::marshalling::option::valid_check_interface, 
        nil::marshalling::option::no_virtual_destructor>
        Msg9;

    static_assert(!std::has_virtual_destructor<Msg9>::value, "Error");

    typedef nil::marshalling::message<nil::marshalling::option::big_endian,
                                      nil::marshalling::option::msg_id_type<message_type>,
                                      nil::marshalling::option::length_info_interface>
        Msg10;

    static_assert(std::has_virtual_destructor<Msg10>::value, "Error");

    typedef nil::marshalling::message<
        nil::marshalling::option::big_endian, 
        nil::marshalling::option::msg_id_type<message_type>,
        nil::marshalling::option::length_info_interface, 
        nil::marshalling::option::no_virtual_destructor>
        Msg11;

    static_assert(!std::has_virtual_destructor<Msg11>::value, "Error");

    typedef nil::marshalling::message<nil::marshalling::option::big_endian,
                                      nil::marshalling::option::msg_id_type<message_type>,
                                      nil::marshalling::option::refresh_interface>
        Msg12;

    static_assert(std::has_virtual_destructor<Msg12>::value, "Error");

    typedef nil::marshalling::message<
        nil::marshalling::option::big_endian, 
        nil::marshalling::option::msg_id_type<message_type>,
        nil::marshalling::option::refresh_interface, 
        nil::marshalling::option::no_virtual_destructor>
        Msg13;

    static_assert(!std::has_virtual_destructor<Msg13>::value, "Error");
}

BOOST_AUTO_TEST_CASE(test12) {
    using Message = nil::marshalling::generic_message<BeMessageBase>;
    Message msg(MessageType1);

    BeMessageBase &interface = msg;
    BOOST_CHECK(interface.get_id() == MessageType1);
    BOOST_CHECK(interface.valid());
    BOOST_CHECK(interface.length() == 0);

    static const std::uint8_t Buf[] = {0x12, 0x34, 0x56};
    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    typename BeMessageBase::read_iterator readIter = 
      nil::marshalling::read_iterator_for<BeMessageBase>(Buf);

    nil::marshalling::status_type es = interface.read(readIter, BufSize);

    BOOST_CHECK(es == nil::marshalling::status_type::success);
    BOOST_CHECK(interface.length() == BufSize);
    BOOST_CHECK(msg.field_data().value().size() == BufSize);

    bool equal = std::equal(std::begin(Buf), std::end(Buf), msg.field_data().value().begin());
    BOOST_CHECK(equal);

    std::vector<std::uint8_t> outBuf;
    outBuf.resize(BufSize);
    typename BeMessageBase::write_iterator writeIter = 
      nil::marshalling::write_iterator_for<BeMessageBase>(&outBuf[0]);

    es = interface.write(writeIter, outBuf.size());
    BOOST_CHECK(es == nil::marshalling::status_type::success);

    equal = std::equal(std::begin(Buf), std::end(Buf), outBuf.begin());
    BOOST_CHECK(equal);
}

BOOST_AUTO_TEST_CASE(test13) {
    BoolHandlerMsg1 msg1;
    BoolHandlerMsg2 msg2;
    BoolHandlerMsg3 msg3;

    BoolHandler handler;

    BOOST_CHECK(msg1.dispatch(handler));
    BOOST_CHECK(handler.getLastId() == msg1.get_id());
    BOOST_CHECK(msg2.dispatch(handler));
    BOOST_CHECK(handler.getLastId() == msg2.get_id());
    BOOST_CHECK(msg3.dispatch(handler));
    BOOST_CHECK(handler.getLastId() == msg3.get_id());
}

BOOST_AUTO_TEST_CASE(test14) {
    static const std::uint8_t Buf[] = {0x12, 0x34, 0xff};
    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    using Msg5 = Message5<ExtraTransportMessageBase>;

    Msg5 msg = internal_read_write_test<Msg5>(&Buf[0], BufSize);
    auto value1 = std::get<0>(msg.fields()).value();
    auto value2 = std::get<1>(msg.fields()).value();

    BOOST_CHECK(value1 == 0x1234);
    BOOST_CHECK(value2 == -1);
    BOOST_CHECK(msg.transportField_version().value() == 5U);
}

BOOST_AUTO_TEST_CASE(test15) {
    static const std::uint8_t Buf[] = {0x1, 0x02, 0x03};
    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    using Msg6 = Message6<BeRefreshableMessageBase>;

    Msg6 msg = internal_read_write_test<Msg6>(&Buf[0], BufSize);
    BOOST_CHECK(msg.eval_length() == 3U);
    BOOST_CHECK(msg.field_value1().field_mask().value() == 1U);
    BOOST_CHECK(msg.field_value1().field_val().field().value() == 0x0203);

    msg.field_value1().field_mask().value() = 0U;

    BeRefreshableMessageBase &interface = msg;
    BOOST_CHECK(interface.refresh());
    BOOST_CHECK(msg.length() == 1U);
    BOOST_CHECK(!interface.refresh());

    msg.field_value1().field_mask().value() = 1U;
    BOOST_CHECK(interface.refresh());
    BOOST_CHECK(msg.length() == 3U);
}

BOOST_AUTO_TEST_CASE(test16) {
    using Msg7 = Message7<ExtraTransportMessageBase>;
    Msg7 msg;
    BOOST_CHECK(msg.version() == 5U);
    BOOST_CHECK(msg.length() == 4U);

    static const std::uint8_t Buf[] = {0x12, 0x34, 0x56, 0x78};
    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;

    msg = internal_read_write_test<Msg7>(&Buf[0], BufSize);
    BOOST_CHECK(msg.field_value1().value() == 0x1234);
    BOOST_CHECK(msg.field_value2().does_exist());
    BOOST_CHECK(msg.field_value2().field().value() == 0x5678);

    msg.version() = 4U;
    typename Msg7::read_iterator readIter = 
      nil::marshalling::read_iterator_for<Msg7>(&Buf[0]);

    nil::marshalling::status_type es = msg.read(readIter, BufSize);
    BOOST_CHECK(es == nil::marshalling::status_type::success);
    BOOST_CHECK(msg.length() == 2U);
    BOOST_CHECK(msg.field_value2().is_missing());

    msg.version() = 10;
    BOOST_CHECK(msg.refresh());
    BOOST_CHECK(msg.length() == 4U);
    BOOST_CHECK(msg.field_value2().does_exist());

    msg.version() = 11;
    BOOST_CHECK(msg.refresh());
    BOOST_CHECK(msg.length() == 2U);
    BOOST_CHECK(msg.field_value2().is_missing());

    //    BOOST_CHECK(value2 == -1);
    //    BOOST_CHECK(msg.transportField_version().value() == 5U);
}

BOOST_AUTO_TEST_SUITE_END()