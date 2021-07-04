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

#define BOOST_TEST_MODULE marshalling_types_test

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <type_traits>

#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/bitmask_value.hpp>
#include <nil/marshalling/types/enumeration.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/string.hpp>
#include <nil/marshalling/types/bitfield.hpp>
#include <nil/marshalling/types/optional.hpp>
#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/float_value.hpp>
#include <nil/marshalling/types/no_value.hpp>
#include <nil/marshalling/types/variant.hpp>

#include <nil/marshalling/compile_control.hpp>
#include <nil/marshalling/units.hpp>
#include <nil/marshalling/version.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/marshalling/container/array_view.hpp>
#include <nil/marshalling/container/static_vector.hpp>
#include <nil/marshalling/container/static_string.hpp>
#include <nil/marshalling/container/string_view.hpp>
#include <nil/marshalling/container/type_traits.hpp>

using namespace nil::marshalling;

static_assert(has_member_function_clear<std::string>::value, "Invalid function presence detection");
static_assert(has_member_function_clear<std::vector<std::uint8_t>>::value, "Invalid function presence detection");
static_assert(has_member_function_clear<container::static_string<5>>::value, "Invalid function presence detection");
static_assert(has_member_function_clear<container::static_vector<std::uint8_t, 5>>::value,
              "Invalid function presence detection");
static_assert(!has_member_function_clear<container::string_view>::value, "Invalid function presence detection");
static_assert(!has_member_function_clear<container::array_view<std::uint8_t>>::value,
              "Invalid function presence detection");

static_assert(has_member_function_resize<std::string>::value, "Invalid function presence detection");
static_assert(has_member_function_resize<std::vector<std::uint8_t>>::value, "Invalid function presence detection");
static_assert(has_member_function_resize<container::static_string<5>>::value, "Invalid function presence detection");
static_assert(has_member_function_resize<container::static_vector<std::uint8_t, 5>>::value,
              "Invalid function presence detection");
static_assert(!has_member_function_resize<container::string_view>::value, "Invalid function presence detection");
static_assert(!has_member_function_resize<container::array_view<std::uint8_t>>::value,
              "Invalid function presence detection");

static_assert(has_member_function_reserve<std::string>::value, "Invalid function presence detection");
static_assert(has_member_function_reserve<std::vector<std::uint8_t>>::value, "Invalid function presence detection");
static_assert(has_member_function_reserve<container::static_string<5>>::value, "Invalid function presence detection");
static_assert(has_member_function_reserve<container::static_vector<std::uint8_t, 5>>::value,
              "Invalid function presence detection");
static_assert(!has_member_function_reserve<container::string_view>::value, "Invalid function presence detection");
static_assert(!has_member_function_reserve<container::array_view<std::uint8_t>>::value,
              "Invalid function presence detection");

struct types_fixture {
    typedef option::big_endian BigEndianOpt;
    typedef option::little_endian LittleEndianOpt;

    enum Enum1 { Enum1_Value1, Enum1_Value2, Enum1_Value3, Enum1_NumOfValues };

    enum class Enum2 : unsigned { Value1, Value2, Value3, Value4, NumOfValues };

    template<typename TField, typename OutputIterator>
    void write_read_field(const TField &field, const OutputIterator expectedBuf, std::size_t size,
                          status_type expectedStatus = status_type::success) {

        std::vector<char> outDataBuf(size);
        pack<TField>(field, outDataBuf.begin(), expectedStatus);

        bool bufAsExpected = std::equal(expectedBuf, expectedBuf + size, outDataBuf.begin());
        if (!bufAsExpected) {
            std::cout << "Expected buffer: " << std::hex;
            std::copy_n(expectedBuf, size, std::ostream_iterator<unsigned>(std::cout, " "));
            std::cout << "\nActual buffer: ";
            std::copy_n(&outDataBuf[0], size, std::ostream_iterator<unsigned>(std::cout, " "));
            std::cout << std::dec << std::endl;
        }
        BOOST_CHECK(bufAsExpected);

        TField newField = pack<TField>(outDataBuf.begin(), outDataBuf.begin() + size, expectedStatus);
        BOOST_CHECK(field == newField);
        BOOST_CHECK(field.value() == newField.value());
    }

    template<typename TFP>
    bool fpEquals(TFP value1, TFP value2) {
        return (std::abs(value1 - value2) < std::numeric_limits<TFP>::epsilon());
    }
};

BOOST_FIXTURE_TEST_SUITE(types_accumulator_test_suite, types_fixture)

BOOST_AUTO_TEST_CASE(types_accumulator_test_minus1) {

    using big_endian_array_type = types::array_list<field_type<option::big_endian>, std::uint32_t>;

    static const std::vector<std::uint8_t> Buf
        = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

    big_endian_array_type be_array = pack<big_endian_array_type>(Buf.begin(), Buf.end());

    std::vector<std::uint32_t> v = be_array.value();

    BOOST_CHECK_EQUAL(v[0], 0x01020304);
    BOOST_CHECK_EQUAL(v[1], 0x05060708);
    BOOST_CHECK_EQUAL(v[2], 0x090a0b0c);
    BOOST_CHECK_EQUAL(v[3], 0x0d0e0f10);

    BOOST_CHECK(be_array.valid());
    BOOST_CHECK(!be_array.set_version(5));
}

BOOST_AUTO_TEST_CASE(types_accumulator_test_minus2) {

    using little_endian_array_type = types::array_list<field_type<option::little_endian>, std::uint32_t>;

    static const std::vector<std::uint8_t> Buf
        = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

    little_endian_array_type le_array = pack<little_endian_array_type>(Buf.begin(), Buf.end());

    std::vector<std::uint32_t> v = le_array.value();

    BOOST_CHECK_EQUAL(v[0], 0x04030201);
    BOOST_CHECK_EQUAL(v[1], 0x08070605);
    BOOST_CHECK_EQUAL(v[2], 0x0c0b0a09);
    BOOST_CHECK_EQUAL(v[3], 0x100f0e0d);

    BOOST_CHECK(le_array.valid());
    BOOST_CHECK(!le_array.set_version(5));
}

BOOST_AUTO_TEST_CASE(types_accumulator_test_minus3) {

    using big_endian_array_type = 
    types::array_list<
        field_type<option::big_endian>,
        types::integral<
            field_type<option::big_endian>, 
            std::uint32_t>,
        option::sequence_fixed_size<5>
    >;

    static const std::vector<std::uint8_t> Buf = {0x01, 0x02, 0x03, 0x04, 
                               0x05, 0x06, 0x07, 0x08, 
                               0x09, 0x0a, 0x0b, 0x0c, 
                               0x0d, 0x0e, 0x0f, 0x10,
                               0x11, 0x12, 0x13, 0x14, 
                               0x15, 0x16, 0x17, 0x18, 
                               0x19, 0x1a, 0x1b, 0x1c, 
                               0x1d, 0x1e, 0x1f, 0x20};

    big_endian_array_type be_array = pack<big_endian_array_type>(Buf.begin(), Buf.end());

    BOOST_CHECK_EQUAL((be_array.value())[0].value(), 0x01020304);
    BOOST_CHECK_EQUAL((be_array.value())[1].value(), 0x05060708);
    BOOST_CHECK_EQUAL((be_array.value())[2].value(), 0x090a0b0c);
    BOOST_CHECK_EQUAL((be_array.value())[3].value(), 0x0d0e0f10);
    BOOST_CHECK_EQUAL((be_array.value())[4].value(), 0x11121314);

    BOOST_CHECK(be_array.valid());
    BOOST_CHECK(!be_array.set_version(5));
}

BOOST_AUTO_TEST_CASE(types_accumulator_test1) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");
    static const std::vector<std::uint8_t> Buf = {0x01, 0x02, 0x03, 0x04};

    testing_type field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK_EQUAL(field.length(), sizeof(std::uint32_t));
    BOOST_CHECK_EQUAL(field.value(), 0x01020304);
    BOOST_CHECK(field.valid());
    BOOST_CHECK(!field.set_version(5));
}

BOOST_AUTO_TEST_CASE(types_accumulator_test2) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t, option::fixed_length<3>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static const std::vector<std::uint8_t> Buf = {0x01, 0x02, 0x03, 0x04};
    testing_type field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK_EQUAL(field.length(), 3);

    BOOST_CHECK_EQUAL(field.value(), 0x010203);
    BOOST_CHECK(field.valid());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test3) {
    typedef types::integral<field_type<option::big_endian>, std::int16_t> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static const std::vector<std::uint8_t> Buf = {0x01, 0x02};
    testing_type field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK_EQUAL(field.length(), sizeof(std::int16_t));
    BOOST_CHECK_EQUAL(field.value(), static_cast<std::int16_t>(0x0102));
    BOOST_CHECK(field.valid());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test4) {
    typedef types::integral<field_type<option::big_endian>, std::int16_t> testing_type;

    static const std::vector<char> Buf = {(char)0xff, (char)0xff};
    testing_type field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK_EQUAL(field.length(), sizeof(std::int16_t));
    BOOST_CHECK_EQUAL(field.value(), -1);
    BOOST_CHECK(field.valid());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test5) {
    typedef types::integral<field_type<option::little_endian>, std::int16_t> testing_type;

    static const std::vector<char> Buf = {0x0, (char)0x80};
    testing_type field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK_EQUAL(field.length(), sizeof(std::int16_t));
    BOOST_CHECK_EQUAL(field.value(), std::numeric_limits<std::int16_t>::min());
    BOOST_CHECK(field.valid());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test6) {
    typedef types::integral<field_type<option::big_endian>, std::int16_t, option::fixed_length<1>> testing_type;

    static const std::vector<char> Buf = {(char)0xff, 0x00};
    testing_type field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK_EQUAL(field.length(), 1);
    BOOST_CHECK_EQUAL(field.value(), -1);
    BOOST_CHECK(field.valid());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test7) {
    typedef types::integral<field_type<option::big_endian>, std::int16_t, option::fixed_length<1>,
                             option::num_value_ser_offset<-2000>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static const std::vector<char> Buf = {13};
    testing_type field = pack<testing_type>(Buf.begin(), Buf.end());

    BOOST_CHECK(field.length() == 1);
    BOOST_CHECK(field.value() == 2013);
    BOOST_CHECK(field.valid());

    field.value() = 2000;
    static const std::vector<char> ExpectedBuf = {0};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    field.value() = 2000 + 0x7f;
    static const std::vector<char> ExpectedBuf2 = {(char)0x7f};
    write_read_field(field, ExpectedBuf2.begin(), ExpectedBuf2.size());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test8) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t, option::fixed_length<3>,
                             option::valid_num_value_range<0, 0x010200>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");
    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value() == 0U);
    field.value() = 0x010200;
    BOOST_CHECK(field.value() == 0x010200);
    BOOST_CHECK(field.valid());

    accumulator_set<testing_type> acc = accumulator_set<testing_type>(field);

    static const std::vector<char> Buf = {0x01, 0x02, 0x03, 0x04};

    field = pack<testing_type>(Buf.begin(), Buf.end(), acc);
    BOOST_CHECK(field.length() == 3);
    BOOST_CHECK(field.value() == 0x010203);
    BOOST_CHECK(!field.valid());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test9) {
    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::valid_num_value_range<0, 10>,
#ifndef CC_COMPILER_GCC47
                             option::valid_num_value_range<20, 30>,
#endif
                             option::default_num_value<100>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.value() == 100);
    BOOST_CHECK(!field.valid());
    field.value() = 5U;
    BOOST_CHECK(field.valid());
    field.value() = 15U;
    BOOST_CHECK(!field.valid());
#ifndef CC_COMPILER_GCC47
    field.value() = 25U;
    BOOST_CHECK(field.valid());
#endif

    accumulator_set<testing_type> acc = accumulator_set<testing_type>(field);

    static const std::vector<char> Buf = {0x05, 0x02};

    field = pack<testing_type>(Buf.begin(), Buf.end(), acc);
    BOOST_CHECK(field.length() == 1);
    BOOST_CHECK(field.value() == 0x05);
    BOOST_CHECK(field.valid());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test10) {
    typedef types::bitmask_value<field_type<option::big_endian>, option::fixed_length<2>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");
    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value() == 0U);

    static const std::vector<char> Buf = {
        (char)0xde,
        (char)0xad,
    };

    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == 2);
    BOOST_CHECK(field.value() == 0xdead);
    BOOST_CHECK(field.get_bit_value(0U) == true);
    BOOST_CHECK(field.get_bit_value(1U) == false);
    BOOST_CHECK(field.get_bit_value(2U) == true);
    BOOST_CHECK(field.get_bit_value(3U) == true);
    BOOST_CHECK(field.get_bit_value(4U) == false);
    BOOST_CHECK(field.get_bit_value(5U) == true);
    BOOST_CHECK(field.get_bit_value(6U) == false);
    BOOST_CHECK(field.get_bit_value(7U) == true);
    BOOST_CHECK(field.get_bit_value(8U) == false);
    BOOST_CHECK(field.get_bit_value(9U) == true);
    BOOST_CHECK(field.get_bit_value(10U) == true);
    BOOST_CHECK(field.get_bit_value(11U) == true);
    BOOST_CHECK(field.get_bit_value(12U) == true);
    BOOST_CHECK(field.get_bit_value(13U) == false);
    BOOST_CHECK(field.get_bit_value(14U) == true);
    BOOST_CHECK(field.get_bit_value(15U) == true);

    field.set_bit_value(1U, true);
    BOOST_CHECK(field.value() == 0xdeaf);

    field.set_bits(0x2);
    BOOST_CHECK(field.value() == 0xdeaf);
    BOOST_CHECK(field.valid());

    static const std::vector<char> ExpectedBuf = {(char)0xde, (char)0xaf};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test11) {
    typedef types::bitmask_value<field_type<option::little_endian>, option::fixed_length<3>,
                                 option::default_num_value<0xffffff>, option::bitmask_reserved_bits<0xff0000, 0>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");
    testing_type field;
    BOOST_CHECK(!field.valid());
    BOOST_CHECK(field.value() == 0xffffff);

    static const std::vector<char> Buf = {(char)0xde, (char)0xad, (char)0x00, (char)0xff};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == 3);
    BOOST_CHECK(field.value() == 0xadde);
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.get_bit_value(0U) == false);
    BOOST_CHECK(field.get_bit_value(1U) == true);
    BOOST_CHECK(field.get_bit_value(2U) == true);
    BOOST_CHECK(field.get_bit_value(3U) == true);
    BOOST_CHECK(field.get_bit_value(4U) == true);
    BOOST_CHECK(field.get_bit_value(5U) == false);
    BOOST_CHECK(field.get_bit_value(6U) == true);
    BOOST_CHECK(field.get_bit_value(7U) == true);
    BOOST_CHECK(field.get_bit_value(8U) == true);
    BOOST_CHECK(field.get_bit_value(9U) == false);
    BOOST_CHECK(field.get_bit_value(10U) == true);
    BOOST_CHECK(field.get_bit_value(11U) == true);
    BOOST_CHECK(field.get_bit_value(12U) == false);
    BOOST_CHECK(field.get_bit_value(13U) == true);
    BOOST_CHECK(field.get_bit_value(14U) == false);
    BOOST_CHECK(field.get_bit_value(15U) == true);
    BOOST_CHECK(field.get_bit_value(16U) == false);
    BOOST_CHECK(field.get_bit_value(17U) == false);
    BOOST_CHECK(field.get_bit_value(18U) == false);
    BOOST_CHECK(field.get_bit_value(19U) == false);
    BOOST_CHECK(field.get_bit_value(20U) == false);
    BOOST_CHECK(field.get_bit_value(21U) == false);
    BOOST_CHECK(field.get_bit_value(22U) == false);
    BOOST_CHECK(field.get_bit_value(23U) == false);

    field.set_bits(0x10000);
    BOOST_CHECK(field.value() == 0x1adde);
    BOOST_CHECK(!field.valid());

    field.set_bit_value(0U, true);
    BOOST_CHECK(field.value() == 0x1addf);
    field.set_bit_value(16U, false);
    BOOST_CHECK(field.value() == 0xaddf);
    BOOST_CHECK(field.valid());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test12) {
    typedef types::enumeration<field_type<option::big_endian>, Enum1, option::fixed_length<1>,
                              option::valid_num_value_range<0, Enum1_NumOfValues - 1>,
                              option::default_num_value<Enum1_NumOfValues>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;

    BOOST_CHECK(!field.valid());
    BOOST_CHECK(field.value() == Enum1_NumOfValues);

    static const std::vector<char> Buf = {(char)Enum1_Value1, (char)0x3f};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == 1);
    BOOST_CHECK(field.value() == Enum1_Value1);
    BOOST_CHECK(field.valid());

    field.value() = Enum1_NumOfValues;
    BOOST_CHECK(!field.valid());
    field.value() = Enum1_Value2;

    static const std::vector<char> ExpectedBuf = {(char)Enum1_Value2};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test13) {
    typedef types::enumeration<field_type<option::big_endian>, Enum2, option::fixed_length<2>,
                              option::valid_num_value_range<0, (int)(Enum2::NumOfValues)-1>,
                              option::default_num_value<(int)Enum2::NumOfValues>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(!field.valid());
    BOOST_CHECK(field.value() == Enum2::NumOfValues);

    static const std::vector<char> Buf = {0x0, (char)Enum2::Value4, (char)0x3f};
    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == 2);

    BOOST_CHECK(field.value() == Enum2::Value4);
    BOOST_CHECK(field.valid());

    field.value() = Enum2::NumOfValues;
    BOOST_CHECK(!field.valid());
    field.value() = Enum2::Value3;

    static const std::vector<char> ExpectedBuf = {0x0, (char)Enum2::Value3};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test14) {
    typedef types::array_list<field_type<option::big_endian>, types::integral<field_type<option::big_endian>, std::uint8_t>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.valid());

    static const std::vector<char> Buf = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9};
    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == Buf.size());
    BOOST_CHECK(field.valid());
    BOOST_CHECK(!field.refresh());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test15) {
    typedef types::array_list<field_type<option::big_endian>, types::integral<field_type<option::big_endian>, std::uint8_t>,
                              option::fixed_size_storage<32>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.valid());

    static const std::vector<char> Buf = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9};
    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == Buf.size());
    BOOST_CHECK(field.valid());

    static const std::vector<char> Buf2 = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc};
    field = pack<testing_type>(Buf2.begin(), Buf2.end());
    BOOST_CHECK(field.length() == Buf2.size());
    BOOST_CHECK(field.valid());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test16) {
    struct SizeField : public types::integral<field_type<option::big_endian>, std::uint8_t> { };

    typedef types::string<field_type<option::big_endian>, option::sequence_size_field_prefix<SizeField>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::string<field_type<option::big_endian>, option::sequence_size_field_prefix<SizeField>,
                          option::fixed_size_storage<256>>
        StaticStorageField;

    static_assert(!StaticStorageField::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().empty());

    StaticStorageField staticStorageField;
    BOOST_CHECK(staticStorageField.valid());
    BOOST_CHECK(staticStorageField.value().empty());

    static const std::vector<char> ExpectedBuf = {0x0};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
    write_read_field(staticStorageField, ExpectedBuf.begin(), ExpectedBuf.size());

    static const std::vector<char> Buf = {0x5, 'h', 'e', 'l', 'l', 'o', 'g', 'a', 'r'};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.value().size() == static_cast<std::size_t>(Buf[0]));
    BOOST_CHECK(field.length() == field.value().size() + 1U);
    BOOST_CHECK(field.valid());

    staticStorageField = pack<StaticStorageField>(Buf.begin(), Buf.end());
    BOOST_CHECK(staticStorageField.value().size() == static_cast<std::size_t>(Buf[0]));
    BOOST_CHECK(staticStorageField.length() == staticStorageField.value().size() + 1U);
    BOOST_CHECK(staticStorageField.valid());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test17) {
    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::valid_num_value_range<0, 4>> SizeField;

    static_assert(!SizeField::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::string<field_type<option::big_endian>, option::sequence_size_field_prefix<SizeField>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    BOOST_CHECK(testing_type::min_length() == SizeField::max_length());
    BOOST_CHECK(testing_type::max_length() == SizeField::max_length() + std::numeric_limits<std::uint16_t>::max());

    typedef types::string<field_type<option::big_endian>, option::sequence_size_field_prefix<SizeField>,
                          option::fixed_size_storage<256>>
        StaticStorageField;

    static_assert(!StaticStorageField::is_version_dependent(), "Invalid version dependency assumption");

    BOOST_CHECK(StaticStorageField::min_length() == SizeField::max_length());
    BOOST_CHECK(StaticStorageField::max_length() == SizeField::max_length() + 255);

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().empty());

    StaticStorageField staticStorageField;
    BOOST_CHECK(staticStorageField.valid());
    BOOST_CHECK(staticStorageField.value().empty());

    static const std::vector<char> Buf = {0x5, 'h', 'e', 'l', 'l', 'o', 'g', 'a', 'r'};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.value().size() == static_cast<std::size_t>(Buf[0]));
    BOOST_CHECK(field.length() == field.value().size() + 1U);
    BOOST_CHECK(!field.valid());
    BOOST_CHECK(field.value() == "hello");

    staticStorageField = pack<StaticStorageField>(Buf.begin(), Buf.end());
    BOOST_CHECK(staticStorageField.value().size() == static_cast<std::size_t>(Buf[0]));
    BOOST_CHECK(staticStorageField.length() == field.value().size() + 1U);
    BOOST_CHECK(!staticStorageField.valid());
    BOOST_CHECK(std::string(staticStorageField.value().c_str()) == std::string("hello"));
}

struct HelloInitialiser {
    template<typename TField>
    void operator()(TField &&field) {
        field.value() = "hello";
    }
};

BOOST_AUTO_TEST_CASE(types_accumulator_test18) {
    typedef types::integral<field_type<option::big_endian>, std::uint16_t> SizeField;

    static_assert(!SizeField::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::string<field_type<option::big_endian>, option::sequence_size_field_prefix<SizeField>,
                          option::default_value_initialiser<HelloInitialiser>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::string<field_type<option::big_endian>, option::sequence_size_field_prefix<SizeField>,
                          option::default_value_initialiser<HelloInitialiser>, option::fixed_size_storage<64>>
        StaticStorageField;

    static_assert(!StaticStorageField::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(!field.value().empty());
    BOOST_CHECK(field.value() == "hello");
    field.value().clear();
    BOOST_CHECK(field.value().empty());
    field.value() = "bla";
    BOOST_CHECK(field.value() == "bla");
    BOOST_CHECK(field.value().size() == 3);
    BOOST_CHECK(field.length() == 5);

    StaticStorageField staticStorageField;
    BOOST_CHECK(staticStorageField.valid());
    BOOST_CHECK(!staticStorageField.value().empty());
    BOOST_CHECK(std::string(staticStorageField.value().c_str()) == std::string("hello"));
    staticStorageField.value().clear();
    BOOST_CHECK(staticStorageField.value().empty());
    staticStorageField.value() = "bla";
    BOOST_CHECK(std::string(staticStorageField.value().c_str()) == std::string("bla"));
    BOOST_CHECK(staticStorageField.value().size() == 3);
    BOOST_CHECK(staticStorageField.length() == 5);

    static const std::vector<char> ExpectedBuf = {0x0, 0x3, 'b', 'l', 'a'};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
    write_read_field(staticStorageField, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test19) {
    typedef types::integral<field_type<option::big_endian>, std::uint8_t> SizeField;

    static_assert(!SizeField::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::string<field_type<option::big_endian>, option::sequence_size_field_prefix<SizeField>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::string<field_type<option::big_endian>, option::sequence_size_field_prefix<SizeField>,
                          option::fixed_size_storage<64>>
        StaticStorageField;

    static_assert(!StaticStorageField::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    auto &fieldStr = field.value();
    BOOST_CHECK(field.valid());
    BOOST_CHECK(fieldStr.empty());

    StaticStorageField staticStorageField;
    auto &staticStorageFieldStr = staticStorageField.value();
    BOOST_CHECK(staticStorageField.valid());
    BOOST_CHECK(staticStorageFieldStr.empty());

    static const std::string Str("hello");
    std::copy(Str.begin(), Str.end(), std::back_inserter(fieldStr));
    BOOST_CHECK(!fieldStr.empty());
    BOOST_CHECK(fieldStr.size() == Str.size());
    BOOST_CHECK(fieldStr == Str);

    std::copy(Str.begin(), Str.end(), std::back_inserter(staticStorageFieldStr));
    BOOST_CHECK(!staticStorageFieldStr.empty());
    BOOST_CHECK(staticStorageFieldStr.size() == Str.size());
    BOOST_CHECK(std::string(staticStorageFieldStr.c_str()) == std::string(Str.c_str()));

    static const std::vector<char> ExpectedBuf = {0x5, 'h', 'e', 'l', 'l', 'o'};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
    write_read_field(staticStorageField, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test20) {
    typedef types::integral<field_type<option::little_endian>, std::uint16_t, option::var_length<1, 2>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static const std::vector<char> Buf = {(char)0x81, 0x01};

    testing_type field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK_EQUAL(field.length(), 2U);
    BOOST_CHECK_EQUAL(field.value(), static_cast<std::uint16_t>(0x81));
    BOOST_CHECK(field.valid());

    field.value() = 0x7ff;
    BOOST_CHECK_EQUAL(field.length(), 2U);
    static const std::vector<char> ExpectedBuf = {(char)0xff, 0x0f};

    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test21) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t, option::var_length<1, 3>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static const std::vector<char> Buf = {(char)0x83, 0x0f};

    testing_type field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK_EQUAL(field.length(), 2U);
    BOOST_CHECK_EQUAL(field.value(), static_cast<std::uint32_t>(0x18f));
    BOOST_CHECK(field.valid());

    field.value() = 0x7ff;
    BOOST_CHECK_EQUAL(field.length(), 2U);
    static const std::vector<char> ExpectedBuf = {(char)0x8f, (char)0x7f};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    field.value() = 0x7f;
    BOOST_CHECK_EQUAL(field.length(), 1U);
    BOOST_CHECK_EQUAL(field.value(), 0x7f);
    static const std::vector<char> ExpectedBuf2 = {(char)0x7f};
    write_read_field(field, ExpectedBuf2.begin(), ExpectedBuf2.size());

    static const std::vector<char> Buf2 = {(char)0x91, (char)0xc2, (char)0x3f, (char)0xff};
    field = pack<testing_type>(Buf2.begin(), Buf2.end());
    BOOST_CHECK_EQUAL(field.length(), 3U);
    BOOST_CHECK_EQUAL(field.value(), static_cast<std::uint32_t>(0x4613f));
    BOOST_CHECK(field.valid());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test22) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t, option::var_length<1, 3>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static const std::vector<char> Buf = {(char)0x83, (char)0x8f, (char)0x8c, (char)0x3f, (char)0xff};
    testing_type field = pack<testing_type>(Buf.begin(), Buf.end(), status_type::protocol_error);
    static_cast<void>(field);
}

BOOST_AUTO_TEST_CASE(types_accumulator_test23) {
    typedef types::integral<field_type<option::little_endian>, std::int16_t, option::var_length<1, 2>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;

    field.value() = static_cast<int16_t>(0xe000);
    BOOST_CHECK_EQUAL(field.length(), 2U);

    static const std::vector<char> ExpectedMinValueBuf = {(char)0x80, (char)0x40};
    write_read_field(field, ExpectedMinValueBuf.begin(), ExpectedMinValueBuf.size());

    field.value() = 0x1fff;
    BOOST_CHECK_EQUAL(field.length(), 2U);

    static const std::vector<char> ExpectedMaxValueBuf = {(char)0xff, (char)0x3f};
    write_read_field(field, ExpectedMaxValueBuf.begin(), ExpectedMaxValueBuf.size());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test24) {
    typedef types::integral<field_type<option::big_endian>, unsigned, option::fixed_length<2>,
                             option::num_value_ser_offset<2>, option::valid_num_value_range<0, 2>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static const std::vector<char> Buf = {0x00, 0x02};

    testing_type field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == 2);
    BOOST_CHECK(field.value() == 0x0);
    BOOST_CHECK(field.valid());
    field.value() = 3;
    BOOST_CHECK(!field.valid());

    static const std::vector<char> ExpectedBuf = {0x00, 0x05};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(types_accumulator_test25) {
    typedef std::tuple<
        types::integral<field_type<option::big_endian>, std::uint8_t, option::fixed_bit_length<2>>,
        types::bitmask_value<field_type<option::big_endian>, option::fixed_length<1>, option::fixed_bit_length<6>>>
        BitfileMembers;

    typedef types::bitfield<field_type<option::big_endian>, BitfileMembers> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    static_cast<void>(field);
    BOOST_CHECK(field.length() == 1U);
    BOOST_CHECK(field.member_bit_length<0>() == 2U);
    BOOST_CHECK(field.member_bit_length<1>() == 6U);

    static const std::vector<char> Buf = {(char)0x41, (char)0xff};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    auto &members = field.value();
    auto &mem1 = std::get<0>(members);
    BOOST_CHECK(mem1.value() == 0x1);

    auto &mem2 = std::get<1>(members);
    BOOST_CHECK(mem2.value() == 0x10);
}

BOOST_AUTO_TEST_CASE(test26) {
    typedef std::tuple<
        types::integral<field_type<option::big_endian>, std::uint8_t, option::fixed_bit_length<3>>,
        types::bitmask_value<field_type<option::big_endian>, option::fixed_length<1>, option::fixed_bit_length<5>>>
        BitfileMembers;

    typedef types::bitfield<field_type<option::big_endian>, BitfileMembers> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    static_cast<void>(field);
    BOOST_CHECK(field.length() == 1U);
    BOOST_CHECK(field.member_bit_length<0>() == 3U);
    BOOST_CHECK(field.member_bit_length<1>() == 5U);

    static const std::vector<char> Buf = {(char)0x09, (char)0xff};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    auto &members = field.value();
    auto &mem1 = std::get<0>(members);
    BOOST_CHECK(mem1.value() == 0x1);

    auto &mem2 = std::get<1>(members);
    BOOST_CHECK(mem2.value() == 0x1);
}

using Test27_FieldBase = field_type<option::big_endian>;

typedef std::tuple<types::integral<Test27_FieldBase, std::uint8_t, option::fixed_bit_length<4>>,
                   types::bitmask_value<Test27_FieldBase, option::fixed_length<1>, option::fixed_bit_length<8>>,
                   types::enumeration<Test27_FieldBase, types_fixture::Enum1, option::fixed_bit_length<4>>>
    Test27_BitfildMembers;

template<typename... TExtraOpts>
class Test27_Field : public types::bitfield<Test27_FieldBase, Test27_BitfildMembers, TExtraOpts...> {
    using Base = types::bitfield<Test27_FieldBase, Test27_BitfildMembers, TExtraOpts...>;

public:
    MARSHALLING_FIELD_MEMBERS_ACCESS(mem1, mem2, mem3);
};

BOOST_AUTO_TEST_CASE(test27) {
    using testing_type = Test27_Field<>;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.length() == 2U);
    BOOST_CHECK(field.member_bit_length<testing_type::FieldIdx_mem1>() == 4U);
    BOOST_CHECK(field.member_bit_length<testing_type::FieldIdx_mem2>() == 8U);
    BOOST_CHECK(field.member_bit_length<testing_type::FieldIdx_mem3>() == 4U);

    static const std::vector<char> Buf = {(char)0x4f, (char)0xa1, (char)0xaa};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    auto &mem1 = field.field_mem1();
    BOOST_CHECK(mem1.value() == 0x1);

    auto &mem2 = field.field_mem2();
    BOOST_CHECK(mem2.value() == 0xfa);

    auto &mem3 = field.field_mem3();
    BOOST_CHECK(mem3.value() == 0x4);
}

BOOST_AUTO_TEST_CASE(test28) {
    typedef types::array_list<
        field_type<option::big_endian>,
        types::integral<field_type<option::big_endian>, std::uint8_t, option::valid_num_value_range<0, 5>>,
        option::sequence_size_field_prefix<types::integral<field_type<option::big_endian>, std::uint16_t>>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    BOOST_CHECK(testing_type::min_length() == sizeof(std::uint16_t));

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().size() == 0U);

    static const std::vector<char> Buf = {0x0, 0xa, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9};
    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == Buf.size());
    BOOST_CHECK(!field.valid());
    BOOST_CHECK(field.value().size() == 10U);

    field.value().resize(5);
    static const std::vector<char> ExpectedBuf = {0x0, 0x5, 0x0, 0x1, 0x2, 0x3, 0x4};
    BOOST_CHECK(field.valid());
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(test29) {
    typedef types::enumeration<field_type<option::big_endian>, Enum1, option::fixed_length<2>,
                              option::valid_num_value_range<0, Enum1_NumOfValues - 1>,
                              option::default_num_value<Enum1_Value2>,
                              option::fail_on_invalid<status_type::protocol_error>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value() == Enum1_Value2);

    static const std::vector<char> Buf = {0x0, (char)Enum1_Value1, (char)0x3f};
    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == 2);
    BOOST_CHECK(field.value() == Enum1_Value1);
    BOOST_CHECK(field.valid());

    static const std::vector<char> Buf2 = {0x0, (char)Enum1_NumOfValues, (char)0x3f};

    field = pack<testing_type>(Buf2.begin(), Buf2.end(), status_type::protocol_error);

    field.value() = Enum1_Value3;
    BOOST_CHECK(field.valid());

    static const std::vector<char> ExpectedBuf = {0x0, (char)Enum1_Value3};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(test30) {
    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::default_num_value<0x2>,
                             option::valid_num_value_range<0x2, 0x2>, option::ignore_invalid>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value() == 0x2);

    static const std::vector<char> Buf = {0x0f};

    field = pack<testing_type>(Buf.begin(), Buf.end());

    BOOST_CHECK(field.value() == 0x2);
    BOOST_CHECK(field.valid());

    static const std::vector<char> Buf2 = {0x00, 0x02, (char)0xff};

    field = pack<testing_type>(Buf2.begin(), Buf2.end());

    BOOST_CHECK(field.value() == 0x2);
    BOOST_CHECK(field.valid());
}

BOOST_AUTO_TEST_CASE(test31) {

    typedef types::optional<
        types::integral<field_type<option::big_endian>, std::uint16_t, option::valid_num_value_range<0, 10>>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    typedef testing_type::Mode Mode;

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.field().value() == 0U);
    BOOST_CHECK(field.get_mode() == Mode::tentative);

    static const std::vector<char> Buf = {0x0f, (char)0xf0};

    field = pack<testing_type>(Buf.begin(), Buf.end());

    BOOST_CHECK(field.field().value() == 0xff0);
    BOOST_CHECK(!field.valid());
    BOOST_CHECK(field.get_mode() == Mode::exists);
    field.set_mode(Mode::missing);
}

BOOST_AUTO_TEST_CASE(test32) {

    typedef types::bundle<
        field_type<option::big_endian>,
        std::tuple<types::integral<field_type<option::big_endian>, std::uint16_t, option::valid_num_value_range<0, 10>,
                                    option::default_num_value<5>>,
                   types::enumeration<field_type<option::big_endian>, Enum1, option::fixed_length<1>,
                                     option::valid_num_value_range<0, Enum1_NumOfValues - 1>,
                                     option::default_num_value<Enum1_Value2>>>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static_assert(testing_type::min_length() == 3U, "Invalid min_length");
    static_assert(testing_type::min_length_from<1>() == 1U, "Invalid min_length");
    static_assert(testing_type::min_length_until<1>() == 2U, "Invalid min_length");
    static_assert(testing_type::max_length() == 3U, "Invalid max_length");
    static_assert(testing_type::max_length_from<1>() == 1U, "Invalid min_length");
    static_assert(testing_type::max_length_until<1>() == 2U, "Invalid min_length");

    testing_type field;
    BOOST_CHECK(field.length() == 3U);
    BOOST_CHECK(field.length_from<1>() == 1U);
    BOOST_CHECK(field.length_until<1>() == 2U);
    BOOST_CHECK(field.valid());
    auto &intValField = std::get<0>(field.value());
    auto &enumValField = std::get<1>(field.value());
    BOOST_CHECK(intValField.value() == 5U);
    BOOST_CHECK(enumValField.value() == Enum1_Value2);

    intValField.value() = 50U;
    BOOST_CHECK(!field.valid());
    intValField.value() = 1U;
    BOOST_CHECK(field.valid());
    enumValField.value() = Enum1_NumOfValues;
    BOOST_CHECK(!field.valid());

    static const std::vector<char> Buf = {0x00, 0x3, Enum1_Value3, (char)0xff};

    field = pack<testing_type>(Buf.begin(), Buf.end());

    BOOST_CHECK(field.length() == 3U);
    BOOST_CHECK(field.valid());
    BOOST_CHECK(intValField.value() == 3U);
    BOOST_CHECK(enumValField.value() == Enum1_Value3);

    intValField.value() = 0xabcd;
    enumValField.value() = Enum1_Value1;

    static const std::vector<char> ExpectedBuf = {(char)0xab, (char)0xcd, (char)Enum1_Value1};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    testing_type fieldTmp;
    auto readIter = &ExpectedBuf[0];
    status_type es = fieldTmp.read_from_until<0, 2>(readIter, ExpectedBuf.size());
    BOOST_CHECK(es == status_type::success);
    BOOST_CHECK(fieldTmp == field);

    fieldTmp = testing_type();
    BOOST_CHECK(fieldTmp != field);

    readIter = &ExpectedBuf[0];
    es = fieldTmp.read_until<1>(readIter, 2);
    BOOST_CHECK(es == status_type::success);
    es = fieldTmp.read_from<1>(readIter, 1);
    BOOST_CHECK(es == status_type::success);
    BOOST_CHECK(fieldTmp == field);

    std::vector<std::uint8_t> outBuf;
    auto writeIter = std::back_inserter(outBuf);
    es = fieldTmp.write_from_until<0, 2>(writeIter, outBuf.max_size());
    BOOST_CHECK(es == status_type::success);
    BOOST_CHECK(outBuf.size() == ExpectedBuf.size());
    BOOST_CHECK(std::equal(outBuf.begin(), outBuf.end(), (const std::uint8_t *)&ExpectedBuf[0]));

    outBuf.clear();
    writeIter = std::back_inserter(outBuf);
    es = fieldTmp.write_until<1>(writeIter, outBuf.max_size());
    BOOST_CHECK(es == status_type::success);
    es = fieldTmp.write_from<1>(writeIter, outBuf.max_size());
    BOOST_CHECK(es == status_type::success);
    BOOST_CHECK(outBuf.size() == ExpectedBuf.size());
    BOOST_CHECK(std::equal(outBuf.begin(), outBuf.end(), (const std::uint8_t *)&ExpectedBuf[0]));
}

BOOST_AUTO_TEST_CASE(test33) {
    typedef types::integral<field_type<option::big_endian>, std::uint8_t> SizeField;

    static_assert(!SizeField::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::string<field_type<option::big_endian>, option::sequence_size_field_prefix<SizeField>> StringField;

    static_assert(!StringField::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::array_list<field_type<option::big_endian>, StringField> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    BOOST_CHECK(testing_type::min_length() == 0U);
    BOOST_CHECK(testing_type::max_length() == 0xffff * StringField::max_length());

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().empty());

    static const std::vector<char> Buf = {0x05, 'h', 'e', 'l', 'l', 'o', 0x03, 'b', 'l', 'a'};

    field = pack<testing_type>(Buf.begin(), Buf.end());

    BOOST_CHECK(field.length() == Buf.size());
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value()[0].value() == "hello");
    BOOST_CHECK(field.value()[1].value() == "bla");
}

BOOST_AUTO_TEST_CASE(test34) {
    typedef types::array_list<field_type<option::big_endian>, types::integral<field_type<option::big_endian>, std::uint8_t>,
                              option::sequence_size_forcing_enabled>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().empty());
    static const std::size_t MaxCount = 5;
    field.force_read_elem_count(MaxCount);

    accumulator_set<testing_type> acc = accumulator_set<testing_type>(field);

    static const std::vector<char> Buf = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9};

    field = pack<testing_type>(Buf.begin(), Buf.end(), acc);

    BOOST_CHECK(field.length() == MaxCount);
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().size() == MaxCount);
}

BOOST_AUTO_TEST_CASE(test35) {
    typedef types::float_value<field_type<option::big_endian>, float> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(fpEquals(field.value(), 0.0f));
    field.value() = 1.23f;
    BOOST_CHECK(fpEquals(field.value(), 1.23f));

    std::vector<std::uint8_t> buf;
    auto writeIter = std::back_inserter(buf);
    status_type es = field.write(writeIter, buf.max_size());
    BOOST_CHECK(es == status_type::success);
    BOOST_CHECK(buf.size() == sizeof(float));

    field = testing_type();
    BOOST_CHECK(fpEquals(field.value(), 0.0f));

    const auto *readIter = &buf[0];
    field = pack<testing_type>(buf.begin(), buf.end());

    BOOST_CHECK(fpEquals(field.value(), 1.23f));
}

BOOST_AUTO_TEST_CASE(test36) {
    typedef types::array_list<field_type<option::big_endian>, std::uint8_t, option::sequence_fixed_size<5>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static_assert(testing_type::min_length() == 5U, "Invalid min length");
    static_assert(testing_type::max_length() == 5U, "Invalid max length");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(testing_type::min_length() == 5U);
    BOOST_CHECK(testing_type::max_length() == 5U);

    static const std::vector<char> Buf = {0x0, 0x1, 0x2, 0x3, 0x4};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == Buf.size());
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().size() == Buf.size());

    BOOST_CHECK(!field.refresh());
}

BOOST_AUTO_TEST_CASE(test37) {
    typedef types::array_list<field_type<option::big_endian>, types::integral<field_type<option::big_endian>, std::uint16_t>,
                              option::sequence_fixed_size<3>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static_assert(testing_type::min_length() == 6U, "Invalid min length");
    static_assert(testing_type::max_length() == 6U, "Invalid max length");

    testing_type field;
    BOOST_CHECK(field.valid());

    static const std::vector<char> Buf = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9};
    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == 6U);
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().size() == 3U);
    BOOST_CHECK((field.value())[0].value() == 0x1);
    BOOST_CHECK((field.value())[1].value() == 0x203);
    BOOST_CHECK((field.value())[2].value() == 0x405);
}

BOOST_AUTO_TEST_CASE(test38) {
    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::valid_num_value_range<0, 0>> TrailField;

    static_assert(!TrailField::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::string<field_type<option::big_endian>, option::sequence_fixed_size<5>,
                          option::sequence_trailing_field_suffix<TrailField>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static_assert(std::is_same<testing_type::value_type, std::string>::value, "Invalid storage assumption assumption");

    static_assert(testing_type::min_length() == 6U, "Invalid min length");
    static_assert(testing_type::max_length() == 6U, "Invalid max length");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.length() == 6U);

    field.value() = "hello";
    BOOST_CHECK(field.length() == 6U);

    static const std::vector<char> ExpectedBuf = {'h', 'e', 'l', 'l', 'o', 0x0};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    field.value() = "foo";
    BOOST_CHECK(field.length() == 6U);

    static const std::vector<char> ExpectedBuf2 = {'f', 'o', 'o', 0x0, 0x0, 0x0};
    write_read_field(field, ExpectedBuf2.begin(), ExpectedBuf2.size());

    field = pack<testing_type>(ExpectedBuf2.begin(), ExpectedBuf2.end());
    BOOST_CHECK(field.value() == "foo");
}

BOOST_AUTO_TEST_CASE(test39) {
    typedef types::float_value<field_type<option::big_endian>, float, option::valid_num_value_range<5, 10>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(fpEquals(field.value(), 0.0f));
    BOOST_CHECK(!field.valid());
    field.value() = 4.999999f;
    BOOST_CHECK(fpEquals(field.value(), 4.999999f));
    BOOST_CHECK(!field.valid());
    field.value() = 5.00001f;
    BOOST_CHECK(fpEquals(field.value(), 5.00001f));
    BOOST_CHECK(field.valid());
}

BOOST_AUTO_TEST_CASE(test40) {
    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<1, 100>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.value() == 0U);
    BOOST_CHECK(field.scale_as<double>() == 0.0);

    field.set_scaled(0.15);
    BOOST_CHECK(field.value() == 15U);

    static const std::vector<char> Buf = {115};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.value() == 115);
    BOOST_CHECK(fpEquals(field.scale_as<float>(), 1.15f));
}

BOOST_AUTO_TEST_CASE(test41) {
    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::valid_num_value_range<0, 0>> TermField;

    static_assert(!TermField::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::string<field_type<option::big_endian>, option::sequence_termination_field_suffix<TermField>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.length() == 1U);

    field.value() = "hello";
    BOOST_CHECK(field.length() == 6U);

    static const std::vector<char> ExpectedBuf = {'h', 'e', 'l', 'l', 'o', 0x0};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    static const std::vector<char> InputBuf = {'f', 'o', 'o', 0x0, 'b', 'l', 'a'};

    field = pack<testing_type>(InputBuf.begin(), InputBuf.end());

    BOOST_CHECK(field.value() == "foo");
    BOOST_CHECK(field.value().size() == 3U);
}

BOOST_AUTO_TEST_CASE(test42) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t, option::var_length<1, 4>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.value() == 0U);
    BOOST_CHECK(field.length() == 1U);

    field.value() = 127U;
    BOOST_CHECK(field.length() == 1U);
    static const std::vector<char> ExpectedBuf1 = {(char)0x7f};

    write_read_field(field, ExpectedBuf1.begin(), ExpectedBuf1.size());

    field.value() = 128U;
    BOOST_CHECK(field.length() == 2U);
    static const std::vector<char> ExpectedBuf2 = {(char)0x81, 0x00};

    write_read_field(field, ExpectedBuf2.begin(), ExpectedBuf2.size());

    field.value() = 0x3fff;
    BOOST_CHECK(field.length() == 2U);
    static const std::vector<char> ExpectedBuf3 = {(char)0xff, (char)0x7f};

    write_read_field(field, ExpectedBuf3.begin(), ExpectedBuf3.size());

    field.value() = 0x4000;
    BOOST_CHECK(field.length() == 3U);
    static const std::vector<char> ExpectedBuf4 = {(char)0x81, (char)0x80, (char)0x00};

    write_read_field(field, ExpectedBuf4.begin(), ExpectedBuf4.size());

    field.value() = 0x1fffff;
    BOOST_CHECK(field.length() == 3U);
    static const std::vector<char> ExpectedBuf5 = {(char)0xff, (char)0xff, (char)0x7f};

    write_read_field(field, ExpectedBuf5.begin(), ExpectedBuf5.size());

    field.value() = 0x200000;
    BOOST_CHECK(field.length() == 4U);
    static const std::vector<char> ExpectedBuf6 = {(char)0x81, (char)0x80, (char)0x80, (char)0x00};

    write_read_field(field, ExpectedBuf6.begin(), ExpectedBuf6.size());
}

BOOST_AUTO_TEST_CASE(test43) {
    typedef types::integral<field_type<option::little_endian>, std::uint32_t, option::var_length<1, 4>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.value() == 0U);
    BOOST_CHECK(field.length() == 1U);

    field.value() = 127U;
    BOOST_CHECK(field.length() == 1U);
    static const std::vector<char> ExpectedBuf1 = {(char)0x7f};

    write_read_field(field, ExpectedBuf1.begin(), ExpectedBuf1.size());

    field.value() = 128U;
    BOOST_CHECK(field.length() == 2U);
    static const std::vector<char> ExpectedBuf2 = {(char)0x80, 0x01};

    write_read_field(field, ExpectedBuf2.begin(), ExpectedBuf2.size());

    field.value() = 0x3fff;
    BOOST_CHECK(field.length() == 2U);
    static const std::vector<char> ExpectedBuf3 = {(char)0xff, (char)0x7f};

    write_read_field(field, ExpectedBuf3.begin(), ExpectedBuf3.size());

    field.value() = 0x4000;
    BOOST_CHECK(field.length() == 3U);
    static const std::vector<char> ExpectedBuf4 = {(char)0x80, (char)0x80, (char)0x01};

    write_read_field(field, ExpectedBuf4.begin(), ExpectedBuf4.size());

    field.value() = 0x1fffff;
    BOOST_CHECK(field.length() == 3U);
    static const std::vector<char> ExpectedBuf5 = {(char)0xff, (char)0xff, (char)0x7f};

    write_read_field(field, ExpectedBuf5.begin(), ExpectedBuf5.size());

    field.value() = 0x200000;
    BOOST_CHECK(field.length() == 4U);
    static const std::vector<char> ExpectedBuf6 = {(char)0x80, (char)0x80, (char)0x80, (char)0x01};

    write_read_field(field, ExpectedBuf6.begin(), ExpectedBuf6.size());
}

BOOST_AUTO_TEST_CASE(test44) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t, option::var_length<2, 4>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.value() == 0U);
    BOOST_CHECK(field.length() == 2U);

    static const std::vector<char> ExpectedBuf1 = {(char)0x80, 0x00};

    write_read_field(field, ExpectedBuf1.begin(), ExpectedBuf1.size());

    field.value() = 127U;
    BOOST_CHECK(field.length() == 2U);
    static const std::vector<char> ExpectedBuf2 = {(char)0x80, 0x7f};

    write_read_field(field, ExpectedBuf2.begin(), ExpectedBuf2.size());

    field.value() = 128U;
    BOOST_CHECK(field.length() == 2U);
    static const std::vector<char> ExpectedBuf3 = {(char)0x81, 0x00};

    write_read_field(field, ExpectedBuf3.begin(), ExpectedBuf3.size());
}

BOOST_AUTO_TEST_CASE(test45) {
    typedef types::integral<field_type<option::little_endian>, std::uint32_t, option::var_length<2, 4>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.value() == 0U);
    BOOST_CHECK(field.length() == 2U);

    static const std::vector<char> ExpectedBuf1 = {(char)0x80, 0x00};

    write_read_field(field, ExpectedBuf1.begin(), ExpectedBuf1.size());

    field.value() = 127U;
    BOOST_CHECK(field.length() == 2U);
    static const std::vector<char> ExpectedBuf2 = {(char)0xff, 0x00};

    write_read_field(field, ExpectedBuf2.begin(), ExpectedBuf2.size());

    field.value() = 128U;
    BOOST_CHECK(field.length() == 2U);
    static const std::vector<char> ExpectedBuf3 = {(char)0x80, 0x01};

    write_read_field(field, ExpectedBuf3.begin(), ExpectedBuf3.size());
}

BOOST_AUTO_TEST_CASE(test46) {
    typedef types::no_value<field_type<option::big_endian>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;

    static const std::vector<char> ExpectedBuf = {0};
    write_read_field(field, ExpectedBuf.begin(), 0);
}

struct BundleInitialiserTest47 {
    template<typename TField>
    void operator()(TField &field) const {
        auto &members = field.value();
        auto &first = std::get<0>(members);
        auto &second = std::get<1>(members);
        first.value() = 1;
        second.value() = 2;
    }
};

BOOST_AUTO_TEST_CASE(test47) {
    typedef types::bundle<field_type<option::big_endian>,
                          std::tuple<types::integral<field_type<option::big_endian>, std::uint16_t>,
                                     types::integral<field_type<option::big_endian>, std::uint8_t>>,
                          option::default_value_initialiser<BundleInitialiserTest47>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    BOOST_CHECK(testing_type::min_length() == 3U);
    BOOST_CHECK(testing_type::max_length() == 3U);

    testing_type field;

    static const std::vector<char> ExpectedBuf = {(char)0x0, (char)0x1, (char)0x2};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(test48) {

    typedef types::optional<types::integral<field_type<option::big_endian>, std::uint16_t>,
                            option::default_optional_mode<types::optional_mode::exists>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    typedef testing_type::Mode Mode;

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.field().value() == 0U);
    BOOST_CHECK(field.get_mode() == Mode::exists);

    field.field().value() = 0xff0;

    static const std::vector<char> Buf = {0x0f, (char)0xf0};

    write_read_field(field, Buf.begin(), Buf.size());
}

struct BundleCustomReaderTest49 {
    template<typename TField, typename TIter>
    status_type operator()(TField &field, TIter &iter, std::size_t len) const {
        auto &members = field.value();
        auto &first = std::get<0>(members);
        auto &second = std::get<1>(members);

        status_type es = first.read(iter, len);
        if (es != status_type::success) {
            return es;
        }

        if (first.value() != 0) {
            second.set_mode(types::optional_mode::missing);
        } else {
            second.set_mode(types::optional_mode::exists);
        }
        return second.read(iter, len - first.length());
    }
};

BOOST_AUTO_TEST_CASE(test49) {

    typedef types::bundle<field_type<option::big_endian>,
                          std::tuple<types::integral<field_type<option::big_endian>, std::uint8_t>,
                                     types::optional<types::integral<field_type<option::big_endian>, std::uint16_t>>>,
                          option::custom_value_reader<BundleCustomReaderTest49>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static_assert(testing_type::min_length() == 1U, "Invalid min_length");
    static_assert(testing_type::max_length() == 3U, "Invalid max_length");
    static_assert(testing_type::min_length_until<1>() == 1U, "Invalid min_length");
    static_assert(testing_type::max_length_until<1>() == 1U, "Invalid max_length");
    static_assert(testing_type::min_length_from<1>() == 0U, "Invalid min_length");
    static_assert(testing_type::max_length_from<1>() == 2U, "Invalid max_length");

    testing_type field;
    BOOST_CHECK(field.valid());
    auto &mem1 = std::get<0>(field.value());
    auto &mem2 = std::get<1>(field.value());

    static const std::vector<char> Buf = {0x00, 0x10, 0x20, (char)0xff};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == 3U);
    BOOST_CHECK(mem1.value() == 0U);
    BOOST_CHECK(mem2.field().value() == 0x1020);
    BOOST_CHECK(mem2.get_mode() == types::optional_mode::exists);

    accumulator_set<testing_type> acc = accumulator_set<testing_type>(field);

    static const std::vector<char> Buf2 = {0x01, 0x10, 0x20, (char)0xff};

    field = pack<testing_type>(Buf2.begin(), Buf2.end(), acc);
    BOOST_CHECK(field.length() == 1U);
    BOOST_CHECK(mem1.value() == 1U);
    BOOST_CHECK(mem2.get_mode() == types::optional_mode::missing);
}

struct Test50_Field : public types::bitmask_value<field_type<option::big_endian>, option::fixed_length<1>> {
    MARSHALLING_BITMASK_BITS(first, second, third, fourth, sixth = 5, seventh, eighth);

    MARSHALLING_BITMASK_BITS_ACCESS_NOTEMPLATE(first, second, third, fourth, sixth, seventh, eighth);
};

template<typename... TExtraOpts>
class Test50_Field2
    : public types::bitmask_value<field_type<option::big_endian>, option::fixed_length<1>, TExtraOpts...> {
    using Base = types::bitmask_value<field_type<option::big_endian>, option::fixed_length<1>, TExtraOpts...>;

public:
    MARSHALLING_BITMASK_BITS_SEQ(first, second, third, fourth, fifth, sixth, seventh, eighth);
};

BOOST_AUTO_TEST_CASE(test50) {
    using testing_type = Test50_Field;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    field.value() = 0xaa;
    BOOST_CHECK(field.getBitValue_first() == false);
    BOOST_CHECK(field.getBitValue_second() == true);
    BOOST_CHECK(field.getBitValue_third() == false);
    BOOST_CHECK(field.getBitValue_fourth() == true);
    BOOST_CHECK(field.getBitValue_sixth() == true);
    BOOST_CHECK(field.getBitValue_seventh() == false);
    BOOST_CHECK(field.getBitValue_eighth() == true);

    field.set_bit_value_first(true);
    field.set_bit_value_second(false);
    field.set_bit_value_third(true);
    field.set_bit_value_fourth(false);
    field.set_bit_value_sixth(false);
    field.set_bit_value_seventh(true);
    field.set_bit_value_eighth(false);

    BOOST_CHECK(field.value() == 0x45);

    using Field2 = Test50_Field2<>;
    Field2 field2;
    static_cast<void>(field2);

    static_assert(!Field2::is_version_dependent(), "Invalid version dependency assumption");
}

class Field_51
    : public types::bitfield<field_type<types_fixture::BigEndianOpt>,
                             std::tuple<types::integral<field_type<types_fixture::BigEndianOpt>, std::uint8_t,
                                                         option::fixed_bit_length<2>>,
                                        types::bitmask_value<field_type<types_fixture::BigEndianOpt>,
                                                             option::fixed_length<1>, option::fixed_bit_length<6>>>> {
public:
    MARSHALLING_FIELD_MEMBERS_ACCESS_NOTEMPLATE(name1, name2)
};

BOOST_AUTO_TEST_CASE(test51) {
    typedef Field_51 testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.length() == 1U);
    BOOST_CHECK(field.member_bit_length<testing_type::FieldIdx_name1>() == 2U);
    BOOST_CHECK(field.member_bit_length<testing_type::FieldIdx_name2>() == 6U);

    static const std::vector<char> Buf = {(char)0x41, (char)0xff};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    auto &mem1 = field.field_name1();
    BOOST_CHECK(mem1.value() == 0x1);

    auto &mem2 = field.field_name2();
    BOOST_CHECK(mem2.value() == 0x10);
}

BOOST_AUTO_TEST_CASE(test52) {
    typedef std::tuple<types::integral<field_type<option::big_endian>, std::uint8_t, option::fixed_bit_length<8>>,
                       types::integral<field_type<option::big_endian>, std::int8_t, option::fixed_bit_length<8>>>
        BitfildMembers;

    typedef types::bitfield<field_type<option::big_endian>, BitfildMembers> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    static_cast<void>(field);
    BOOST_CHECK(field.length() == 2U);
    BOOST_CHECK(field.member_bit_length<0>() == 8U);
    BOOST_CHECK(field.member_bit_length<1>() == 8U);

    static const std::vector<char> Buf = {(char)0xff, (char)0xff};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    auto &members = field.value();
    auto &mem1 = std::get<0>(members);
    BOOST_CHECK(mem1.value() == 255);

    auto &mem2 = std::get<1>(members);
    BOOST_CHECK(mem2.value() == -1);
}

BOOST_AUTO_TEST_CASE(test53) {
    typedef types::integral<field_type<option::little_endian>, std::int32_t, option::fixed_bit_length<23>,
                             option::scaling_ratio<180, 0x800000>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field(std::numeric_limits<std::int32_t>::max());
    static const double ExpVal1 = (static_cast<double>(std::numeric_limits<std::int32_t>::max()) * 180) / 0x800000;
    BOOST_CHECK(field.scale_as<double>() == ExpVal1);
}

BOOST_AUTO_TEST_CASE(test54) {
    typedef types::integral<field_type<option::big_endian>, std::int8_t, option::scaling_ratio<100, 1>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field(1);

    BOOST_CHECK(field.value() == 1);
    BOOST_CHECK(field.scale_as<int>() == 100);

    field.set_scaled(1000);
    BOOST_CHECK(field.value() == 10);

    field.set_scaled(260.38);
    BOOST_CHECK(field.value() == 2);

    field.set_scaled(-200.00);
    BOOST_CHECK(field.value() == -2);
}

BOOST_AUTO_TEST_CASE(test55) {
    typedef types::integral<field_type<option::big_endian>, std::int16_t, option::scaling_ratio<1, 100>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;

    field.set_scaled(-0.1);
    BOOST_CHECK(field.value() == -10);

    field.value() = -123;
    BOOST_CHECK(field.scale_as<float>() == -1.23f);
}

BOOST_AUTO_TEST_CASE(test56) {
    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::valid_num_value_range<0, 0>> TrailField;

    static_assert(!TrailField::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::string<field_type<option::big_endian>, option::sequence_fixed_size<5>, option::fixed_size_storage<5>,
                          option::sequence_trailing_field_suffix<TrailField>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static_assert(testing_type::min_length() == 6U, "Invalid min length");
    static_assert(testing_type::max_length() == 6U, "Invalid max length");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.length() == 6U);

    field.value() = "hello";
    BOOST_CHECK(field.length() == 6U);

    static const std::vector<char> ExpectedBuf = {'h', 'e', 'l', 'l', 'o', 0x0};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    field.value() = "foo";
    BOOST_CHECK(field.length() == 6U);

    static const std::vector<char> ExpectedBuf2 = {'f', 'o', 'o', 0x0, 0x0, 0x0};
    write_read_field(field, ExpectedBuf2.begin(), ExpectedBuf2.size());

    field = pack<testing_type>(ExpectedBuf2.begin(), ExpectedBuf2.end());

    BOOST_CHECK(field.value() == "foo");
}

BOOST_AUTO_TEST_CASE(test57) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t, option::scaling_ratio<1, 10>,
                             option::units_milliseconds>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static const std::uint32_t InitVal = 600000;
    testing_type field;
    field.value() = InitVal;
    BOOST_CHECK(units::get_milliseconds<unsigned>(field) == InitVal / 10);
    BOOST_CHECK(units::get_microseconds<unsigned long>(field) == (InitVal * 1000L) / 10);
    BOOST_CHECK(units::get_nanoseconds<unsigned long long>(field) == (InitVal * 1000ULL * 1000) / 10);
    BOOST_CHECK(units::get_seconds<unsigned>(field) == InitVal / (10 * 1000));
    BOOST_CHECK(units::get_minutes<unsigned>(field) == InitVal / (10 * 60 * 1000));
    BOOST_CHECK(units::get_hours<double>(field) == (double)InitVal / (10 * 60 * 60 * 1000));
    BOOST_CHECK(units::get_days<double>(field) == (double)InitVal / (10 * 24L * 60 * 60 * 1000));
    BOOST_CHECK(units::get_weeks<double>(field) == (double)InitVal / (10 * 7ULL * 24 * 60 * 60 * 1000));

    units::set_nanoseconds(field, 500000U);
    BOOST_CHECK(units::get_nanoseconds<unsigned>(field) == 500000U);
    BOOST_CHECK(field.value() == 5);

    units::set_microseconds(field, 300U);
    BOOST_CHECK(units::get_microseconds<unsigned>(field) == 300U);
    BOOST_CHECK(field.value() == 3);

    units::set_milliseconds(field, 100U);
    BOOST_CHECK(units::get_milliseconds<unsigned>(field) == 100U);
    BOOST_CHECK(std::abs(units::get_seconds<float>(field) - 0.1f) <= std::numeric_limits<float>::epsilon());
    BOOST_CHECK(field.value() == 1000);

    units::set_seconds(field, 1.2);
    BOOST_CHECK(std::abs(units::get_seconds<float>(field) - 1.2f) <= std::numeric_limits<float>::epsilon());
    BOOST_CHECK(units::get_milliseconds<unsigned>(field) == 1200U);
    BOOST_CHECK(field.value() == 12000);

    units::set_minutes(field, (double)1 / 3);
    BOOST_CHECK(std::abs(units::get_minutes<double>(field) - (double)1 / 3) <= std::numeric_limits<double>::epsilon());
    BOOST_CHECK(std::abs(units::get_hours<double>(field) - (double)1 / (3 * 60))
                <= std::numeric_limits<double>::epsilon());
    BOOST_CHECK(units::get_seconds<unsigned>(field) == 20U);
    BOOST_CHECK(units::get_milliseconds<unsigned>(field) == 20000U);
    BOOST_CHECK(field.value() == 200000);

    units::set_hours(field, 0.5f);
    BOOST_CHECK(std::abs(units::get_hours<double>(field) - 0.5) <= std::numeric_limits<double>::epsilon());
    BOOST_CHECK(units::get_minutes<unsigned>(field) == 30U);
    BOOST_CHECK(units::get_seconds<unsigned>(field) == 30U * 60U);
    BOOST_CHECK(units::get_milliseconds<unsigned>(field) == 30U * 60U * 1000U);
    BOOST_CHECK(field.value() == 30U * 60U * 1000U * 10U);

    units::set_days(field, (float)1 / 3);
    BOOST_CHECK(std::abs(units::get_days<double>(field) - (double)1 / 3) <= std::numeric_limits<double>::epsilon());
    BOOST_CHECK(units::get_hours<unsigned>(field) == 8U);
    BOOST_CHECK(units::get_minutes<unsigned>(field) == 8U * 60);
    BOOST_CHECK(units::get_seconds<unsigned>(field) == 8U * 60U * 60U);
    BOOST_CHECK(units::get_milliseconds<unsigned long>(field) == 8UL * 60U * 60U * 1000U);
    BOOST_CHECK(field.value() == 8UL * 60U * 60U * 1000U * 10U);

    units::set_weeks(field, (double)2 / 7);
    BOOST_CHECK(std::abs(units::get_weeks<double>(field) - (double)2 / 7) <= std::numeric_limits<double>::epsilon());
    BOOST_CHECK(units::get_days<unsigned>(field) == 2U);
    BOOST_CHECK(units::get_hours<unsigned>(field) == 2U * 24U);
    BOOST_CHECK(units::get_minutes<unsigned>(field) == 2U * 24 * 60);
    BOOST_CHECK(units::get_seconds<unsigned long>(field) == 2UL * 24U * 60U * 60U);
    BOOST_CHECK(units::get_milliseconds<unsigned long>(field) == 2UL * 24U * 60U * 60U * 1000U);
    BOOST_CHECK(field.value() == 2UL * 24U * 60U * 60U * 1000U * 10U);
}

BOOST_AUTO_TEST_CASE(test58) {

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<100, 1>,
                             option::units_nanoseconds>
        Field1;

    static_assert(!Field1::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field1 field(1U);
        BOOST_CHECK(field.value() == 1U);
        BOOST_CHECK(units::get_nanoseconds<unsigned>(field) == 100U);
        BOOST_CHECK(std::abs(units::get_microseconds<double>(field) - 0.1) <= std::numeric_limits<double>::epsilon());
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<100, 1>,
                             option::units_microseconds>
        Field2;

    static_assert(!Field2::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field2 field(5U);
        BOOST_CHECK(field.value() == 5U);
        BOOST_CHECK(units::get_microseconds<unsigned>(field) == 500U);
        BOOST_CHECK(std::abs(units::get_milliseconds<double>(field) - 0.5) <= std::numeric_limits<double>::epsilon());
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::units_milliseconds> Field3;

    static_assert(!Field3::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field3 field(200U);
        BOOST_CHECK(field.value() == 200U);
        BOOST_CHECK(units::get_milliseconds<unsigned>(field) == 200U);
        BOOST_CHECK(std::abs(units::get_seconds<double>(field) - 0.2) <= std::numeric_limits<double>::epsilon());
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<1, 10>,
                             option::units_seconds>
        Field4;

    static_assert(!Field4::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field4 field(1U);
        BOOST_CHECK(field.value() == 1U);
        BOOST_CHECK(std::abs(units::get_seconds<double>(field) - 0.1) <= std::numeric_limits<double>::epsilon());
        BOOST_CHECK(units::get_milliseconds<unsigned>(field) == 100U);
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<1, 10>,
                             option::units_minutes>
        Field5;

    static_assert(!Field5::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field5 field(1U);
        BOOST_CHECK(field.value() == 1U);
        BOOST_CHECK(std::abs(units::get_minutes<double>(field) - 0.1) <= std::numeric_limits<double>::epsilon());
        BOOST_CHECK(units::get_seconds<unsigned>(field) == 6U);
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<1, 10>, option::units_hours>
        Field6;

    static_assert(!Field6::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field6 field(1U);
        BOOST_CHECK(field.value() == 1U);
        BOOST_CHECK(std::abs(units::get_hours<double>(field) - 0.1) <= std::numeric_limits<double>::epsilon());
        BOOST_CHECK(units::get_seconds<unsigned>(field) == 6U * 60U);
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<1, 12>, option::units_days>
        Field7;

    static_assert(!Field7::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field7 field(1U);
        BOOST_CHECK(field.value() == 1U);
        BOOST_CHECK(std::abs(units::get_days<double>(field) - (double)1 / 12)
                    <= std::numeric_limits<double>::epsilon());
        BOOST_CHECK(units::get_hours<unsigned>(field) == 2U);
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::units_weeks> Field8;

    static_assert(!Field8::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field8 field(1U);
        BOOST_CHECK(field.value() == 1U);
        BOOST_CHECK(units::get_weeks<unsigned>(field) == 1U);
        BOOST_CHECK(units::get_hours<unsigned>(field) == 24U * 7U);
    } while (false);
}

BOOST_AUTO_TEST_CASE(test59) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t, option::units_millimeters> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    field.value() = 345U;
    BOOST_CHECK(units::get_nanometers<unsigned long long>(field) == 345000000UL);
    BOOST_CHECK(units::get_micrometers<unsigned>(field) == 345000U);
    BOOST_CHECK(units::get_millimeters<unsigned>(field) == 345U);
    BOOST_CHECK(std::abs(units::get_centimeters<double>(field) - 34.5) <= std::numeric_limits<double>::epsilon());
    BOOST_CHECK(std::abs(units::getMeters<double>(field) - 0.345) <= std::numeric_limits<double>::epsilon());
    BOOST_CHECK(std::abs(units::getKilometers<double>(field) - 0.000345) <= std::numeric_limits<double>::epsilon());

    units::set_nanometers(field, 100000000UL);
    BOOST_CHECK(field.value() == 100U);
    BOOST_CHECK(units::get_millimeters<unsigned>(field) == 100U);

    units::set_micrometers(field, 222000UL);
    BOOST_CHECK(field.value() == 222U);
    BOOST_CHECK(units::get_millimeters<unsigned>(field) == 222U);

    units::set_millimeters(field, 400);
    BOOST_CHECK(field.value() == 400U);
    BOOST_CHECK(units::get_micrometers<unsigned>(field) == 400000U);

    units::setCentimeters(field, 10);
    BOOST_CHECK(units::get_millimeters<unsigned>(field) == 100U);

    units::setMeters(field, 0.025);
    BOOST_CHECK(units::get_millimeters<unsigned>(field) == 25U);

    units::setKilometers(field, 0.025);
    BOOST_CHECK(units::getMeters<unsigned>(field) == 25U);
}

BOOST_AUTO_TEST_CASE(test60) {
    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<100, 1>,
                             option::units_nanometers>
        Field1;

    static_assert(!Field1::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field1 field(1U);
        BOOST_CHECK(field.value() == 1U);
        BOOST_CHECK(units::get_nanometers<unsigned>(field) == 100U);
        BOOST_CHECK(std::abs(units::get_micrometers<double>(field) - 0.1) <= std::numeric_limits<double>::epsilon());
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<100, 1>,
                             option::units_micrometers>
        Field2;

    static_assert(!Field2::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field2 field(5U);
        BOOST_CHECK(field.value() == 5U);
        BOOST_CHECK(units::get_micrometers<unsigned>(field) == 500U);
        BOOST_CHECK(std::abs(units::get_millimeters<double>(field) - 0.5) <= std::numeric_limits<double>::epsilon());
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::units_millimeters> Field3;

    static_assert(!Field3::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field3 field(200U);
        BOOST_CHECK(field.value() == 200U);
        BOOST_CHECK(units::get_millimeters<unsigned>(field) == 200U);
        BOOST_CHECK(std::abs(units::getMeters<double>(field) - 0.2) <= std::numeric_limits<double>::epsilon());
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<1, 10>, option::units_meters>
        Field4;

    static_assert(!Field4::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field4 field(1U);
        BOOST_CHECK(field.value() == 1U);
        BOOST_CHECK(std::abs(units::getMeters<double>(field) - 0.1) <= std::numeric_limits<double>::epsilon());
        BOOST_CHECK(units::get_millimeters<unsigned>(field) == 100U);
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<1, 10>,
                             option::units_centimeters>
        Field5;

    static_assert(!Field5::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field5 field(1U);
        BOOST_CHECK(field.value() == 1U);
        BOOST_CHECK(std::abs(units::get_centimeters<double>(field) - 0.1) <= std::numeric_limits<double>::epsilon());
        BOOST_CHECK(units::get_millimeters<unsigned>(field) == 1U);
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<1, 10>,
                             option::units_kilometers>
        Field6;

    static_assert(!Field6::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field6 field(1U);
        BOOST_CHECK(field.value() == 1U);
        BOOST_CHECK(std::abs(units::getKilometers<double>(field) - 0.1) <= std::numeric_limits<double>::epsilon());
        BOOST_CHECK(units::getMeters<unsigned>(field) == 100U);
    } while (false);
}

BOOST_AUTO_TEST_CASE(test61) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t, option::units_centimeters_per_second>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    field.value() = 10U;
    BOOST_CHECK(units::getNanometersPerSecond<unsigned long long>(field) == 100000000UL);
    BOOST_CHECK(units::getMicrometersPerSecond<unsigned>(field) == 100000U);
    BOOST_CHECK(units::getMillimetersPerSecond<unsigned>(field) == 100U);
    BOOST_CHECK(units::getCentimetersPerSecond<unsigned>(field) == 10U);
    BOOST_CHECK(std::abs(units::getMetersPerSecond<double>(field) - 0.1) <= std::numeric_limits<double>::epsilon());
    BOOST_CHECK(std::abs(units::getKilometersPerSecond<double>(field) - 0.0001)
                <= std::numeric_limits<double>::epsilon());
    BOOST_CHECK(std::abs(units::getKilometersPerHour<double>(field) - (0.1 * 3600) / 1000)
                <= std::numeric_limits<double>::epsilon());

    units::setNanometersPerSecond(field, 50000000UL);
    BOOST_CHECK(field.value() == 5U);
    BOOST_CHECK(units::getMillimetersPerSecond<unsigned>(field) == 50U);

    units::setMicrometersPerSecond(field, 10000UL);
    BOOST_CHECK(field.value() == 1U);
    BOOST_CHECK(units::getMillimetersPerSecond<unsigned>(field) == 10U);

    units::setMillimetersPerSecond(field, 400);
    BOOST_CHECK(field.value() == 40U);
    BOOST_CHECK(units::getCentimetersPerSecond<unsigned>(field) == 40U);

    units::setCentimetersPerSecond(field, 10);
    BOOST_CHECK(units::getMillimetersPerSecond<unsigned>(field) == 100U);

    units::setMetersPerSecond(field, 0.02);
    BOOST_CHECK(units::getMillimetersPerSecond<unsigned>(field) == 20U);

    units::setKilometersPerSecond(field, 0.00002);
    BOOST_CHECK(units::getMillimetersPerSecond<unsigned>(field) == 20U);

    units::setKilometersPerHour(field, 36);
    BOOST_CHECK(units::getMetersPerSecond<unsigned>(field) == 10U);
}

BOOST_AUTO_TEST_CASE(test62) {
    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<100, 1>,
                             option::units_nanometers_per_second>
        Field1;

    static_assert(!Field1::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field1 field(1U);
        BOOST_CHECK(field.value() == 1U);
        BOOST_CHECK(units::getNanometersPerSecond<unsigned>(field) == 100U);
        BOOST_CHECK(std::abs(units::getMicrometersPerSecond<double>(field) - 0.1)
                    <= std::numeric_limits<double>::epsilon());
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<100, 1>,
                             option::units_micrometers_per_second>
        Field2;

    static_assert(!Field2::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field2 field(5U);
        BOOST_CHECK(field.value() == 5U);
        BOOST_CHECK(units::getMicrometersPerSecond<unsigned>(field) == 500U);
        BOOST_CHECK(std::abs(units::getMillimetersPerSecond<double>(field) - 0.5)
                    <= std::numeric_limits<double>::epsilon());
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::units_millimeters_per_second> Field3;

    static_assert(!Field3::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field3 field(200U);
        BOOST_CHECK(field.value() == 200U);
        BOOST_CHECK(units::getMillimetersPerSecond<unsigned>(field) == 200U);
        BOOST_CHECK(std::abs(units::getMetersPerSecond<double>(field) - 0.2) <= std::numeric_limits<double>::epsilon());
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<1, 10>,
                             option::units_meters_per_second>
        Field4;

    static_assert(!Field4::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field4 field(1U);
        BOOST_CHECK(field.value() == 1U);
        BOOST_CHECK(std::abs(units::getMetersPerSecond<double>(field) - 0.1) <= std::numeric_limits<double>::epsilon());
        BOOST_CHECK(units::getMillimetersPerSecond<unsigned>(field) == 100U);
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::scaling_ratio<1, 10>,
                             option::units_centimeters_per_second>
        Field5;

    static_assert(!Field5::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field5 field(1U);
        BOOST_CHECK(field.value() == 1U);
        BOOST_CHECK(std::abs(units::getCentimetersPerSecond<double>(field) - 0.1)
                    <= std::numeric_limits<double>::epsilon());
        BOOST_CHECK(units::getMillimetersPerSecond<unsigned>(field) == 1U);
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::units_kilometers_per_hour> Field6;

    static_assert(!Field6::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field6 field(36U);
        BOOST_CHECK(field.value() == 36U);
        BOOST_CHECK(units::getMetersPerSecond<unsigned>(field) == 10U);
    } while (false);

    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::units_kilometers_per_second> Field7;

    static_assert(!Field7::is_version_dependent(), "Invalid version dependency assumption");

    do {
        Field7 field(1U);
        BOOST_CHECK(field.value() == 1U);
        BOOST_CHECK(units::getMetersPerSecond<unsigned>(field) == 1000U);
    } while (false);
}

BOOST_AUTO_TEST_CASE(test63) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t, option::units_kilohertz> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    field.value() = 10U;
    BOOST_CHECK(units::getHertz<unsigned long>(field) == 10000UL);
    BOOST_CHECK(units::getKilohertz<unsigned>(field) == 10U);
    BOOST_CHECK(std::abs(units::getMegahertz<double>(field) - 0.01) <= std::numeric_limits<double>::epsilon());
    BOOST_CHECK(std::abs(units::getGigahertz<double>(field) - 0.00001) <= std::numeric_limits<double>::epsilon());

    units::setHertz(field, 20000U);
    BOOST_CHECK(units::getKilohertz<unsigned>(field) == 20U);

    units::setKilohertz(field, 1);
    BOOST_CHECK(units::getHertz<unsigned long>(field) == 1000L);

    units::setMegahertz(field, 2);
    BOOST_CHECK(units::getHertz<unsigned long>(field) == 2000000UL);

    units::setGigahertz(field, 3);
    BOOST_CHECK(units::getKilohertz<unsigned long>(field) == 3000000UL);
}

BOOST_AUTO_TEST_CASE(test64) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t, option::scaling_ratio<1, 10>,
                             option::units_degrees>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    field.value() = 300U;
    BOOST_CHECK(units::getDegrees<unsigned>(field) == 30U);
    BOOST_CHECK(std::abs(units::getRadians<double>(field) - 0.523599) <= 0.000001);

    units::setDegrees(field, 50U);
    BOOST_CHECK(field.value() == 500U);
    BOOST_CHECK(units::getDegrees<unsigned>(field) == 50U);
    BOOST_CHECK(std::abs(units::getRadians<double>(field) - 0.872665) <= 0.000001);

    units::setRadians(field, 1.04719);
    BOOST_CHECK(units::getDegrees<unsigned>(field) == 60U);
    BOOST_CHECK(field.value() == 600U);
    BOOST_CHECK(std::abs(units::getRadians<double>(field) - 1.04719) <= 0.00001);
}

BOOST_AUTO_TEST_CASE(test65) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t, option::scaling_ratio<1, 100>,
                             option::units_radians>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    field.value() = 100U;
    BOOST_CHECK(units::getRadians<unsigned>(field) == 1U);
    BOOST_CHECK(std::abs(units::getDegrees<double>(field) - 57.2958) <= 0.0001);

    units::setRadians(field, 0.5);
    BOOST_CHECK(field.value() == 50U);
    BOOST_CHECK(std::abs(units::getRadians<double>(field) - 0.5) <= std::numeric_limits<double>::epsilon());
    BOOST_CHECK(std::abs(units::getDegrees<double>(field) - 28.6479) <= 0.0001);

    units::setDegrees(field, 114.592);
    BOOST_CHECK(units::getRadians<unsigned>(field) == 2U);
    BOOST_CHECK(field.value() == 200U);
    BOOST_CHECK(std::abs(units::getDegrees<double>(field) - 114.592) <= 0.001);
}

BOOST_AUTO_TEST_CASE(test66) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t, option::units_milliamps> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    field.value() = 345U;
    BOOST_CHECK(units::getNanoamps<unsigned long long>(field) == 345000000UL);
    BOOST_CHECK(units::getMicroamps<unsigned>(field) == 345000U);
    BOOST_CHECK(units::getMilliamps<unsigned>(field) == 345U);
    BOOST_CHECK(std::abs(units::getAmps<double>(field) - 0.345) <= std::numeric_limits<double>::epsilon());
    BOOST_CHECK(std::abs(units::getKiloamps<double>(field) - 0.000345) <= std::numeric_limits<double>::epsilon());

    units::setNanoamps(field, 100000000UL);
    BOOST_CHECK(field.value() == 100U);
    BOOST_CHECK(units::getMilliamps<unsigned>(field) == 100U);

    units::setMicroamps(field, 222000UL);
    BOOST_CHECK(field.value() == 222U);
    BOOST_CHECK(units::getMilliamps<unsigned>(field) == 222U);

    units::setMilliamps(field, 400);
    BOOST_CHECK(field.value() == 400U);
    BOOST_CHECK(units::getMicroamps<unsigned>(field) == 400000U);

    units::setAmps(field, 0.025);
    BOOST_CHECK(units::getMilliamps<unsigned>(field) == 25U);

    units::setKiloamps(field, 0.025);
    BOOST_CHECK(units::getAmps<unsigned>(field) == 25U);
}

BOOST_AUTO_TEST_CASE(test67) {
    typedef types::integral<field_type<option::big_endian>, std::uint32_t, option::units_millivolts> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    field.value() = 345U;
    BOOST_CHECK(units::getNanovolts<unsigned long long>(field) == 345000000UL);
    BOOST_CHECK(units::getMicrovolts<unsigned>(field) == 345000U);
    BOOST_CHECK(units::getMillivolts<unsigned>(field) == 345U);
    BOOST_CHECK(std::abs(units::getVolts<double>(field) - 0.345) <= std::numeric_limits<double>::epsilon());
    BOOST_CHECK(std::abs(units::getKilovolts<double>(field) - 0.000345) <= std::numeric_limits<double>::epsilon());

    units::setNanovolts(field, 100000000UL);
    BOOST_CHECK(field.value() == 100U);
    BOOST_CHECK(units::getMillivolts<unsigned>(field) == 100U);

    units::setMicrovolts(field, 222000UL);
    BOOST_CHECK(field.value() == 222U);
    BOOST_CHECK(units::getMillivolts<unsigned>(field) == 222U);

    units::setMillivolts(field, 400);
    BOOST_CHECK(field.value() == 400U);
    BOOST_CHECK(units::getMicrovolts<unsigned>(field) == 400000U);

    units::setVolts(field, 0.025);
    BOOST_CHECK(units::getMillivolts<unsigned>(field) == 25U);

    units::setKilovolts(field, 0.025);
    BOOST_CHECK(units::getVolts<unsigned>(field) == 25U);
}

BOOST_AUTO_TEST_CASE(test68) {
    typedef types::float_value<field_type<option::big_endian>, float, option::units_seconds> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    field.value() = 1.345f;

    BOOST_CHECK(std::abs(field.value() - 1.345f) <= std::numeric_limits<float>::epsilon());
    BOOST_CHECK(units::get_microseconds<unsigned>(field) == 1345000U);
    BOOST_CHECK(units::get_milliseconds<unsigned>(field) == 1345U);
    BOOST_CHECK(std::abs(units::get_seconds<float>(field) - 1.345f) <= std::numeric_limits<float>::epsilon());

    units::set_milliseconds(field, 500U);
    BOOST_CHECK(std::abs(field.value() - 0.5f) <= std::numeric_limits<float>::epsilon());
    BOOST_CHECK(units::get_milliseconds<unsigned>(field) == 500U);
    BOOST_CHECK(std::abs(units::get_seconds<float>(field) - 0.5f) <= std::numeric_limits<float>::epsilon());

    units::set_minutes(field, (float)1 / 180);
    BOOST_CHECK(std::abs(units::get_seconds<float>(field) - (float)1 / 3) <= std::numeric_limits<float>::epsilon());
    BOOST_CHECK(units::get_milliseconds<unsigned>(field) == 333U);
    BOOST_CHECK(std::abs(units::get_milliseconds<float>(field) - (333 + (float)1 / 3))
                <= std::numeric_limits<float>::epsilon());
}

BOOST_AUTO_TEST_CASE(test69) {
    struct LenField : public types::integral<field_type<option::big_endian>, std::uint8_t> { };

    static_assert(!LenField::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::array_list<field_type<option::big_endian>, types::integral<field_type<option::big_endian>, std::uint16_t>,
                              option::sequence_ser_length_field_prefix<LenField>>
        testing_type;

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().empty());

    static const std::vector<char> ExpectedBuf = {0x0};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    static const std::vector<char> Buf = {0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
    field = pack<testing_type>(Buf.begin(), Buf.end());

    BOOST_CHECK(field.value().size() == static_cast<std::size_t>(Buf[0]) / 2U);
    BOOST_CHECK(field.length() == (field.value().size() * 2) + 1U);
    BOOST_CHECK(field.value()[0].value() == 0x0102);
    BOOST_CHECK(field.value()[1].value() == 0x0304);
    BOOST_CHECK(field.value()[2].value() == 0x0506);
    BOOST_CHECK(field.value()[3].value() == 0x0708);

    static const std::vector<char> Buf2 = {0x7, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};

    field = pack<testing_type>(Buf2.begin(), Buf2.end(), status_type::invalid_msg_data);

    static const std::vector<char> Buf3 = {0x4, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    field = pack<testing_type>(Buf3.begin(), Buf3.end());
    BOOST_CHECK(field.value().size() == static_cast<std::size_t>(Buf3[0]) / 2U);
    BOOST_CHECK(field.length() == (field.value().size() * 2) + 1U);
    BOOST_CHECK(field.value()[0].value() == 0x0a0b);
    BOOST_CHECK(field.value()[1].value() == 0x0c0d);
}

using Test70_FieldBase = field_type<option::big_endian>;

template<std::uint8_t TVal>
using Test70_IntKeyField = types::integral<Test70_FieldBase, std::uint8_t, option::default_num_value<TVal>,
                                            option::valid_num_value_range<TVal, TVal>, option::fail_on_invalid<>>;

using Test70_Mem1 = types::bundle<Test70_FieldBase,
                                  std::tuple<Test70_IntKeyField<1>, types::integral<Test70_FieldBase, std::uint16_t>>>;

using Test70_Mem2 = types::bundle<Test70_FieldBase,
                                  std::tuple<Test70_IntKeyField<2>, types::integral<Test70_FieldBase, std::uint32_t>>>;

template<typename... TExtra>
class Test70_Field : public types::variant<Test70_FieldBase, std::tuple<Test70_Mem1, Test70_Mem2>, TExtra...> {
    using Base = types::variant<Test70_FieldBase, std::tuple<Test70_Mem1, Test70_Mem2>, TExtra...>;

public:
    MARSHALLING_VARIANT_MEMBERS_ACCESS(mem1, mem2);
};

class Test70_LengthRetriever {
public:
    Test70_LengthRetriever(std::size_t &val) : val_(val) {
    }

    template<std::size_t TIdx, typename TField>
    void operator()(const TField &field) {
        val_ = field.length();
    }

private:
    std::size_t &val_;
};

BOOST_AUTO_TEST_CASE(test70) {
    using testing_type = Test70_Field<>;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(!field.valid());
    BOOST_CHECK(field.length() == 0U);
    BOOST_CHECK(field.current_field() == std::tuple_size<testing_type::members_type>::value);

    auto &mem1 = field.initField_mem1();
    std::get<1>(field.accessField_mem1().value()).value() = 0x0a0b;
    BOOST_CHECK(std::get<1>(mem1.value()).value() == 0x0a0b);
    BOOST_CHECK(field.current_field() == 0U);
    BOOST_CHECK(field.length() == 3U);
    BOOST_CHECK(field.valid());

    testing_type field2(field);
    BOOST_CHECK(field2 == field);

    testing_type field3(std::move(field2));
    BOOST_CHECK(field3 == field);

    auto &mem2 = field.initField_mem2();
    std::get<1>(field.accessField_mem2().value()).value() = 0x0c0c0c0c;
    BOOST_CHECK(std::get<1>(mem2.value()).value() == 0x0c0c0c0c);
    BOOST_CHECK(field.current_field() == 1U);
    BOOST_CHECK(field.length() == 5U);
    BOOST_CHECK(field.valid());

    field.reset();
    BOOST_CHECK(!field.current_field_valid());
    BOOST_CHECK(!field.valid());
    BOOST_CHECK(field.length() == 0U);
    BOOST_CHECK(field.current_field() == std::tuple_size<testing_type::members_type>::value);

    static const std::vector<char> Buf = {0x1, 0x2, 0x3};
    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.length() == 3U);
    BOOST_CHECK(field.current_field() == 0U);

    static const std::vector<char> Buf2 = {0x2, 0x3, 0x4};
    field = pack<testing_type>(Buf2.begin(), Buf2.end(), status_type::not_enough_data);
    BOOST_CHECK(!field.valid());
    BOOST_CHECK(field.length() == 0U);
    BOOST_CHECK(field.current_field() == std::tuple_size<testing_type::members_type>::value);

    static const std::vector<char> Buf3 = {0x2, 0x3, 0x4, 0x5, 0x6};
    field = pack<testing_type>(Buf3.begin(), Buf3.end());
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.length() == 5U);
    BOOST_CHECK(field.current_field() == 1U);

    std::size_t len1 = 0U;
    field.current_field_exec(Test70_LengthRetriever(len1));
    BOOST_CHECK(field.length() == len1);

    std::size_t len2 = 0U;
    Test70_LengthRetriever lenRetriever(len2);
    field.current_field_exec(lenRetriever);
    BOOST_CHECK(len2 == len1);

    std::size_t len3 = 0U;
    static_cast<const testing_type &>(field).current_field_exec(Test70_LengthRetriever(len3));
    BOOST_CHECK(len3 == len1);

    field.initField_mem1();
    std::get<1>(field.accessField_mem1().value()).value() = 0x0a0b;
    BOOST_CHECK(field3 == field);

    using InitialisedField = Test70_Field<option::default_variant_index<0>>;
    InitialisedField iniField;
    BOOST_CHECK(iniField.valid());
    BOOST_CHECK(iniField.length() == 3U);
    BOOST_CHECK(iniField.current_field() == 0);

    auto &iniMem1 = iniField.initField_mem1();
    BOOST_CHECK(std::get<0>(iniMem1.value()).value() == 1U);
    BOOST_CHECK(std::get<1>(iniMem1.value()).value() == 0U);
    BOOST_CHECK(field.current_field() == 0U);
    BOOST_CHECK(field.length() == 3U);
    BOOST_CHECK(field.valid());

    std::size_t len4 = 0U;
    field.current_field_exec(Test70_LengthRetriever(len4));
    BOOST_CHECK(field.length() == len4);
}

struct Test71_Field
    : public types::bundle<field_type<option::big_endian>,
                           std::tuple<types::integral<field_type<option::big_endian>, std::uint8_t>,
                                      types::optional<types::integral<field_type<option::big_endian>, std::uint8_t>,
                                                      option::default_optional_mode<types::optional_mode::missing>>>,
                           option::has_custom_read, option::has_custom_refresh> {
    MARSHALLING_FIELD_MEMBERS_ACCESS_NOTEMPLATE(mask, val);

    template<typename TIter>
    status_type read(TIter &iter, std::size_t len) {
        status_type es = field_mask().read(iter, len);

        if (es != status_type::success) {
            return es;
        }

        if (field_mask().value() == 0) {
            field_val().set_missing();
        } else {
            field_val().set_exists();
        }

        len -= field_mask().length();
        return field_val().read(iter, len);
    }

    bool refresh() {
        bool exists = (field_mask().value() != 0);
        if (exists == field_val().does_exist()) {
            return false;
        }

        if (exists) {
            field_val().set_exists();
        } else {
            field_val().set_missing();
        }
        return true;
    }
};

BOOST_AUTO_TEST_CASE(test71) {
    using testing_type = Test71_Field;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.length() == 1U);
    BOOST_CHECK(field.field_val().is_missing());

    field.field_mask().value() = 1;
    bool result = field.refresh();
    BOOST_CHECK(result);
    BOOST_CHECK(field.length() == 2U);
    BOOST_CHECK(!field.refresh());
    field.field_mask().value() = 0;
    BOOST_CHECK(field.refresh());
    BOOST_CHECK(field.length() == 1U);

    static const std::vector<char> Buf = {0, 0, 0};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == 1U);
    BOOST_CHECK(field.field_val().is_missing());

    static const std::vector<char> Buf2 = {1, 5, 0};

    field = pack<testing_type>(Buf2.begin(), Buf2.end());
    BOOST_CHECK(field.length() == 2U);
    BOOST_CHECK(field.field_val().does_exist());
    BOOST_CHECK(field.field_val().field().value() == (unsigned)Buf2[1]);
}

BOOST_AUTO_TEST_CASE(test72) {
    static_assert(!types::detail::string_has_push_back<container::string_view>::value,
                  "string_view doesn't have push_back");

    typedef types::integral<field_type<option::big_endian>, std::uint8_t> SizeField;

    static_assert(!SizeField::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::string<field_type<option::big_endian>, option::sequence_size_field_prefix<SizeField>,
                          option::orig_data_view>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().empty());

    static const std::vector<char> Buf = {0x5, 'h', 'e', 'l', 'l', 'o', 'g', 'a', 'r'};
    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.value().size() == static_cast<std::size_t>(Buf[0]));
    BOOST_CHECK(field.length() == field.value().size() + 1U);
    BOOST_CHECK(field.valid());
    BOOST_CHECK(&(*field.value().begin()) == &Buf[1]);

    static const std::string Str("blabla");
    field.value() = testing_type::value_type(Str.c_str(), Str.size());
    BOOST_CHECK(&(*field.value().begin()) == &Str[0]);

    static const std::vector<char> ExpectedBuf = {0x6, 'b', 'l', 'a', 'b', 'l', 'a'};

    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(test73) {
    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::valid_num_value_range<0, 0>> TermField;

    static_assert(!TermField::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::string<field_type<option::big_endian>, option::sequence_termination_field_suffix<TermField>,
                          option::orig_data_view>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.length() == 1U);

    static const char *HelloStr = "hello";

    field.value() = HelloStr;
    BOOST_CHECK(&(*field.value().begin()) == HelloStr);
    BOOST_CHECK(field.length() == 6U);

    static const std::vector<char> ExpectedBuf = {'h', 'e', 'l', 'l', 'o', 0x0};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    static const std::vector<char> InputBuf = {'f', 'o', 'o', 0x0, 'b', 'l', 'a'};

    field = pack<testing_type>(InputBuf.begin(), InputBuf.end());

    BOOST_CHECK(field.value() == "foo");
    BOOST_CHECK(field.value().size() == 3U);
}

BOOST_AUTO_TEST_CASE(test74) {
    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::valid_num_value_range<0, 0>> TrailField;

    static_assert(!TrailField::is_version_dependent(), "Invalid version dependency assumption");

    typedef types::string<field_type<option::big_endian>, option::sequence_fixed_size<5>,
                          option::sequence_trailing_field_suffix<TrailField>, option::orig_data_view>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static_assert(testing_type::min_length() == 6U, "Invalid min length");
    static_assert(testing_type::max_length() == 6U, "Invalid max length");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.length() == 6U);

    static const char *HelloStr = "hello";

    field.value() = HelloStr;
    BOOST_CHECK(field.value().size() == 5U);
    BOOST_CHECK(field.length() == 6U);
    BOOST_CHECK(&(*field.value().begin()) == HelloStr);

    static const std::vector<char> ExpectedBuf = {'h', 'e', 'l', 'l', 'o', 0x0};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    field.value() = "foo";
    BOOST_CHECK(field.value().size() == 3U);
    BOOST_CHECK(std::string(field.value().data()) == "foo");
    BOOST_CHECK(field.value() == container::string_view("foo"));
    BOOST_CHECK(field.length() == 6U);

    static const std::vector<char> ExpectedBuf2 = {'f', 'o', 'o', 0x0, 0x0, 0x0};
    write_read_field(field, ExpectedBuf2.begin(), ExpectedBuf2.size());

    field = pack<testing_type>(ExpectedBuf2.begin(), ExpectedBuf2.end());
    BOOST_CHECK(field.value() == "foo");
}

BOOST_AUTO_TEST_CASE(test75) {
    typedef types::array_list<field_type<option::big_endian>, std::uint8_t, option::orig_data_view> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static_assert(std::is_same<testing_type::value_type, container::array_view<std::uint8_t>>::value,
                  "Expected to be array view");

    testing_type field;
    BOOST_CHECK(field.valid());

    BOOST_CHECK(field.value().empty());

    static const std::vector<char> Buf = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9};
    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == Buf.size());
    BOOST_CHECK(field.valid());

    auto &view = field.value();
    auto *viewStart = reinterpret_cast<const char *>(&(*view.begin()));
    BOOST_CHECK(viewStart == &Buf[0]);
    BOOST_CHECK(!field.refresh());
}

BOOST_AUTO_TEST_CASE(test76) {
    typedef types::array_list<
        field_type<option::big_endian>, std::uint8_t,
        option::sequence_size_field_prefix<types::integral<field_type<option::big_endian>, std::uint16_t>>,
        option::orig_data_view>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    BOOST_CHECK(testing_type::min_length() == sizeof(std::uint16_t));

    testing_type field;
    BOOST_CHECK(field.value().size() == 0U);
    BOOST_CHECK(field.value().empty());

    static const std::vector<char> Buf = {0x0, 0xa, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xf, 0xf};
    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == 12);
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().size() == 10U);
    BOOST_CHECK(&(*field.value().begin()) == reinterpret_cast<const std::uint8_t *>(&Buf[2]));

    field.value().remove_suffix(5);
    BOOST_CHECK(field.valid());
    static const std::vector<char> ExpectedBuf = {0x0, 0x5, 0x0, 0x1, 0x2, 0x3, 0x4};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(test77) {
    typedef types::array_list<field_type<option::big_endian>, std::uint8_t, option::sequence_fixed_size<6>,
                              option::orig_data_view>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static_assert(testing_type::min_length() == 6U, "Invalid min length");
    static_assert(testing_type::max_length() == 6U, "Invalid max length");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().size() == 0U);
    BOOST_CHECK(field.value().empty());

    static const std::vector<char> Buf = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9};
    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == 6U);
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().size() == 6U);
    BOOST_CHECK((field.value())[0] == 0x0);
    BOOST_CHECK((field.value())[1] == 0x1);
    BOOST_CHECK(&(*field.value().begin()) == reinterpret_cast<const std::uint8_t *>(&Buf[0]));

    field.value().remove_prefix(3);
    BOOST_CHECK(field.value().size() == 3U);
    BOOST_CHECK((field.value())[0] == 0x3);
    BOOST_CHECK((field.value())[1] == 0x4);
    BOOST_CHECK(&(*field.value().begin()) == reinterpret_cast<const std::uint8_t *>(&Buf[3]));
    BOOST_CHECK(field.length() == 6U);

    static const std::vector<char> ExpectedBuf = {0x3, 0x4, 0x5, 0x0, 0x0, 0x0};

    std::vector<char> outDataBuf(ExpectedBuf.size());
    pack<testing_type>(field, outDataBuf.begin());

    bool bufAsExpected = std::equal(ExpectedBuf.begin(), ExpectedBuf.end(), outDataBuf.begin());
    BOOST_CHECK(bufAsExpected);
}

class Test78_Field : public types::variant<Test70_FieldBase, std::tuple<Test70_Mem1, Test70_Mem2>> {
public:
    MARSHALLING_VARIANT_MEMBERS_ACCESS_NOTEMPLATE(mem1, mem2);
};

BOOST_AUTO_TEST_CASE(test78) {
    Test78_Field field;

    static_assert(!Test78_Field::is_version_dependent(), "Invalid version dependency assumption");

    auto &mem1_1 = field.initField_mem1();
    static_cast<void>(mem1_1);
    auto &mem1_2 = field.accessField_mem1();
    static_cast<void>(mem1_2);

    auto &mem2_1 = field.initField_mem2();
    static_cast<void>(mem2_1);
    auto &mem2_2 = field.accessField_mem2();
    static_cast<void>(mem2_2);
}

BOOST_AUTO_TEST_CASE(test79) {
    class testing_type
        : public types::array_list<field_type<option::big_endian>, types::integral<field_type<option::big_endian>, std::uint8_t>,
                                   option::sequence_elem_length_forcing_enabled, option::sequence_fixed_size<3>> {
    public:
        testing_type() {
            force_read_elem_length(2U);
        }
    };

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.valid());
    static_assert(testing_type::min_length() == 3U, "Min length is incorrect");
    static_assert(3U < testing_type::max_length(), "Max length is incorrect");

    static const std::vector<char> Buf
        = {0x1, 0x0, 0x2, 0x0, 0x3, 0x0, 0x4, 0x0, 0x5, 0x0, 0x6, 0x0, 0x7, 0x0, 0x8, 0x0};

    field = pack<testing_type>(Buf.begin(), Buf.end());

    BOOST_CHECK(field.length() == 6U);
    BOOST_CHECK(field.value().size() == 3U);
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value()[0].value() == 0x1);
    BOOST_CHECK(field.value()[1].value() == 0x2);
    BOOST_CHECK(field.value()[2].value() == 0x3);
}

BOOST_AUTO_TEST_CASE(test80) {
    typedef types::bundle<
        field_type<option::big_endian>,
        std::tuple<types::integral<field_type<option::big_endian>, std::uint16_t, option::valid_num_value_range<0, 10>,
                                    option::default_num_value<5>>,
                   types::integral<field_type<option::big_endian>, std::uint8_t, option::valid_num_value_range<100, 100>,
                                    option::default_num_value<100>, option::empty_serialization>,
                   types::enumeration<field_type<option::big_endian>, Enum1, option::fixed_length<1>,
                                     option::valid_num_value_range<0, Enum1_NumOfValues - 1>,
                                     option::default_num_value<Enum1_Value2>>>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static_assert(testing_type::min_length() == 3U, "Invalid min_length");
    static_assert(testing_type::max_length() == 3U, "Invalid max_length");
    static_assert(testing_type::min_length_from_until<1, 2>() == 0U, "Invalid min_length");
    static_assert(testing_type::max_length_from_until<1, 2>() == 0U, "Invalid max_length");
    static_assert(testing_type::min_length_from<1>() == 1U, "Invalid min_length");
    static_assert(testing_type::max_length_from<1>() == 1U, "Invalid max_length");

    testing_type field;
    BOOST_CHECK(field.valid());
    auto &intValField = std::get<0>(field.value());
    auto &constValField = std::get<1>(field.value());
    auto &enumValField = std::get<2>(field.value());
    BOOST_CHECK(intValField.value() == 5U);
    BOOST_CHECK(constValField.value() == 100U);
    BOOST_CHECK(enumValField.value() == Enum1_Value2);

    intValField.value() = 50U;
    BOOST_CHECK(!field.valid());
    intValField.value() = 1U;
    BOOST_CHECK(field.valid());
    enumValField.value() = Enum1_NumOfValues;
    BOOST_CHECK(!field.valid());
    enumValField.value() = Enum1_Value1;
    BOOST_CHECK(field.valid());
    constValField.value() = 10;
    BOOST_CHECK(!field.valid());
    constValField.value() = 100;
    BOOST_CHECK(field.valid());

    static const std::vector<char> Buf = {0x00, 0x3, Enum1_Value3, (char)0xff};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == 3U);
    BOOST_CHECK(field.valid());
    BOOST_CHECK(intValField.value() == 3U);
    BOOST_CHECK(constValField.value() == 100U);
    BOOST_CHECK(enumValField.value() == Enum1_Value3);

    intValField.value() = 0xabcd;
    enumValField.value() = Enum1_Value1;

    static const std::vector<char> ExpectedBuf = {(char)0xab, (char)0xcd, (char)Enum1_Value1};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(test81) {
    using testing_type = types::integral<
        field_type<option::big_endian>, std::uint64_t,
        option::valid_big_unsigned_num_value_range<0xffffffff, std::numeric_limits<std::uintmax_t>::max() - 1>,
        option::default_big_unsigned_num_value<std::numeric_limits<std::uintmax_t>::max()>>;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(!field.valid());
    BOOST_CHECK(field.value() == std::numeric_limits<std::uintmax_t>::max());
}

BOOST_AUTO_TEST_CASE(test82) {

    typedef types::bundle<
        field_type<option::big_endian>,
        std::tuple<types::integral<field_type<option::big_endian>, std::uint16_t, option::valid_num_value_range<0, 10>,
                                    option::default_num_value<5>>>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static_assert(testing_type::min_length() == 2U, "Invalid min_length");
    static_assert(testing_type::min_length_from<0>() == 2U, "Invalid min_length");
    static_assert(testing_type::min_length_until<1>() == 2U, "Invalid min_length");
    static_assert(testing_type::max_length() == 2U, "Invalid max_length");
    static_assert(testing_type::max_length_from<0>() == 2U, "Invalid min_length");
    static_assert(testing_type::max_length_until<1>() == 2U, "Invalid min_length");

    testing_type field;
    BOOST_CHECK(field.length() == 2U);
    BOOST_CHECK(field.length_from<0>() == 2U);
    BOOST_CHECK(field.length_until<1>() == 2U);
    BOOST_CHECK(field.valid());
    auto &intValField = std::get<0>(field.value());
    BOOST_CHECK(intValField.value() == 5U);

    intValField.value() = 50U;
    BOOST_CHECK(!field.valid());
    intValField.value() = 1U;
    BOOST_CHECK(field.valid());
    static const std::vector<char> Buf = {0x00, 0x3, (char)0xff};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == 2U);
    BOOST_CHECK(field.valid());
    BOOST_CHECK(intValField.value() == 3U);

    intValField.value() = 0xabcd;

    static const std::vector<char> ExpectedBuf = {(char)0xab, (char)0xcd};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    testing_type fieldTmp;
    auto readIter = &ExpectedBuf[0];
    status_type es = fieldTmp.read_from_until<0, 1>(readIter, ExpectedBuf.size());
    BOOST_CHECK(es == status_type::success);
    BOOST_CHECK(fieldTmp == field);
}

BOOST_AUTO_TEST_CASE(test83) {
    typedef types::array_list<field_type<option::big_endian>, std::uint8_t, option::sequence_fixed_size<5>,
                              option::sequence_fixed_size_use_fixed_size_storage>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static_assert(testing_type::min_length() == 5U, "Invalid min length");
    static_assert(testing_type::max_length() == 5U, "Invalid max length");

    static_assert(container::is_static_vector<testing_type::value_type>(), "The storage typ is incorrect");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(testing_type::min_length() == 5U);
    BOOST_CHECK(testing_type::max_length() == 5U);

    static const std::vector<char> Buf = {0x0, 0x1, 0x2, 0x3, 0x4};
    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == Buf.size());
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().size() == Buf.size());
}

BOOST_AUTO_TEST_CASE(test84) {
    typedef types::string<field_type<option::big_endian>, option::sequence_fixed_size<5>,
                          option::sequence_fixed_size_use_fixed_size_storage>
        testing_type;

    static_assert(testing_type::min_length() == 5U, "Invalid min length");
    static_assert(testing_type::max_length() == 5U, "Invalid max length");
    static_assert(container::is_static_string<testing_type::value_type>(), "Invalid storage type");

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.length() == 5U);

    static const char *HelloStr = "hello";
    field.value() = HelloStr;
    BOOST_CHECK(field.value().size() == 5U);
    BOOST_CHECK(field.length() == 5U);
    // BOOST_CHECK(&(*field.value().begin()) == HelloStr);

    static const std::vector<char> ExpectedBuf = {'h', 'e', 'l', 'l', 'o'};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    field.value() = "foo";
    BOOST_CHECK(field.value().size() == 3U);
    BOOST_CHECK(std::string(field.value().data()) == "foo");
    BOOST_CHECK(field.length() == 5U);

    static const std::vector<char> ExpectedBuf2 = {'f', 'o', 'o', 0x0, 0x0};
    write_read_field(field, ExpectedBuf2.begin(), ExpectedBuf2.size());

    field = pack<testing_type>(ExpectedBuf2.begin(), ExpectedBuf2.end());
    BOOST_CHECK(field.value() == "foo");
}

BOOST_AUTO_TEST_CASE(test85) {
    typedef types::string<field_type<option::big_endian>, option::sequence_fixed_size<5>> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    static_assert(testing_type::min_length() == 5U, "Invalid min length");
    static_assert(testing_type::max_length() == 5U, "Invalid max length");

    testing_type field;

    field.value() = "blabla";
    BOOST_CHECK(field.value().size() == 6U);
    BOOST_CHECK(field.length() == 5U);

    static const std::vector<char> ExpectedBuf = {'b', 'l', 'a', 'b', 'l'};

    std::vector<std::uint8_t> outBuf;
    auto writeIter = std::back_inserter(outBuf);
    status_type es = field.write(writeIter, outBuf.max_size());
    BOOST_CHECK(es == status_type::success);
    BOOST_CHECK(outBuf.size() == ExpectedBuf.size());
    BOOST_CHECK(std::equal(outBuf.begin(), outBuf.end(), std::begin(ExpectedBuf)));
}

BOOST_AUTO_TEST_CASE(test86) {
    typedef types::integral<field_type<option::big_endian>, std::uint8_t, option::valid_num_value_range_override<0, 10>,
                             option::valid_num_value_range<20, 30>, option::default_num_value<20>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.value() == 20);
    BOOST_CHECK(!field.valid());
    field.value() = 5U;
    BOOST_CHECK(field.valid());
}

BOOST_AUTO_TEST_CASE(test87) {
    typedef types::array_list<
        field_type<option::big_endian>,
        types::integral<field_type<option::big_endian>, std::uint8_t, option::valid_num_value_range<0, 5>>,
        option::sequence_size_field_prefix<types::integral<field_type<option::big_endian>, std::uint16_t>>,
        option::sequence_elem_ser_length_field_prefix<types::integral<field_type<option::big_endian>, std::uint8_t>>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    BOOST_CHECK(testing_type::min_length() == sizeof(std::uint16_t));

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().size() == 0U);

    static const std::vector<char> Buf = {0x0, 0x4, 0x1, 0x0, 0x1, 0x1, 0x1, 0x2, 0x1, 0x3};
    field = pack<testing_type>(Buf.begin(), Buf.end());
    BOOST_CHECK(field.length() == Buf.size());
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().size() == 4U);

    field.value().resize(5);
    static const std::vector<char> ExpectedBuf = {0x0, 0x5, 0x1, 0x0, 0x1, 0x1, 0x1, 0x2, 0x1, 0x3, 0x1, 0x0};
    BOOST_CHECK(field.valid());
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    static const std::vector<char> Buf2 = {0x0, 0x4, 0x2, 0x0, 0x1, 0x2, 0x3, 0x4, 0x2, 0x5, 0x6, 0x2, 0x7, 0x8};
    
    field = pack<testing_type>(Buf2.begin(), Buf2.end());
    
    BOOST_CHECK(field.length() == Buf2.size() - 4U);
    BOOST_CHECK(!field.valid());
    BOOST_CHECK(field.value().size() == 4U);
    BOOST_CHECK(field.value()[0].value() == 0x0);
    BOOST_CHECK(field.value()[1].value() == 0x3);
    BOOST_CHECK(field.value()[2].value() == 0x5);
    BOOST_CHECK(field.value()[3].value() == 0x7);
}

BOOST_AUTO_TEST_CASE(test88) {
    typedef types::array_list<
        field_type<option::big_endian>,
        types::bundle<
            field_type<option::big_endian>,
            std::tuple<types::integral<field_type<option::big_endian>, std::uint8_t>,
                       types::string<field_type<option::big_endian>, option::sequence_size_field_prefix<types::integral<
                                                                   field_type<option::big_endian>, std::uint8_t>>>>>,
        option::sequence_size_field_prefix<types::integral<field_type<option::big_endian>, std::uint8_t>>,
        option::sequence_elem_ser_length_field_prefix<
            types::integral<field_type<option::big_endian>, std::uint32_t, option::var_length<1, 4>>>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    BOOST_CHECK(testing_type::min_length() == sizeof(std::uint8_t));

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().size() == 0U);

    static const std::vector<char> Buf
        = {0x2, 0x9, 0x1, 0x5, 'h', 'e', 'l', 'l', 'o', 0xa, 0xb, 0x7, 0x2, 0x3, 'b', 'l', 'a', 0xc, 0xd};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    auto &vec = field.value();
    BOOST_CHECK(vec.size() == 2U);
    auto &bundle0 = vec[0];
    auto &bundle1 = vec[1];
    BOOST_CHECK(std::get<0>(bundle0.value()).value() == 1U);
    BOOST_CHECK(std::get<1>(bundle0.value()).value() == "hello");
    BOOST_CHECK(std::get<0>(bundle1.value()).value() == 2U);
    BOOST_CHECK(std::get<1>(bundle1.value()).value() == "bla");

    static const std::vector<char> ExpectedBuf
        = {0x2, 0x7, 0x1, 0x5, 'h', 'e', 'l', 'l', 'o', 0x5, 0x2, 0x3, 'b', 'l', 'a'};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    field.value().resize(1);
    auto &intField = std::get<0>(field.value()[0].value());
    intField.value() = 4U;
    auto &stringField = std::get<1>(field.value()[0].value());
    stringField.value().clear();
    for (auto idx = 0; idx < 128; ++idx) {
        stringField.value().push_back('a');
    }

    std::vector<char> expBuf;
    expBuf.push_back(0x1);          // count
    expBuf.push_back(0x81);         // high byte of length
    expBuf.push_back(0x02);         // low byte of length
    expBuf.push_back(0x4);          // value of first integral byte
    expBuf.push_back((char)128);    // length of string
    for (auto idx = 0; idx < 128; ++idx) {
        expBuf.push_back('a');    // string itself
    }
    write_read_field(field, &expBuf[0], expBuf.size());
}

BOOST_AUTO_TEST_CASE(test89) {
    typedef types::array_list<
        field_type<option::big_endian>,
        types::bundle<
            field_type<option::little_endian>,
            std::tuple<types::integral<field_type<option::little_endian>, std::uint32_t, option::var_length<1, 4>>,
                       types::string<field_type<option::little_endian>,
                                     option::sequence_size_field_prefix<types::integral<
                                         field_type<option::little_endian>, std::uint16_t, option::var_length<1, 2>>>>>>,
        option::sequence_ser_length_field_prefix<
            types::integral<field_type<option::little_endian>, std::uint32_t, option::var_length<1, 4>>>,
        option::sequence_elem_ser_length_field_prefix<
            types::integral<field_type<option::little_endian>, std::uint32_t, option::var_length<1, 4>>>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    BOOST_CHECK(testing_type::min_length() == sizeof(std::uint8_t));

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().size() == 0U);

    static const std::vector<char> Buf
        = {18, 0x9, 0x1, 0x5, 'h', 'e', 'l', 'l', 'o', 0xa, 0xb, 0x7, 0x2, 0x3, 'b', 'l', 'a', 0xc, 0xd};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    auto &vec = field.value();
    BOOST_CHECK(vec.size() == 2U);
    auto &bundle0 = vec[0];
    auto &bundle1 = vec[1];
    BOOST_CHECK(std::get<0>(bundle0.value()).value() == 1U);
    BOOST_CHECK(std::get<1>(bundle0.value()).value() == "hello");
    BOOST_CHECK(std::get<0>(bundle1.value()).value() == 2U);
    BOOST_CHECK(std::get<1>(bundle1.value()).value() == "bla");

    static const std::vector<char> ExpectedBuf
        = {14, 0x7, 0x1, 0x5, 'h', 'e', 'l', 'l', 'o', 0x5, 0x2, 0x3, 'b', 'l', 'a'};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    field.value().resize(1);
    auto &intField = std::get<0>(field.value()[0].value());
    intField.value() = 0x4000;
    auto &stringField = std::get<1>(field.value()[0].value());
    stringField.value().clear();
    for (auto idx = 0; idx < 128; ++idx) {
        stringField.value().push_back('a');
    }

    auto expTotalLength = 2 + 2 + 3 + 2 + 128;
    BOOST_CHECK(field.length() == expTotalLength);

    std::vector<char> expBuf;
    static const std::vector<char> totalLenEncoding = {(char)0x87, 0x1};
    static const std::vector<char> elemLenEncoding = {(char)0x85, 0x1};
    static const std::vector<char> intEncoding = {(char)0x80, (char)0x80, 0x1};
    static const std::vector<char> stringLenEncoding = {(char)0x80, 0x1};

    expBuf.insert(expBuf.end(), totalLenEncoding.begin(), totalLenEncoding.end());
    expBuf.insert(expBuf.end(), elemLenEncoding.begin(), elemLenEncoding.end());
    expBuf.insert(expBuf.end(), intEncoding.begin(), intEncoding.end());
    expBuf.insert(expBuf.end(), stringLenEncoding.begin(), stringLenEncoding.end());

    for (auto idx = 0; idx < 128; ++idx) {
        expBuf.push_back('a');    // string itself
    }
    write_read_field(field, &expBuf[0], expBuf.size());
}

BOOST_AUTO_TEST_CASE(test90) {
    typedef types::array_list<
        field_type<option::big_endian>,
        types::bundle<field_type<option::big_endian>, std::tuple<types::integral<field_type<option::big_endian>, std::uint8_t>,
                                                           types::integral<field_type<option::big_endian>, std::uint16_t>>>,
        option::sequence_size_field_prefix<types::integral<field_type<option::big_endian>, std::uint8_t>>,
        option::sequence_elem_fixed_ser_length_field_prefix<
            types::integral<field_type<option::big_endian>, std::uint32_t, option::var_length<1, 4>>>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    BOOST_CHECK(testing_type::min_length() == 2U);

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().size() == 0U);

    static const std::vector<char> Buf = {0x2, 0x4, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    auto &vec = field.value();
    BOOST_CHECK(vec.size() == 2U);
    auto &bundle0 = vec[0];
    auto &bundle1 = vec[1];
    BOOST_CHECK(std::get<0>(bundle0.value()).value() == 0x1);
    BOOST_CHECK(std::get<1>(bundle0.value()).value() == 0x0203);
    BOOST_CHECK(std::get<0>(bundle1.value()).value() == 0x5);
    BOOST_CHECK(std::get<1>(bundle1.value()).value() == 0x0607);

    static const std::vector<char> ExpectedBuf = {0x2, 0x3, 0x1, 0x2, 0x3, 0x5, 0x6, 0x7};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());

    field.value().clear();
    static const std::vector<char> EmptyExpectedBuf = {0x0};

    write_read_field(field, EmptyExpectedBuf.begin(), EmptyExpectedBuf.size());
    BOOST_CHECK(field.length() == 1U);
}

BOOST_AUTO_TEST_CASE(test91) {
    typedef types::array_list<
        field_type<option::big_endian>,
        types::bundle<field_type<option::big_endian>, std::tuple<types::integral<field_type<option::big_endian>, std::uint8_t>,
                                                           types::integral<field_type<option::big_endian>, std::uint16_t>>>,
        option::sequence_fixed_size<2>,
        option::sequence_elem_fixed_ser_length_field_prefix<
            types::integral<field_type<option::big_endian>, std::uint32_t, option::var_length<1, 4>>>>
        testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    BOOST_CHECK(testing_type::min_length() == 7U);

    testing_type field;
    BOOST_CHECK(field.valid());
    BOOST_CHECK(field.value().size() == 0U);

    static const std::vector<char> Buf = {0x4, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    auto &vec = field.value();
    BOOST_CHECK(vec.size() == 2U);
    auto &bundle0 = vec[0];
    auto &bundle1 = vec[1];
    BOOST_CHECK(std::get<0>(bundle0.value()).value() == 0x1);
    BOOST_CHECK(std::get<1>(bundle0.value()).value() == 0x0203);
    BOOST_CHECK(std::get<0>(bundle1.value()).value() == 0x5);
    BOOST_CHECK(std::get<1>(bundle1.value()).value() == 0x0607);

    static const std::vector<char> ExpectedBuf = {0x3, 0x1, 0x2, 0x3, 0x5, 0x6, 0x7};
    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(test92) {
    typedef std::tuple<types::integral<field_type<option::little_endian>, std::uint8_t>,
                       types::integral<field_type<option::little_endian>, std::uint8_t>,
                       types::integral<field_type<option::little_endian>, std::uint8_t>>
        BitfileMembers;

    typedef types::bitfield<field_type<option::little_endian>, BitfileMembers> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(!field.set_version(5U));
    static_cast<void>(field);
    BOOST_CHECK(field.length() == 3U);
    BOOST_CHECK(field.member_bit_length<0>() == 8U);
    BOOST_CHECK(field.member_bit_length<1>() == 8U);
    BOOST_CHECK(field.member_bit_length<2>() == 8U);

    static const std::vector<char> Buf = {(char)0x1, (char)0x2, (char)0x3};

    field = pack<testing_type>(Buf.begin(), Buf.end());
    auto &members = field.value();
    auto &mem1 = std::get<0>(members);
    BOOST_CHECK(mem1.value() == 0x1);

    auto &mem2 = std::get<1>(members);
    BOOST_CHECK(mem2.value() == 0x2);

    auto &mem3 = std::get<2>(members);
    BOOST_CHECK(mem3.value() == 0x3);
}

BOOST_AUTO_TEST_CASE(test93) {
    typedef std::tuple<types::integral<field_type<option::little_endian>, std::uint8_t, option::fixed_bit_length<4>,
                                        option::default_num_value<0xf>>,
                       types::integral<field_type<option::little_endian>, std::int16_t, option::default_num_value<2016>,
                                        option::num_value_ser_offset<-2000>, option::fixed_bit_length<8>>,
                       types::integral<field_type<option::little_endian>, std::uint16_t, option::fixed_bit_length<12>,
                                        option::default_num_value<0x801>>>
        BitfileMembers;

    typedef types::bitfield<field_type<option::little_endian>, BitfileMembers> testing_type;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    static_cast<void>(field);
    BOOST_CHECK(field.length() == 3U);
    BOOST_CHECK(field.member_bit_length<0>() == 4U);
    BOOST_CHECK(field.member_bit_length<1>() == 8U);
    BOOST_CHECK(field.member_bit_length<2>() == 12U);

    auto &members = field.value();
    auto &mem1 = std::get<0>(members);
    BOOST_CHECK(mem1.value() == 0xf);
    auto &mem2 = std::get<1>(members);
    BOOST_CHECK(mem2.value() == 2016);
    auto &mem3 = std::get<2>(members);
    BOOST_CHECK(mem3.value() == 0x801);

    static const std::vector<char> ExpectedBuf = {0x0f, 0x11, (char)0x80};

    write_read_field(field, ExpectedBuf.begin(), ExpectedBuf.size());
}

BOOST_AUTO_TEST_CASE(test94) {
    using Mem1 = types::integral<field_type<option::big_endian>, std::uint16_t>;

    struct Mem2 : public types::integral<field_type<option::big_endian>, std::uint16_t, option::has_custom_version_update> {
        bool set_version(unsigned) {
            return true;
        }
    };

    typedef types::bundle<field_type<option::big_endian>, std::tuple<Mem1, Mem2>> testing_type;

    static_assert(testing_type::is_version_dependent(), "Invalid version dependency assumption");
    testing_type field;
    BOOST_CHECK(field.set_version(5U));
}

BOOST_AUTO_TEST_CASE(test95) {
    using Mem1 = types::integral<field_type<option::big_endian>, std::uint16_t>;

    using Mem2 = types::optional<Mem1, option::exists_since_version<5>, option::exists_by_default>;

    typedef types::bundle<field_type<option::big_endian>, std::tuple<Mem1, Mem2>> testing_type;

    static_assert(testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    BOOST_CHECK(field.length() == 4U);
    BOOST_CHECK(!field.set_version(5U));
    BOOST_CHECK(field.length() == 4U);
    BOOST_CHECK(field.set_version(4U));
    BOOST_CHECK(field.length() == 2U);
    BOOST_CHECK(field.set_version(15U));
    BOOST_CHECK(field.length() == 4U);
}

BOOST_AUTO_TEST_CASE(test96) {
    using Mem1 = types::integral<field_type<option::big_endian>, std::uint8_t, option::fixed_bit_length<4>>;

    struct Mem2 : public types::integral<field_type<option::big_endian>, std::uint8_t, option::has_custom_version_update,
                                          option::fixed_bit_length<4>> {
        bool set_version(unsigned) {
            return true;
        }
    };

    typedef types::bitfield<field_type<option::big_endian>, std::tuple<Mem1, Mem2>> testing_type;

    static_assert(testing_type::is_version_dependent(), "Invalid version dependency assumption");
    testing_type field;
    BOOST_CHECK(field.set_version(5U));
}

BOOST_AUTO_TEST_CASE(test97) {
    using Mem1 = types::integral<field_type<option::big_endian>, std::uint16_t>;

    using Mem2 = types::optional<Mem1, option::exists_since_version<5>, option::exists_by_default>;

    using ListElem = types::bundle<field_type<option::big_endian>, std::tuple<Mem1, Mem2>>;

    static_assert(ListElem::is_version_dependent(), "Invalid version dependency assumption");

    using testing_type = types::array_list<field_type<option::big_endian>, ListElem>;

    static_assert(testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    field.value().resize(1);
    BOOST_CHECK(field.length() == 4U);
    BOOST_CHECK(field.set_version(1U));
    BOOST_CHECK(field.length() == 2U);

    do {
        accumulator_set<testing_type> acc = accumulator_set<testing_type>(field);

        static const std::vector<char> Buf1 = {(char)0x01, (char)0x02};

        field = pack<testing_type>(Buf1.begin(), Buf1.end(), acc);
        BOOST_CHECK(field.value().size() == 1U);
        auto &members = field.value()[0].value();
        auto &mem1 = std::get<0>(members);
        auto &mem2 = std::get<1>(members);
        BOOST_CHECK(mem1.value() == 0x102);
        BOOST_CHECK(mem2.is_missing());

        BOOST_CHECK(field.set_version(15U));
        BOOST_CHECK(mem2.does_exist());
        BOOST_CHECK(field.length() == 4U);
    } while (false);

    do {
        accumulator_set<testing_type> acc = accumulator_set<testing_type>(field);

        static const std::vector<char> Buf2 = {(char)0x03, (char)0x04, (char)0x05, (char)0x06};

        field = pack<testing_type>(Buf2.begin(), Buf2.end(), acc);
        BOOST_CHECK(field.value().size() == 1U);
        auto &members = field.value()[0].value();
        auto &mem1 = std::get<0>(members);
        auto &mem2 = std::get<1>(members);
        BOOST_CHECK(field.length() == 4U);
        BOOST_CHECK(mem2.does_exist());
        BOOST_CHECK(mem1.value() == 0x304);
        BOOST_CHECK(mem2.field().value() == 0x506);
    } while (false);
}

BOOST_AUTO_TEST_CASE(test98) {
    using testing_type
        = types::integral<field_type<option::big_endian>, std::uint8_t, option::invalid_by_default, option::version_storage>;

    testing_type field;
    BOOST_CHECK(!field.valid());
    BOOST_CHECK(field.get_version() == 0U);
    BOOST_CHECK(field.set_version(5U));
    BOOST_CHECK(field.get_version() == 5U);

    using Field2
        = types::bitmask_value<field_type<option::big_endian>, option::fixed_length<1U>, option::default_num_value<0x6U>,
                               option::version_storage, option::bitmask_reserved_bits<0xc2U, 0x2U>>;

    Field2 field2;
    BOOST_CHECK(field2.get_version() == 0U);
    BOOST_CHECK(field2.set_version(5U));
    BOOST_CHECK(field2.get_version() == 5U);
}

BOOST_AUTO_TEST_CASE(test99) {
    typedef types::array_list<field_type<option::big_endian>, std::uint8_t, option::sequence_length_forcing_enabled> Field1;

    static_assert(!Field1::is_version_dependent(), "Invalid version dependency assumption");

    Field1 field1;
    BOOST_CHECK(field1.valid());

    field1.force_read_length(4U);

    static const std::vector<char> Buf = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9};

    accumulator_set<Field1> acc1 = accumulator_set<Field1>(field1);

    field1 = pack<Field1>(Buf.begin(), Buf.end(), acc1);
    BOOST_CHECK(field1.value().size() == 4U);
    BOOST_CHECK(field1.length() == 4U);
    BOOST_CHECK(field1.valid());
    field1.clear_read_length_forcing();

    typedef types::string<field_type<option::big_endian>, option::sequence_length_forcing_enabled> Field2;

    static_assert(!Field2::is_version_dependent(), "Invalid version dependency assumption");

    Field2 field2;
    BOOST_CHECK(field2.valid());

    field2.force_read_length(5U);

    static const std::vector<char> Buf2 = {'h', 'e', 'l', 'l', 'o', 'a', 'b', 'c', 'd'};

    accumulator_set<Field2> acc2 = accumulator_set<Field2>(field2);

    field2 = pack<Field2>(Buf2.begin(), Buf2.end(), acc2);
    BOOST_CHECK(field2.value() == "hello");
    BOOST_CHECK(field2.valid());
    field2.clear_read_length_forcing();
}

BOOST_AUTO_TEST_CASE(test100) {
    typedef types::integral<field_type<option::big_endian>, std::int64_t, option::fixed_length<5U, false>,
                             option::num_value_ser_offset<0x492559f64fLL>, option::scaling_ratio<1, 0x174878e800LL>>
        testing_type;

    testing_type field;

    static const std::vector<char> Buf = {(char)0x87, (char)0x54, (char)0xa2, (char)0x03, (char)0xb9};

    field = pack<testing_type>(Buf.begin(), Buf.end());

    BOOST_CHECK(std::abs(field.get_scaled<double>() - 2.67) < 0.1);
}

BOOST_AUTO_TEST_SUITE_END()
