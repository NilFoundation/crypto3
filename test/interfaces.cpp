//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
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

#define BOOST_TEST_MODULE hash_pack_test

#include <boost/array.hpp>
#include <boost/cstdint.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

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

#include <nil/marshalling/algorithms/unpack.hpp>
#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/marshalling/algorithms/repack.hpp>

#include <boost/container/static_vector.hpp>

#include <boost/type_traits/is_class.hpp>

#include <cstdio>

using namespace nil::marshalling;

BOOST_AUTO_TEST_SUITE(pack_interfaces_test_suite)

template <typename Vector>
void resize(Vector &t, size_t count) {
    t.resize(count);
}

template <typename T, size_t ArraySize>
void resize(std::array<T, ArraySize> &t, size_t count) {
    BOOST_CHECK(ArraySize == count);
}


template <typename T, typename Input>
void test_pack(Input in) {
    status_type status;

    T result1 = pack<option::big_endian>(in, status);
    BOOST_CHECK(status == status_type::success);

    T result2 = pack<option::big_endian>(in.begin(), in.end(), status);
    BOOST_CHECK(status == status_type::success);

    T result3;
    status = pack<option::big_endian>(in, result3);
    BOOST_CHECK(status == status_type::success);

    T result4;
    status = pack<option::big_endian>(in.begin(), in.end(), result4);
    BOOST_CHECK(status == status_type::success);

#ifdef INPUT_HAS_BEGIN
    T result5;
    resize(result5, 2);
    pack<option::big_endian>(in, result5.begin(), status);
    BOOST_CHECK(status == status_type::success);

    T result6;
    resize(result6, 2);
    pack<option::big_endian>(in.begin(), in.end(), result6.begin(), status);
    BOOST_CHECK(status == status_type::success);

    T result7;
    resize(result7, 2);
    status = pack<option::big_endian>(in, result7.begin());
    BOOST_CHECK(status == status_type::success);

    T result8;
    resize(result8, 2);
    status = pack<option::big_endian>(in.begin(), in.end(), result8.begin());
    BOOST_CHECK(status == status_type::success);
#endif

}

template <typename T, typename Tinput>
void test_unpack(Tinput in) {
    status_type status;

    T res_1_1 = unpack<option::big_endian>(in, status);
    T res_1_2 = unpack<option::big_endian>(in.begin(), in.end(), status);
    T res_1_3, res_1_4;
    status = unpack<option::big_endian>(in, res_1_3);
    status = unpack<option::big_endian>(in.begin(), in.end(), res_1_4);

}

BOOST_AUTO_TEST_CASE(vector_test) {
#define INPUT_HAS_BEGIN 1
    std::vector<uint8_t> in1 = {0x12, 0x34, 0x56, 0x78};
    test_pack<std::vector<uint16_t>>(in1);
    test_pack<std::array<uint16_t, 2>>(in1);
//    test_pack<boost::array<uint16_t, 2>>(in1);
    test_pack<boost::container::static_vector<uint16_t, 2>>(in1);
#define INPUT_HAS_BEGIN 0
    test_pack<types::integral<field_type<option::big_endian>, std::uint16_t>>(in1);

#define INPUT_HAS_BEGIN 1
    std::array<uint8_t, 4> in2 = {0x12, 0x34, 0x56, 0x78};
    test_pack<std::vector<uint16_t>>(in2);
    test_pack<std::array<uint16_t, 2>>(in2);
//    test_pack<boost::array<uint16_t, 2>>(in2);
    test_pack<boost::container::static_vector<uint16_t, 2>>(in2);
#define INPUT_HAS_BEGIN 0
    test_pack<types::integral<field_type<option::big_endian>, std::uint16_t>>(in2);

    std::vector<uint16_t> in = {0x1234, 0x5678};
    test_unpack<std::vector<uint8_t>>(in);
    test_unpack<std::array<uint8_t, 4>>(in);
    test_unpack<boost::container::static_vector<uint8_t, 4>>(in);
}

BOOST_AUTO_TEST_SUITE_END()
