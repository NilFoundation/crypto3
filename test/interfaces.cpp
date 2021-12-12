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
typename std::enable_if<std::is_class<Vector>::value, void>::type
    resize(Vector &t, size_t count) {
    t.resize(count);
}

template <typename T>
typename std::enable_if<!std::is_class<T>::value, void>::type resize(T &t, size_t count) {

}

template <typename T, size_t ArraySize>
void resize(std::array<T, ArraySize> &t, size_t count) {
    BOOST_CHECK(ArraySize == count);
}

template <typename T, size_t ArraySize>
void resize(boost::array<T, ArraySize> &t, size_t count) {
    BOOST_CHECK(ArraySize == count);
}

template <typename T, typename Input>
void test_pack_output_have_begin(Input in) {
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
}

template <typename T, typename Input>
void test_pack_output_have_not_begin(Input in) {
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
}

template <typename T, typename Tinput>
void test_unpack_input_have_begin(Tinput in) {
    status_type status;

    T result1 = unpack<option::big_endian>(in, status);
    BOOST_CHECK(status == status_type::success);

    T result2 = unpack<option::big_endian>(in.begin(), in.end(), status);
    BOOST_CHECK(status == status_type::success);

    T result3;
    status = unpack<option::big_endian>(in, result3);
    BOOST_CHECK(status == status_type::success);

    T result4;
    status = unpack<option::big_endian>(in.begin(), in.end(), result4);
    BOOST_CHECK(status == status_type::success);

    T result5;
    resize(result5, 4);
    unpack<option::big_endian>(in, result5.begin(), status);
    BOOST_CHECK(status == status_type::success);

    T result6;
    resize(result6, 4);
    unpack<option::big_endian>(in.begin(), in.end(), result6.begin(), status);
    BOOST_CHECK(status == status_type::success);

    T result7;
    resize(result7, 4);
    status = unpack<option::big_endian>(in, result7.begin());
    BOOST_CHECK(status == status_type::success);

    T result8;
    resize(result8, 4);
    status = pack<option::big_endian>(in.begin(), in.end(), result8.begin());
    BOOST_CHECK(status == status_type::success);
}

template <typename T, typename Tinput>
void test_unpack_input_have_not_begin(Tinput in) {
    status_type status;

    T result1 = unpack<option::big_endian>(in, status);
    BOOST_CHECK(status == status_type::success);

    T result3;
    status = unpack<option::big_endian>(in, result3);
    BOOST_CHECK(status == status_type::success);

    T result5;
    resize(result5, 4);
    unpack<option::big_endian>(in, result5.begin(), status);
    BOOST_CHECK(status == status_type::success);

    T result7;
    resize(result7, 4);
    status = unpack<option::big_endian>(in, result7.begin());
    BOOST_CHECK(status == status_type::success);
}

template <typename T, typename Tinput>
void test_unpack_input_marshalling(Tinput in) {
    status_type status;

    T result1 = unpack(in, status);
    BOOST_CHECK(status == status_type::success);

    T result3;
    status = unpack(in, result3);
    BOOST_CHECK(status == status_type::success);

    T result5;
    resize(result5, 4);
    unpack(in, result5.begin(), status);
    BOOST_CHECK(status == status_type::success);

    T result7;
    resize(result7, 4);
    status = unpack(in, result7.begin());
    BOOST_CHECK(status == status_type::success);
}


BOOST_AUTO_TEST_CASE(pack_test) {
    std::vector<uint8_t> in1 = {0x12, 0x34, 0x56, 0x78};
    test_pack_output_have_begin<std::vector<uint16_t>>(in1);
    test_pack_output_have_begin<std::array<uint16_t, 2>>(in1);
    test_pack_output_have_begin<boost::array<uint16_t, 2>>(in1);
    test_pack_output_have_begin<boost::container::static_vector<uint16_t, 2>>(in1);
    test_pack_output_have_not_begin<std::uint32_t>(in1);
    test_pack_output_have_not_begin<types::integral<field_type<option::big_endian>, std::uint16_t>>(in1);

    std::array<uint8_t, 4> in2 = {0x12, 0x34, 0x56, 0x78};
    test_pack_output_have_begin<std::vector<uint16_t>>(in2);
    test_pack_output_have_begin<std::array<uint16_t, 2>>(in2);
    test_pack_output_have_begin<boost::array<uint16_t, 2>>(in2);
    test_pack_output_have_begin<boost::container::static_vector<uint16_t, 2>>(in2);
    test_pack_output_have_not_begin<std::uint32_t>(in2);
    test_pack_output_have_not_begin<types::integral<field_type<option::big_endian>, std::uint16_t>>(in2);

}

BOOST_AUTO_TEST_CASE(unpack_test) {
    std::vector<uint16_t> in1 = {0x1234, 0x5678};
    test_unpack_input_have_begin<std::vector<uint8_t>>(in1);
    test_unpack_input_have_begin<std::array<uint8_t, 4>>(in1);
    test_unpack_input_have_begin<boost::container::static_vector<uint8_t, 4>>(in1);
    test_unpack_input_have_begin<boost::array<uint8_t, 4>>(in1);

    std::array<uint16_t, 2> in2 = {0x1234, 0x5678};
    test_unpack_input_have_begin<std::vector<uint8_t>>(in2);
    test_unpack_input_have_begin<std::array<uint8_t, 4>>(in2);
    test_unpack_input_have_begin<boost::container::static_vector<uint8_t, 4>>(in2);
    test_unpack_input_have_begin<boost::array<uint8_t, 4>>(in2);


    uint32_t in3 = 0x12345678;
    test_unpack_input_have_not_begin<std::vector<uint8_t>>(in3);
    test_unpack_input_have_not_begin<std::array<uint8_t, 4>>(in3);
    test_unpack_input_have_not_begin<boost::container::static_vector<uint8_t, 4>>(in3);
    test_unpack_input_have_not_begin<boost::array<uint8_t, 4>>(in3);

    using input_type = types::array_list<
        field_type<option::little_endian>,
        types::integral<
            field_type<option::big_endian>,
            std::uint8_t>,
        option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    input_type in4;
    std::array<std::uint16_t, 2> inp_seed_blank = {{0x1234, 0x5678}};
    input_seed_type &inp_seed = in4.value();
    for (auto it = inp_seed_blank.begin();
         it != inp_seed_blank.end();
         ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    test_unpack_input_marshalling<std::vector<uint8_t>>(in4);
    test_unpack_input_marshalling<std::array<uint8_t, 4>>(in4);
    test_unpack_input_marshalling<boost::container::static_vector<uint8_t, 4>>(in4);
    test_unpack_input_marshalling<boost::array<uint8_t, 4>>(in4);
}

BOOST_AUTO_TEST_CASE(repack_test) {
    using T = std::vector<std::uint16_t>;
    using Tout = std::vector<std::uint32_t>;
    std::vector<std::uint16_t> in = {0x1234, 0x5678, 0x90ab, 0xcdef};
    std::vector<std::uint32_t> res = {{0x12345678, 0x90abcdef}};


    status_type status;

    T result1 = repack<option::big_endian, option::big_endian>(in, status);
    BOOST_CHECK(status == status_type::success);

    T result2 = repack<option::big_endian, option::big_endian>(in.begin(), in.end(), status);
    BOOST_CHECK(status == status_type::success);

    T result3;
    status = repack<option::big_endian, option::big_endian>(in, result3);
    BOOST_CHECK(status == status_type::success);

    T result4;
    status = repack<option::big_endian, option::big_endian>(in.begin(), in.end(), result4);
    BOOST_CHECK(status == status_type::success);

    T result5;
    resize(result5, 2);
    repack<option::big_endian, option::big_endian>(in, result5.begin(), status);
    BOOST_CHECK(status == status_type::success);

    T result6;
    resize(result6, 2);
    repack<option::big_endian, option::big_endian>(in.begin(), in.end(), result6.begin(), status);
    BOOST_CHECK(status == status_type::success);

    T result7;
    resize(result7, 2);
    status = repack<option::big_endian, option::big_endian>(in, result7.begin());
    BOOST_CHECK(status == status_type::success);

    T result8;
    resize(result8, 2);
    status = repack<option::big_endian, option::big_endian>(in.begin(), in.end(), result8.begin());
    BOOST_CHECK(status == status_type::success);
}

BOOST_AUTO_TEST_SUITE_END()
