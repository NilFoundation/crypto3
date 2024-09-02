//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#include <boost/array.hpp>
#include <boost/cstdint.hpp>

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

#include <nil/marshalling/algorithms/pack.hpp>

#include <boost/container/static_vector.hpp>

#include <boost/type_traits/is_class.hpp>

#include <cstdio>
#include <variant>
#include <iostream>
#include <array>

using namespace nil::marshalling;

template<typename T>
void to_big_vector(T input) {
    using TOut = std::vector<uint32_t>;
    status_type status;
    const TOut out = {0x12345678};
    TOut result = pack(input, status);

    if (status == nil::marshalling::status_type::success && equal(result.begin(), result.end(), out.begin())) {
        std::cout << "success" << std::endl;
    } else {
        std::cout << "fail" << std::endl;
    }
}

template<typename T>
void to_small_vector(T input) {
    using TOut = std::vector<uint8_t>;
    status_type status;
    const TOut out = {0x12, 0x34, 0x56, 0x78};
    TOut result = pack(input, status);

    if (status == nil::marshalling::status_type::success && std::equal(result.begin(), result.end(), out.begin())) {
        std::cout << "success" << std::endl;
    } else {
        std::cout << "fail" << std::endl;
    }
}

template<typename T>
void to_big_array(T input) {
    using TOut = std::array<uint32_t, 1>;
    status_type status;
    const TOut out = {0x12345678};
    TOut result = pack(input, status);

    if (status == nil::marshalling::status_type::success && std::equal(result.begin(), result.end(), out.begin())) {
        std::cout << "success" << std::endl;
    } else {
        std::cout << "fail" << std::endl;
    }
}

template<typename T>
void to_small_array(T input) {
    using TOut = std::array<uint8_t, 4>;
    status_type status;
    TOut out = {0x12, 0x34, 0x56, 0x78};
    TOut result = pack(input, status);

    if (status == nil::marshalling::status_type::success && std::equal(result.begin(), result.end(), out.begin())) {
        std::cout << "success" << std::endl;
    } else {
        std::cout << "fail" << std::endl;
    }
}

template<typename T>
void to_type(T input) {
    using TOut = uint32_t;
    status_type status;
    TOut out = 0x12345678;
    TOut result = pack(input, status);

    if (status == nil::marshalling::status_type::success && result == out) {
        std::cout << "success" << std::endl;
    } else {
        std::cout << "fail" << std::endl;
    }
}

template<typename T>
void to_marshalling_type(T input) {
    using TOut = types::integral<field_type<option::big_endian>, std::uint16_t>;
    status_type status;
    std::uint16_t out = 0x1234;
    TOut result = pack(input, status);

    if (status == nil::marshalling::status_type::success && result.value() == out) {
        std::cout << "success" << std::endl;
    } else {
        std::cout << "fail" << std::endl;
    }
}

template <typename T>
void to_different_types(T input) {
    std::cout << "- big vector: ";
    to_big_vector(input);
    std::cout << "- small vector: ";
    to_small_vector(input);
    std::cout << "- big array: ";
    to_big_array(input);
    std::cout << "- small array: ";
    to_small_array(input);
    std::cout << "- type: ";
    to_type(input);
    std::cout << "- marshalling type: ";
    to_marshalling_type(input);
}

int main(int argc, char *argv[]) {
    const std::vector<uint16_t> v_b_in = {0x1234, 0x5678};
    const std::vector<uint8_t> v_s_in = {0x12, 0x34, 0x56, 0x78};
    const std::array<uint16_t, 2> a_b_in = {0x1234, 0x5678};
    const std::array<uint8_t, 4> a_s_in = {0x12, 0x34, 0x56, 0x78};
    const uint32_t type_in = 0x12345678;
    using marshalling_type_input = types::array_list<field_type<option::big_endian>,
                                         types::integral<field_type<option::big_endian>, std::uint8_t>,
                                         option::fixed_size_storage<4>>;
    using input_seed_type = typename marshalling_type_input::value_type;
    marshalling_type_input marshalling_type_in;
    std::array<std::uint16_t, 4> inp_seed_blank = {{0x12, 0x34, 0x56, 0x78}};
    input_seed_type &inp_seed = marshalling_type_in.value();
    for (auto it = inp_seed_blank.begin(); it != inp_seed_blank.end(); ++it) {
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    std::cout << "From big vector to:" << std::endl;
    to_different_types(v_b_in);
    std::cout << "From small vector to:" << std::endl;
    to_different_types(v_s_in);
    std::cout << "From big array to:" << std::endl;
    to_different_types(a_b_in);
    std::cout << "From small array to:" << std::endl;
    to_different_types(a_s_in);
    std::cout << "From type to:" << std::endl;
    to_different_types(type_in);
    std::cout << "From marshalling type to:" << std::endl;
    to_different_types(marshalling_type_in);
}