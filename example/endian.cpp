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

int main(int argc, char *argv[]) {
    status_type status;

    std::cout << "Using default (big_endian) for input and output" << std::endl; // Input by default option::big_endian
    std::vector<std::uint8_t> in1 = {{0x12, 0x34, 0x56, 0x78}};
    std::uint32_t res1 = 0x12345678;

    std::uint32_t out1 = pack(in1, status);

    assert(status == status_type::success);
    assert(out1 == res1);

    std::cout << "Change only output endian" << std::endl; // Input by default option::big_endian
    std::vector<std::uint8_t> in2 = {{0x12, 0x34, 0x56, 0x78}};
    std::uint32_t res2 = 0x78563412;

    std::uint32_t out2 = pack<option::little_endian>(in2, status);

    assert(status == status_type::success);
    assert(out2 == res2);

    std::cout << "Change input and output endian" << std::endl;
    std::vector<std::uint8_t> in3 = {{0x12, 0x34, 0x56, 0x78}};
    std::uint32_t res3 = 0x78563412;

    std::uint32_t out3 = pack<option::little_endian, option::little_endian>(in2, status);

    assert(status == status_type::success);
    assert(out3 == res3);

}