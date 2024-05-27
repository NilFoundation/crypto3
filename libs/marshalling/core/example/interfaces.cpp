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

using namespace nil::marshalling;

using T = std::vector<uint32_t>;
const std::vector<uint16_t> in = {{0x1234, 0x5678}};
const T out = {0x12345678};

void result_as_output() {
    status_type status;

    T result1 = pack(in, status);
    std::cout << "Using input as parameter: " << equal(result1.begin(), result1.end(), out.begin()) << std::endl;

    T result2 = pack(in.begin(), in.end(), status);
    std::cout << "Using input iterators as parameters: " << equal(result2.begin(), result2.end(), out.begin()) << std::endl;
}

void result_as_parameter() {
    status_type status;

    T result1;
    status = pack(in, result1);
    std::cout << "Using input as parameter: " << equal(result1.begin(), result1.end(), out.begin()) << std::endl;

    T result2;
    status = pack(in.begin(), in.end(), result2);
    std::cout << "Using input iterators as parameters: " << equal(result2.begin(), result2.end(), out.begin()) << std::endl;
}

void result_as_iterator_parameter() {
    status_type status;

    T result1(out.size());
    typename T::iterator itr1 = result1.begin();
    itr1 = pack(in, result1.begin(), status);
    std::cout << "Using input as parameter, output as begin iterator: " << equal(result1.begin(), result1.end(), out.begin()) << std::endl;

    T result2(out.size());
    typename T::iterator itr2 = result2.begin();
    itr2 = pack(in.begin(), in.end(), result2.begin(), status);
    std::cout << "Using input iterators as parameters, output as begin iterator: " << equal(result2.begin(), result2.end(), out.begin()) << std::endl;

    T result3(out.size());
    typename T::iterator itr3 = result1.begin();
    status = pack(in, result3.begin());
    std::cout << "Using input as parameter, output as begin iterator: " << equal(result3.begin(), result3.end(), out.begin()) << std::endl;

    T result4(out.size());
    typename T::iterator itr4 = result2.begin();
    status = pack(in.begin(), in.end(), result4.begin());
    std::cout << "Using input iterators as parameters, output as begin iterator: " << equal(result4.begin(), result4.end(), out.begin()) << std::endl;
}

int main(int argc, char *argv[]) {
    std::cout << "Interface usage examples" << std::endl;

    std::cout << std::endl << "Result type as output:" << std::endl;
    result_as_output();

    std::cout << std::endl << "Result type as parameter:" << std::endl;
    result_as_parameter();

    std::cout << std::endl << "Result type as iterator parameter:" << std::endl;
    result_as_iterator_parameter();
}