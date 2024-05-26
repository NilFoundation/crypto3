//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ACCUMULATION_VECTOR_HPP
#define CRYPTO3_MARSHALLING_ACCUMULATION_VECTOR_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/container/accumulation_vector.hpp>

#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>
#include <nil/crypto3/marshalling/zk/types/sparse_vector.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<
                    typename TTypeBase,
                    typename AccumulationVector,
                    typename = typename std::enable_if<
                        std::is_same<AccumulationVector,
                                     container::accumulation_vector<typename AccumulationVector::group_type>>::value,
                        bool>::type,
                    typename... TOptions>
                using accumulation_vector = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        curve_element<TTypeBase, typename AccumulationVector::group_type>,
                        sparse_vector<TTypeBase, container::sparse_vector<typename AccumulationVector::group_type>>>>;

                template<typename AccumulationVector, typename Endianness>
                accumulation_vector<nil::marshalling::field_type<Endianness>, AccumulationVector>
                    fill_accumulation_vector(const AccumulationVector &accumulation_vector_inp) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    using curve_element_type = curve_element<TTypeBase, typename AccumulationVector::group_type>;

                    curve_element_type filled_first = curve_element_type(accumulation_vector_inp.first);

                    return accumulation_vector<nil::marshalling::field_type<Endianness>, AccumulationVector>(
                        std::make_tuple(
                            filled_first,
                            fill_sparse_vector<container::sparse_vector<typename AccumulationVector::group_type>,
                                               Endianness>(accumulation_vector_inp.rest)));
                }

                template<typename AccumulationVector, typename Endianness>
                AccumulationVector make_accumulation_vector(
                    const accumulation_vector<nil::marshalling::field_type<Endianness>, AccumulationVector>
                        &filled_accumulation_vector) {

                    return AccumulationVector(
                        std::move(std::get<0>(filled_accumulation_vector.value()).value()),
                        std::move(make_sparse_vector<container::sparse_vector<typename AccumulationVector::group_type>,
                                                     Endianness>(std::get<1>(filled_accumulation_vector.value()))));
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_ACCUMULATION_VECTOR_HPP
