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

#ifndef CRYPTO3_ZK_SNARK_ACCUMULATION_VECTOR_HPP
#define CRYPTO3_ZK_SNARK_ACCUMULATION_VECTOR_HPP

#include <iostream>
#include <iterator>

#include <nil/crypto3/zk/snark/sparse_vector.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * An accumulation vector comprises an accumulation value and a sparse vector.
                 * The method "accumulate_chunk" allows one to accumulate portions of the sparse
                 * vector into the accumulation value.
                 */
                template<typename Type>
                class accumulation_vector {
                    using underlying_value_type = typename Type::value_type;

                public:
                    underlying_value_type first;
                    sparse_vector<Type> rest;

                    accumulation_vector() = default;
                    accumulation_vector(const accumulation_vector<Type> &other) = default;
                    accumulation_vector(accumulation_vector<Type> &&other) = default;
                    accumulation_vector(underlying_value_type &&first, sparse_vector<Type> &&rest) :
                        first(std::move(first)), rest(std::move(rest)) {};
                    accumulation_vector(underlying_value_type &&first, std::vector<underlying_value_type> &&v) :
                        first(std::move(first)), rest(std::move(v)) {
                    }
                    accumulation_vector(std::vector<underlying_value_type> &&v) :
                        first(underlying_value_type::zero()), rest(std::move(v)) {};

                    accumulation_vector<Type> &operator=(const accumulation_vector<Type> &other) = default;
                    accumulation_vector<Type> &operator=(accumulation_vector<Type> &&other) = default;

                    bool operator==(const accumulation_vector<Type> &other) const {
                        return (this->first == other.first && this->rest == other.rest);
                    }

                    bool is_fully_accumulated() const {
                        return rest.empty();
                    }

                    std::size_t domain_size() const {
                        return rest.domain_size();
                    }

                    std::size_t size() const {
                        return rest.domain_size();
                    }

                    std::size_t size_in_bits() const {
                        const std::size_t first_size_in_bits = Type::value_bits;
                        const std::size_t rest_size_in_bits = rest.size_in_bits();
                        return first_size_in_bits + rest_size_in_bits;
                    }

                    template<typename InputIterator>
                    accumulation_vector<Type> accumulate_chunk(InputIterator begin, InputIterator end,
                                                               std::size_t offset) const {
                        std::pair<underlying_value_type, sparse_vector<Type>> acc_result =
                            rest.accumulate(begin, end, offset);
                        underlying_value_type new_first = first + acc_result.first;
                        return accumulation_vector<Type>(std::move(new_first), std::move(acc_result.second));
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SNARK_ACCUMULATION_VECTOR_HPP
