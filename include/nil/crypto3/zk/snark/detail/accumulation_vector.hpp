//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_SNARK_ACCUMULATION_VECTOR_HPP
#define CRYPTO3_ZK_SNARK_ACCUMULATION_VECTOR_HPP

#include <iostream>

#include <nil/crypto3/zk/snark/detail/sparse_vector.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename T>
                class accumulation_vector;

                template<typename T>
                std::ostream &operator<<(std::ostream &out, const accumulation_vector<T> &v);

                template<typename T>
                std::istream &operator>>(std::istream &in, accumulation_vector<T> &v);

                /**
                 * An accumulation vector comprises an accumulation value and a sparse vector.
                 * The method "accumulate_chunk" allows one to accumlate portions of the sparse
                 * vector into the accumualation value.
                 */
                template<typename T>
                class accumulation_vector {
                public:
                    T first;
                    sparse_vector<T> rest;

                    accumulation_vector() = default;
                    accumulation_vector(const accumulation_vector<T> &other) = default;
                    accumulation_vector(accumulation_vector<T> &&other) = default;
                    accumulation_vector(T &&first, sparse_vector<T> &&rest) :
                        first(std::move(first)), rest(std::move(rest)) {};
                    accumulation_vector(T &&first, std::vector<T> &&v) : first(std::move(first)), rest(std::move(v)) {
                    }
                    accumulation_vector(std::vector<T> &&v) : first(T::zero()), rest(std::move(v)) {};

                    accumulation_vector<T> &operator=(const accumulation_vector<T> &other) = default;
                    accumulation_vector<T> &operator=(accumulation_vector<T> &&other) = default;

                    bool operator==(const accumulation_vector<T> &other) const;

                    bool is_fully_accumulated() const;

                    std::size_t domain_size() const;
                    std::size_t size() const;
                    std::size_t size_in_bits() const;

                    template<typename FieldType>
                    accumulation_vector<T>
                        accumulate_chunk(const typename std::vector<FieldType>::const_iterator &it_begin,
                                         const typename std::vector<FieldType>::const_iterator &it_end,
                                         const std::size_t offset) const;
                };

                template<typename T>
                std::ostream &operator<<(std::ostream &out, const accumulation_vector<T> &v);

                template<typename T>
                std::istream &operator>>(std::istream &in, accumulation_vector<T> &v);

                template<typename T>
                bool accumulation_vector<T>::operator==(const accumulation_vector<T> &other) const {
                    return (this->first == other.first && this->rest == other.rest);
                }

                template<typename T>
                bool accumulation_vector<T>::is_fully_accumulated() const {
                    return rest.empty();
                }

                template<typename T>
                std::size_t accumulation_vector<T>::domain_size() const {
                    return rest.domain_size();
                }

                template<typename T>
                std::size_t accumulation_vector<T>::size() const {
                    return rest.domain_size();
                }

                template<typename T>
                std::size_t accumulation_vector<T>::size_in_bits() const {
                    const std::size_t first_size_in_bits = T::size_in_bits();
                    const std::size_t rest_size_in_bits = rest.size_in_bits();
                    return first_size_in_bits + rest_size_in_bits;
                }

                template<typename T>
                template<typename FieldType>
                accumulation_vector<T> accumulation_vector<T>::accumulate_chunk(
                    const typename std::vector<FieldType>::const_iterator &it_begin,
                    const typename std::vector<FieldType>::const_iterator &it_end,
                    const std::size_t offset) const {
                    std::pair<T, sparse_vector<T>> acc_result =
                        rest.template accumulate<FieldType>(it_begin, it_end, offset);
                    T new_first = first + acc_result.first;
                    return accumulation_vector<T>(std::move(new_first), std::move(acc_result.second));
                }

                template<typename T>
                std::ostream &operator<<(std::ostream &out, const accumulation_vector<T> &v) {
                    out << v.first << OUTPUT_NEWLINE;
                    out << v.rest << OUTPUT_NEWLINE;

                    return out;
                }

                template<typename T>
                std::istream &operator>>(std::istream &in, accumulation_vector<T> &v) {
                    in >> v.first;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> v.rest;
                    algebra::consume_OUTPUT_NEWLINE(in);

                    return in;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SNARK_ACCUMULATION_VECTOR_HPP
