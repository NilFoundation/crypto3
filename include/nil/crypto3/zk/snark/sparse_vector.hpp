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
// @file Declaration of interfaces for a sparse vector.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_SPARSE_VECTOR_HPP
#define CRYPTO3_ZK_SPARSE_VECTOR_HPP

#include <iostream>
#include <vector>
#include <numeric>

#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A sparse vector is a list of indices along with corresponding values.
                 * The indices are selected from the set {0,1,...,domain_size-1}.
                 */
                template<typename Type>
                struct sparse_vector {

                    using group_type = Type;

                private:
                    using underlying_value_type = 
                        typename group_type::value_type;
                public:
                    
                    std::vector<std::size_t> indices;
                    std::vector<underlying_value_type> values;
                    std::size_t domain_size_;

                    sparse_vector() = default;
                    sparse_vector(const sparse_vector<Type> &other) = default;
                    sparse_vector(sparse_vector<Type> &&other) = default;
                    sparse_vector(std::vector<underlying_value_type> &&v) :
                        values(std::move(v)), domain_size_(values.size()) {
                        indices.resize(domain_size_);
                        std::iota(indices.begin(), indices.end(), 0);
                    }

                    sparse_vector<Type> &operator=(const sparse_vector<Type> &other) = default;
                    sparse_vector<Type> &operator=(sparse_vector<Type> &&other) = default;

                    underlying_value_type operator[](const std::size_t idx) const {
                        auto it = std::lower_bound(indices.begin(), indices.end(), idx);
                        return (it != indices.end() && *it == idx) ? values[it - indices.begin()] :
                                                                     underlying_value_type();
                    }

                    bool operator==(const sparse_vector<Type> &other) const {
                        if (this->domain_size_ != other.domain_size_) {
                            return false;
                        }

                        std::size_t this_pos = 0, other_pos = 0;
                        while (this_pos < this->indices.size() && other_pos < other.indices.size()) {
                            if (this->indices[this_pos] == other.indices[other_pos]) {
                                if (this->values[this_pos] != other.values[other_pos]) {
                                    return false;
                                }
                                ++this_pos;
                                ++other_pos;
                            } else if (this->indices[this_pos] < other.indices[other_pos]) {
                                if (!this->values[this_pos].is_zero()) {
                                    return false;
                                }
                                ++this_pos;
                            } else {
                                if (!other.values[other_pos].is_zero()) {
                                    return false;
                                }
                                ++other_pos;
                            }
                        }

                        /* at least one of the vectors has been exhausted, so other must be empty */
                        while (this_pos < this->indices.size()) {
                            if (!this->values[this_pos].is_zero()) {
                                return false;
                            }
                            ++this_pos;
                        }

                        while (other_pos < other.indices.size()) {
                            if (!other.values[other_pos].is_zero()) {
                                return false;
                            }
                            ++other_pos;
                        }

                        return true;
                    }

                    bool operator==(const std::vector<underlying_value_type> &other) const {
                        if (this->domain_size_ < other.size()) {
                            return false;
                        }

                        std::size_t j = 0;
                        for (std::size_t i = 0; i < other.size(); ++i) {
                            if (this->indices[j] == i) {
                                if (this->values[j] != other[j]) {
                                    return false;
                                }
                                ++j;
                            } else {
                                if (!other[j].is_zero()) {
                                    return false;
                                }
                            }
                        }

                        return true;
                    }

                    bool is_valid() const {
                        if (values.size() == indices.size() && values.size() <= domain_size_) {
                            return false;
                        }

                        for (std::size_t i = 0; i + 1 < indices.size(); ++i) {
                            if (indices[i] >= indices[i + 1]) {
                                return false;
                            }
                        }

                        if (!indices.empty() && indices[indices.size() - 1] >= domain_size_) {
                            return false;
                        }

                        return true;
                    }

                    bool empty() const {
                        return indices.empty();
                    }

                    std::size_t domain_size() const {
                        return domain_size_;
                    }

                    std::size_t size() const {
                        return indices.size();
                    }

                    std::size_t size_in_bits() const {
                        return indices.size() * (sizeof(std::size_t) * 8 + Type::value_bits);
                    }

                    /* return a pair consisting of the accumulated value and the sparse vector of non-accumulated values
                     */
                    template<typename InputBaseIterator>
                    std::pair<underlying_value_type, sparse_vector<Type>>
                        accumulate(InputBaseIterator it_begin, InputBaseIterator it_end, std::size_t offset) const {
#ifdef MULTICORE
                        const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env var
                                                                             // or call omp_set_num_threads()
#else
                        const std::size_t chunks = 1;
#endif

                        underlying_value_type accumulated_value = underlying_value_type::zero();
                        sparse_vector<Type> resulting_vector;
                        resulting_vector.domain_size_ = domain_size_;

                        const std::size_t range_len = std::distance(it_begin, it_end);
                        bool in_block = false;
                        std::size_t first_pos = -1,
                                    last_pos = -1;    // g++ -flto emits unitialized warning, even though in_block
                        // guards for such cases.

                        for (std::size_t i = 0; i < indices.size(); ++i) {
                            const bool matching_pos = (offset <= indices[i] && indices[i] < offset + range_len);
                            // printf("i = %zu, pos[i] = %zu, offset = %zu, w_size = %zu\n", i, indices[i], offset,
                            // w_size);
                            bool copy_over;

                            if (in_block) {
                                if (matching_pos && last_pos == i - 1) {
                                    // block can be extended, do it
                                    last_pos = i;
                                    copy_over = false;
                                } else {
                                    // block has ended here
                                    in_block = false;
                                    copy_over = true;

                                    accumulated_value =
                                        accumulated_value +
                                        algebra::multiexp<algebra::policies::multiexp_method_bos_coster>(
                                            values.begin() + first_pos, values.begin() + last_pos + 1,
                                            it_begin + (indices[first_pos] - offset),
                                            it_begin + (indices[last_pos] - offset) + 1, chunks);
                                }
                            } else {
                                if (matching_pos) {
                                    // block can be started
                                    first_pos = i;
                                    last_pos = i;
                                    in_block = true;
                                    copy_over = false;
                                } else {
                                    copy_over = true;
                                }
                            }

                            if (copy_over) {
                                resulting_vector.indices.emplace_back(indices[i]);
                                resulting_vector.values.emplace_back(values[i]);
                            }
                        }

                        if (in_block) {
                            accumulated_value =
                                accumulated_value + algebra::multiexp<algebra::policies::multiexp_method_bos_coster>(
                                                        values.begin() + first_pos,
                                                        values.begin() + last_pos + 1,
                                                        it_begin + (indices[first_pos] - offset),
                                                        it_begin + (indices[last_pos] - offset) + 1,
                                                        chunks);
                        }

                        return std::make_pair(accumulated_value, resulting_vector);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SPARSE_VECTOR_HPP
