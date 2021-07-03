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

#ifndef CRYPTO3_ACCUMULATORS_ZK_SPARSE_HPP
#define CRYPTO3_ACCUMULATORS_ZK_SPARSE_HPP

#include <boost/container/static_vector.hpp>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/zk/snark/accumulators/parameters/offset.hpp>

#include <nil/crypto3/algebra/multiexp/multiexp.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace detail {
                template<typename T>
                struct sparse_impl : boost::accumulators::accumulator_base {
                    typedef typename T::value_type value_type;
                    typedef std::vector<std::size_t> indicies_type;

                    typedef std::pair<value_type, std::pair<indicies_type, std::vector<T>>> result_type;

                    template<typename Args>
                    sparse_impl(const Args &args) : in_block(false), accumulated_value(value_type::zero()) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        resolve_type(args[boost::accumulators::sample], args[::nil::crypto3::accumulators::offset]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                    }

                protected:
                    template<typename SinglePassRange>
                    inline result_type resolve_type(const SinglePassRange r, std::size_t offset) {
                        const std::size_t chunks = 1;

                        std::pair<indicies_type, std::vector<T>> resulting_vector;
                        resulting_vector.domain_size_ = domain_size_;

                        const std::size_t range_len = r.size();
                        std::size_t first_pos = -1, last_pos = -1;
                        for (std::size_t i = 0; i < indices.size(); ++i) {
                            const bool matching_pos = (offset <= indices[i] && indices[i] < offset + range_len);
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
                                            std::begin(r) + (indices[first_pos] - offset),
                                            std::begin(r) + (indices[last_pos] - offset) + 1, chunks);
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
                                resulting_vector.first.emplace_back(indices[i]);
                                resulting_vector.second.emplace_back(values[i]);
                            }
                        }

                        if (in_block) {
                            accumulated_value =
                                accumulated_value + algebra::multiexp<algebra::policies::multiexp_method_bos_coster>(
                                                        values.begin() + first_pos,
                                                        values.begin() + last_pos + 1,
                                                        std::begin(r) + (indices[first_pos] - offset),
                                                        std::begin(r) + (indices[last_pos] - offset) + 1,
                                                        chunks);
                        }

                        return std::make_pair(accumulated_value, resulting_vector);
                    }

                    bool in_block;

                    value_type accumulated_value;

                    indicies_type indices;
                    std::vector<value_type> values;
                    std::size_t domain_size_;
                };
            }    // namespace detail

            namespace tag {
                template<typename T>
                struct sparse : boost::accumulators::depends_on<> {
                    typedef T value_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::detail::sparse_impl<value_type>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::sparse<Mode>>::type::result_type
                    sparse(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::sparse<Mode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_SNARK_HPP
