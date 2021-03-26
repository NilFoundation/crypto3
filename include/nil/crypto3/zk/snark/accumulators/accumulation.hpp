//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ACCUMULATORS_ZK_ACCUMULATION_HPP
#define CRYPTO3_ACCUMULATORS_ZK_ACCUMULATION_HPP

#include <boost/container/static_vector.hpp>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/zk/snark/accumulators/sparse.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace detail {
                template<typename Mode>
                struct accumulation_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Mode mode_type;
                    typedef typename Mode::cipher_type cipher_type;
                    typedef typename Mode::padding_type padding_type;

                    typedef typename mode_type::endian_type endian_type;

                    constexpr static const std::size_t word_bits = mode_type::word_bits;
                    typedef typename mode_type::word_type word_type;

                    constexpr static const std::size_t block_bits = mode_type::block_bits;
                    constexpr static const std::size_t block_words = mode_type::block_words;
                    typedef typename mode_type::block_type block_type;

                    constexpr static const std::size_t value_bits = sizeof(typename block_type::value_type) * CHAR_BIT;
                    constexpr static const std::size_t block_values = block_bits / value_bits;

                    typedef ::nil::crypto3::detail::injector<endian_type, value_bits, block_values, block_bits>
                        injector_type;

                public:
                    typedef digest<block_bits> result_type;

                    template<typename Args>
                    accumulation_impl(const Args &args) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        resolve_type(args[boost::accumulators::sample]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                    }

                protected:
                    inline void resolve_type(const word_type &value) {
                        process(value, word_bits);
                    }

                    inline void process_snark() {
                    }

                    inline void process(const block_type &value, std::size_t value_seen) {
                    }

                    inline void process(const word_type &value, std::size_t value_seen) {
                    }
                };
            }    // namespace detail

            namespace tag {
                template<typename T>
                struct accumulation : boost::accumulators::depends_on<sparse<T>> {

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::detail::accumulation_impl<T>> impl;
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
