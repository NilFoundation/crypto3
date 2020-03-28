//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ACCUMULATORS_PUBKEY_HPP
#define CRYPTO3_PUBKEY_ACCUMULATORS_PUBKEY_HPP

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <boost/container/static_vector.hpp>

#include <nil/crypto3/pubkey/accumulators/parameters/bits.hpp>

#include <nil/crypto3/pubkey/detail/digest.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Mode>
                struct pubkey_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Mode mode_type;
                    typedef typename mode_type::finalizer_type finalizer_type;

                    constexpr static const std::size_t input_block_bits = mode_type::input_block_bits;
                    constexpr static const std::size_t input_block_values = mode_type::input_block_values;
                    typedef typename mode_type::input_block_type input_block_type;

                    constexpr static const std::size_t input_value_bits = mode_type::input_value_bits;
                    typedef typename input_block_type::value_type input_value_type;

                    constexpr static const std::size_t output_block_bits = mode_type::output_block_bits;
                    constexpr static const std::size_t output_block_values = mode_type::output_block_values;
                    typedef typename mode_type::output_block_type output_block_type;

                    constexpr static const std::size_t output_value_bits = mode_type::output_value_bits;
                    typedef typename output_block_type::value_type output_value_type;

                    typedef boost::container::static_vector<input_value_type, input_block_values> cache_type;

                public:
                    typedef pubkey::digest<output_block_bits> result_type;

                    template<typename Args>
                    // The constructor takes an argument pack.
                    pubkey_impl(const Args &args) : seen(0) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                    }

                protected:
                    std::size_t seen;
                    cache_type cache;
                    result_type digest;
                };
            }    // namespace impl

            namespace tag {
                template<typename Mode>
                struct pubkey : boost::accumulators::depends_on<> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::pubkey_impl<Mode>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::pubkey<Mode>>::type::result_type
                    pubkey(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::pubkey<Mode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_HPP
