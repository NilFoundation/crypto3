//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Aleksey Moskvin <zerg1996@yandex.ru>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BITS_COUNT_HPP
#define CRYPTO3_BITS_COUNT_HPP

#include <boost/mpl/always.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/mac/accumulators/parameters/bits.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {

                ///////////////////////////////////////////////////////////////////////////////
                // bits_count_impl
                struct bits_count_impl : boost::accumulators::accumulator_base {
                    // for boost::result_of
                    typedef std::size_t result_type;

                    bits_count_impl(boost::accumulators::dont_care) : cnt(0) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        resolve_type(args[boost::accumulators::sample], args[bits | std::size_t()]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        return cnt;
                    }

                protected:
                    template<typename Block>
                    inline void resolve_type(const Block &value, std::size_t bits) {
                        cnt += bits;
                    }

                    std::size_t cnt;
                };

            }    // namespace impl

            ///////////////////////////////////////////////////////////////////////////////
            // tag::count
            //
            namespace tag {
                struct bits_count : boost::accumulators::depends_on<> {
                    /// INTERNAL ONLY
                    ///
                    typedef boost::mpl::always<accumulators::impl::bits_count_impl> impl;
                };
            }    // namespace tag

            ///////////////////////////////////////////////////////////////////////////////
            // extract::count
            //
            namespace extract {
                boost::accumulators::extractor<tag::bits_count> const bits_count = {};

                BOOST_ACCUMULATORS_IGNORE_GLOBAL(bits_count)
            }    // namespace extract

        }    // namespace accumulators
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_BLOCK_BITS_COUNT_HPP
