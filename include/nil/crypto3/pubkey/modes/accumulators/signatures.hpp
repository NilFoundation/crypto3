//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ACCUMULATORS_PUBKEY_SCHEME_SIGS_HPP
#define CRYPTO3_ACCUMULATORS_PUBKEY_SCHEME_SIGS_HPP

#include <boost/container/static_vector.hpp>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/digest.hpp>
#include <nil/crypto3/detail/inject.hpp>

#include <nil/crypto3/pubkey/accumulators/bits_count.hpp>

#include <nil/crypto3/pubkey/accumulators/parameters/scheme.hpp>
#include <nil/crypto3/pubkey/accumulators/parameters/bits.hpp>

#include <nil/crypto3/pubkey/scheme.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Mode>
                struct scheme_sigs_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Mode mode_type;
                    typedef typename Mode::scheme_type scheme_type;
                    typedef typename Mode::padding_type padding_type;

                    typedef typename mode_type::endian_type endian_type;

                    constexpr static const std::size_t public_key_bits = scheme_type::public_key_type::key_bits;
                    typedef typename scheme_type::public_key_type::key_type public_key_type;

                    constexpr static const std::size_t private_key_bits = scheme_type::private_key_type::key_bits;
                    typedef typename scheme_type::private_key_type::key_type private_key_type;

                    constexpr static const std::size_t scheme_key_bits = mode_type::scheme_key_bits;
                    typedef typename mode_type::key_type scheme_key_type;

                public:
                    typedef std::pair<public_key_type, private_key_type> result_type;

                    template<typename Args>
                    scheme_sigs_impl(const Args &args) : mode(args[boost::accumulators::sample]) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        resolve_type(args[boost::accumulators::sample]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        using namespace ::nil::crypto3::detail;

                        result_type res = dgst;

                        return res;
                    }

                protected:
                    inline void resolve_type(const scheme_key_type &value) {
                    }
                    mode_type mode;

                    result_type dgst;
                };
            }    // namespace impl

            namespace tag {
                template<typename Mode>
                struct scheme_sigs : boost::accumulators::depends_on<bits_count> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::scheme_sigs_impl<mode_type>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::scheme_sigs<Mode>>::type::result_type
                    scheme_sigs(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::scheme_sigs<Mode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_HPP
