//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ACCUMULATORS_PUBKEY_SCHEME_KEYS_HPP
#define CRYPTO3_ACCUMULATORS_PUBKEY_SCHEME_KEY_HPP

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
                struct scheme_keys_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Mode mode_type;
                    typedef typename Mode::cipher_type cipher_type;
                    typedef typename Mode::padding_type padding_type;

                    typedef typename mode_type::endian_type endian_type;

                    constexpr static const std::size_t word_bits = mode_type::word_bits;
                    typedef typename mode_type::word_type word_type;

                    constexpr static const std::size_t pubkey_bits = mode_type::pubkey_bits;
                    constexpr static const std::size_t pubkey_words = mode_type::pubkey_words;
                    typedef typename mode_type::pubkey_type pubkey_type;

                    constexpr static const std::size_t value_bits = sizeof(typename pubkey_type::value_type) * CHAR_BIT;
                    constexpr static const std::size_t pubkey_values = pubkey_bits / value_bits;

                    typedef ::nil::crypto3::detail::injector<endian_type, value_bits, pubkey_values, pubkey_bits>
                        injector_type;

                public:
                    typedef digest<pubkey_bits> result_type;

                    template<typename Args>
                    scheme_keys_impl(const Args &args) : total_seen(0), mode(args[boost::accumulators::sample]) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        resolve_type(args[boost::accumulators::sample],
                                     args[::nil::crypto3::accumulators::bits | std::size_t()]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        using namespace ::nil::crypto3::detail;

                        result_type res = dgst;

                        return res;
                    }

                protected:
                    inline void resolve_type(const pubkey_type &value, std::size_t bits) {
                        process(value, bits == 0 ? pubkey_bits : bits);
                    }

                    inline void resolve_type(const word_type &value, std::size_t bits) {
                        process(value, bits == 0 ? word_bits : bits);
                    }

                    inline void process(const pubkey_type &value, std::size_t value_seen) {
                        using namespace ::nil::crypto3::detail;
                    }

                    inline void process(const word_type &value, std::size_t value_seen) {
                        using namespace ::nil::crypto3::detail;
                    }

                    mode_type mode;

                    std::size_t total_seen;
                    pubkey_type cache;
                    result_type dgst;
                };
            }    // namespace impl

            namespace tag {
                template<typename Mode>
                struct scheme_key : boost::accumulators::depends_on<bits_count> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::scheme_keys_impl<mode_type>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::scheme<Mode>>::type::result_type
                    scheme_key(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::scheme<Mode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_HPP
