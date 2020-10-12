//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ACCUMULATORS_PUBKEY_SCHEME_KEYS_HPP
#define CRYPTO3_ACCUMULATORS_PUBKEY_SCHEME_KEYS_HPP

#include <unordered_map>

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
                    typedef typename Mode::scheme_type scheme_type;
                    typedef typename Mode::padding_type padding_type;

                    typedef typename mode_type::endian_type endian_type;

                    constexpr static const std::size_t public_key_bits = scheme_type::public_key_type::key_bits;
                    typedef typename scheme_type::public_key_type::key_type public_key_type;

                    constexpr static const std::size_t private_key_bits = scheme_type::private_key_type::key_bits;
                    typedef typename scheme_type::private_key_type::key_type private_key_type;

                    constexpr static const std::size_t scheme_key_bits = mode_type::scheme_key_bits;
                    typedef typename mode_type::key_type scheme_key_type;

                    typedef std::pair<private_key_type, private_key_type> input_type;

                public:
                    typedef std::pair<public_key_type, private_key_type> result_type;

                    template<typename Args>
                    scheme_keys_impl(const Args &args) : mode(args[boost::accumulators::sample]) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        process(args[boost::accumulators::sample]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        using namespace ::nil::crypto3::detail;

                        result_type res = dgst;

                        return res;
                    }

                protected:
                    inline void process(const input_type &value) {
                        cache.insert(value);
                    }

                    std::unordered_map<private_key_type, private_key_type> cache;

                    mode_type mode;

                    result_type dgst;
                };
            }    // namespace impl

            namespace tag {
                template<typename Mode>
                struct scheme_keys : boost::accumulators::depends_on<bits_count> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::scheme_keys_impl<mode_type>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::scheme_keys<Mode>>::type::result_type
                    scheme_keys(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::scheme_keys<Mode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_HPP
