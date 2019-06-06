//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ACCUMULATORS_CODEC_HPP
#define CRYPTO3_ACCUMULATORS_CODEC_HPP

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <boost/container/static_vector.hpp>

#include <nil/crypto3/codec/detail/make_array.hpp>
#include <nil/crypto3/codec/detail/digest.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Mode>
                struct codec_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Mode mode_type;
                    typedef typename mode_type::finalizer_type finalizer_type;

                    typedef typename mode_type::input_block_type input_block_type;
                    typedef typename input_block_type::value_type input_value_type;
                    constexpr static const std::size_t input_block_bits = mode_type::input_block_bits;
                    constexpr static const std::size_t input_value_bits =
                            input_block_bits / std::tuple_size<input_block_type>::value;

                    typedef typename mode_type::output_block_type output_block_type;
                    typedef typename output_block_type::value_type output_value_type;
                    constexpr static const std::size_t output_block_bits = mode_type::output_block_bits;
                    constexpr static const std::size_t output_value_bits =
                            output_block_bits / std::tuple_size<output_block_type>::value;

                    typedef boost::container::static_vector<input_value_type,
                                                            std::tuple_size<input_block_type>::value> cache_type;

                public:
                    typedef codec::digest<output_block_bits> result_type;

                    template<typename Args>
                    // The constructor takes an argument pack.
                    codec_impl(const Args &args) : seen(0), cache(cache_type()), digest(result_type()) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        return process(args[boost::accumulators::sample]);
                    }

                    template<typename ArgumentPack>
                    inline result_type result(const ArgumentPack &args) const {
                        result_type result = digest;

                        if (input_block_bits && seen % input_block_bits) {
                            finalizer_type(input_block_bits - seen % input_block_bits)(result);
                        } else {
                            finalizer_type(0)(result);
                        }

                        return result;
                    }

                protected:

                    inline void process(const input_value_type &value) {
                        if (cache.size() < cache.max_size()) {
                            cache.push_back(value);
                            seen += input_value_bits;
                        } else {
                            output_block_type ob = mode_type::process_block(
                                    codec::make_array<std::tuple_size<input_block_type>::value>(cache.begin(),
                                            cache.end()));
                            std::move(ob.begin(), ob.end(), digest.end());
                            seen += input_value_bits;
                            cache.clear();
                        }
                    }

                    inline void process(const input_block_type &block) {
                        if (cache.empty()) {
                            output_block_type ob = mode_type::process_block(block);
                            std::move(ob.begin(), ob.end(), digest.end());
                            seen += input_block_bits;
                        } else {
                            input_block_type b = codec::make_array<std::tuple_size<input_block_type>::value>(
                                    cache.begin(), cache.end());
                            typename input_block_type::const_iterator itr =
                                    block.begin() + (cache.max_size() - cache.size());

                            std::copy(block.begin(), itr, b.end());

                            output_block_type ob = mode_type::process_block(block);

                            std::move(ob.begin(), ob.end(), digest.end());

                            seen += input_block_bits;

                            cache.clear();
                            cache.insert(cache.end(), itr, block.end());
                            seen += input_value_bits * std::distance(itr, block.end());
                        }
                    }

                    std::size_t seen;
                    cache_type cache;
                    result_type digest;
                };
            }

            namespace tag {
                template<typename Mode>
                struct codec : boost::accumulators::depends_on<> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::codec_impl<Mode>> impl;
                };
            }

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::codec<Mode> >::type::result_type codec(
                        const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::codec<Mode> >(acc);
                }
            }
        }
    }
}

#endif //CRYPTO3_ACCUMULATORS_CODEC_HPP
