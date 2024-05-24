//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Aleksey Moskvin <zerg1996@yandex.ru>
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

#ifndef CRYPTO3_ACCUMULATORS_CODEC_HPP
#define CRYPTO3_ACCUMULATORS_CODEC_HPP

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <boost/container/static_vector.hpp>

#include <boost/range/algorithm.hpp>

#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/digest.hpp>

#include <nil/crypto3/codec/accumulators/parameters/bits.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            template<typename CodecMode>
            struct accumulator_mode {
                typedef CodecMode codec_mode_type;
            };

            template<typename CodecMode>
            struct preprocessing_accumulator_mode : public accumulator_mode<CodecMode> {
                typedef typename accumulator_mode<CodecMode>::codec_mode_type codec_mode_type;
            };

            template<typename CodecMode>
            struct postprocessing_accumulator_mode : public accumulator_mode<CodecMode> {
                typedef typename accumulator_mode<CodecMode>::codec_mode_type codec_mode_type;
            };

            namespace impl {
                template<typename CodecMode, typename AccumulatorMode>
                struct codec_impl : boost::accumulators::accumulator_base {
                    typedef CodecMode codec_mode_type;
                    typedef AccumulatorMode accumulator_mode_type;
                };

                template<typename CodecMode>
                struct codec_impl<CodecMode, preprocessing_accumulator_mode<CodecMode>>
                    : boost::accumulators::accumulator_base {
                protected:
                    typedef CodecMode codec_mode_type;
                    typedef preprocessing_accumulator_mode<CodecMode> accumulator_mode_type;

                    typedef typename codec_mode_type::finalizer_type finalizer_type;
                    typedef typename codec_mode_type::preprocessor_type preprocessor_type;

                    constexpr static const std::size_t input_block_bits = codec_mode_type::input_block_bits;
                    constexpr static const std::size_t input_block_values = codec_mode_type::input_block_values;
                    typedef typename codec_mode_type::input_block_type input_block_type;

                    constexpr static const std::size_t input_value_bits = codec_mode_type::input_value_bits;
                    typedef typename input_block_type::value_type input_value_type;

                    constexpr static const std::size_t output_block_bits = codec_mode_type::output_block_bits;
                    constexpr static const std::size_t output_block_values = codec_mode_type::output_block_values;
                    typedef typename codec_mode_type::output_block_type output_block_type;

                    constexpr static const std::size_t output_value_bits = codec_mode_type::output_value_bits;
                    typedef typename output_block_type::value_type output_value_type;

                    typedef boost::container::static_vector<input_value_type, input_block_values> cache_type;

                public:
                    typedef digest<output_block_bits> result_type;

                    codec_impl(boost::accumulators::dont_care) : seen(0) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        resolve_type(args[boost::accumulators::sample], args[bits | std::size_t()]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        result_type res = dgst;

                        if (!cache.empty()) {
                            input_block_type ib = {0};
                            std::move(cache.begin(), cache.end(), ib.begin());
                            output_block_type ob = codec_mode_type::process_block(ib);
                            std::move(ob.begin(), ob.end(), std::inserter(res, res.end()));
                        }

                        if (seen % input_block_bits) {
                            finalizer_type(input_block_bits - seen % input_block_bits)(res);
                        } else {
                            finalizer_type(0)(res);
                        }

                        return res;
                    }

                protected:
                    inline void resolve_type(const input_value_type &value, std::size_t bits) {
                        if (bits == std::size_t()) {
                            process(value, input_value_bits);
                        } else {
                            process(value, bits);
                        }
                    }

                    inline void resolve_type(const input_block_type &value, std::size_t bits) {
                        if (bits == std::size_t()) {
                            process(value, input_block_bits);
                        } else {
                            process(value, bits);
                        }
                    }

                    inline void process(const input_value_type &value, std::size_t) {
                        if (cache.size() == cache.max_size()) {
                            input_block_type ib = {0};
                            std::move(cache.begin(), cache.end(), ib.begin());
                            output_block_type ob = codec_mode_type::process_block(ib);
                            std::move(ob.begin(), ob.end(), std::inserter(dgst, dgst.end()));

                            cache.clear();
                        }

                        cache.push_back(value);
                        seen += input_value_bits;
                    }

                    inline void process(const input_block_type &block, std::size_t) {
                        output_block_type ob;
                        if (cache.empty()) {
                            ob = codec_mode_type::process_block(block);
                        } else {
                            input_block_type b = make_array<input_block_values>(cache.begin(), cache.end());
                            typename input_block_type::const_iterator itr =
                                block.begin() + (cache.max_size() - cache.size());

                            std::move(block.begin(), itr, b.end());

                            ob = codec_mode_type::process_block(b);

                            cache.clear();
                            cache.insert(cache.end(), itr, block.end());
                        }

                        std::move(ob.begin(), ob.end(), std::inserter(dgst, dgst.end()));
                        seen += input_block_bits;
                    }

                    std::size_t seen;
                    cache_type cache;
                    result_type dgst;
                };

                template<typename CodecMode>
                struct codec_impl<CodecMode, postprocessing_accumulator_mode<CodecMode>>
                    : boost::accumulators::accumulator_base {
                protected:
                    typedef CodecMode codec_mode_type;
                    typedef postprocessing_accumulator_mode<CodecMode> accumulator_mode_type;

                    typedef typename codec_mode_type::finalizer_type finalizer_type;
                    typedef typename codec_mode_type::preprocessor_type preprocessor_type;

                    constexpr static const std::size_t input_block_bits = codec_mode_type::input_block_bits;
                    constexpr static const std::size_t input_block_values = codec_mode_type::input_block_values;
                    typedef typename codec_mode_type::input_block_type input_block_type;

                    constexpr static const std::size_t input_value_bits = codec_mode_type::input_value_bits;
                    typedef typename input_block_type::value_type input_value_type;

                    constexpr static const std::size_t output_block_bits = codec_mode_type::output_block_bits;
                    constexpr static const std::size_t output_block_values = codec_mode_type::output_block_values;
                    typedef typename codec_mode_type::output_block_type output_block_type;

                    constexpr static const std::size_t output_value_bits = codec_mode_type::output_value_bits;
                    typedef typename output_block_type::value_type output_value_type;

                public:
                    typedef digest<output_block_bits> result_type;

                    codec_impl(boost::accumulators::dont_care) : leading_zeros(0) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        preprocessor_type preprocessor;
                        const input_block_type block =
                            args[boost::accumulators::sample];    // TODO: I think it must be user type block like
                                                                  // dgst
                        if (input.empty()) {
                            preprocessor(block);
                            leading_zeros = preprocessor.leading_zeros;
                        }
                        std::move(block.begin(), block.end(), std::back_inserter(input));
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        result_type res;
                        output_block_type ob = codec_mode_type::process_block(input);
                        std::move(ob.begin(), ob.end(), std::inserter(res, res.end()));
                        if (leading_zeros) {
                            finalizer_type fin(leading_zeros);
                            fin(res);
                        }
                        std::reverse(res.begin(), res.end());
                        return res;
                    }

                protected:
                    std::size_t leading_zeros;
                    input_block_type input;
                };    // namespace impl
            }         // namespace impl

            namespace tag {
                template<typename ProcessingMode>
                struct codec : boost::accumulators::depends_on<> {
                    typedef ProcessingMode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::codec_impl<
                        mode_type, typename mode_type::codec_type::template accumulator_mode_type<ProcessingMode>>>
                        impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::codec<Mode>>::type::result_type
                    codec(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::codec<Mode>>(acc);
                }

                template<typename Codec, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet,
                                           tag::codec<typename Codec::stream_encoder_type>>::type::result_type
                    encode(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::codec<typename Codec::stream_encoder_type>>(acc);
                }

                template<typename Codec, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet,
                                           tag::codec<typename Codec::stream_decoder_type>>::type::result_type
                    decode(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::codec<typename Codec::stream_decoder_type>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_CODEC_HPP
