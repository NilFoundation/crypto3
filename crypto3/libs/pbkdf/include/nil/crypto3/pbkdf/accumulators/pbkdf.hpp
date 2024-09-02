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

#ifndef CRYPTO3_ACCUMULATORS_PBKDF_HPP
#define CRYPTO3_ACCUMULATORS_PBKDF_HPP

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <boost/container/static_vector.hpp>

#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/static_digest.hpp>

#include <nil/crypto3/pbkdf/accumulators/parameters/bits.hpp>
#include <nil/crypto3/pbkdf/accumulators/parameters/salt.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename CodecMode>
                struct pdkdf_impl<CodecMode> : boost::accumulators::accumulator_base {
                protected:
                    typedef CodecMode codec_mode_type;

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

                    pdkdf_impl(boost::accumulators::dont_care) : leading_zeros(0) {
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
                };
            }    // namespace impl

            namespace tag {
                template<typename Hash>
                struct pdkdf : boost::accumulators::depends_on<> {
                    typedef Hash hash_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::pdkdf_impl<Hash>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Hash, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::pdkdf<Hash>>::type::result_type
                    pdkdf(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::pdkdf<Hash>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_BLOCK_HPP