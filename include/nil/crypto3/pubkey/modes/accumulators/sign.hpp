//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ACCUMULATORS_PUBKEY_MODES_SIGN_HPP
#define CRYPTO3_ACCUMULATORS_PUBKEY_MODES_SIGN_HPP

#include <nil/crypto3/pubkey/accumulators/sign.hpp>

#include <nil/crypto3/pubkey/secret_sharing.hpp>

#include <nil/crypto3/pubkey/modes/threshold.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename ProcessingMode>
                struct sign_impl<ProcessingMode,
                                 typename std::enable_if<!std::is_same<
                                     pubkey::weighted_shamir_sss<
                                         typename ProcessingMode::key_type::sss_public_key_group_type::group_type>,
                                     typename ProcessingMode::key_type::sss_public_key_group_type>::value>::type>
                    : boost::accumulators::accumulator_base {
                protected:
                    typedef ProcessingMode mode_type;
                    typedef typename mode_type::scheme_type scheme_type;
                    typedef typename mode_type::padding_type padding_type;
                    typedef typename mode_type::key_type key_type;

                    constexpr static const auto block_bits = mode_type::input_block_bits;
                    typedef typename mode_type::input_block_type input_block_type;

                    constexpr static const auto value_bits = mode_type::input_value_bits;
                    typedef typename mode_type::input_value_type input_value_type;

                public:
                    typedef typename mode_type::result_type result_type;

                    template<typename Args>
                    sign_impl(const Args &args) : private_key(args[boost::accumulators::sample]) {
                    }

                    template<typename Args>
                    inline void operator()(const Args &args) {
                        resolve_type(
                            args[boost::accumulators::sample],
                            args[::nil::crypto3::accumulators::iterator_last | typename input_block_type::iterator()]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        return mode_type::process(private_key, cache);
                    }

                protected:
                    template<typename InputBlock, typename InputIterator>
                    inline void resolve_type(const InputBlock &block, InputIterator) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const InputBlock>));
                        resolve_type(block.cbegin(), block.cend());
                    }

                    template<
                        typename ValueType,
                        typename InputIterator,
                        typename std::enable_if<std::is_same<input_value_type, ValueType>::value, bool>::type = true>
                    inline void resolve_type(const ValueType &value, InputIterator) {
                        cache.emplace_back(value);
                    }

                    template<
                        typename InputIterator,
                        typename ValueType = typename std::iterator_traits<InputIterator>::value_type,
                        typename std::enable_if<std::is_same<input_value_type, ValueType>::value, bool>::type = true>
                    inline void resolve_type(InputIterator first, InputIterator last) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
                        std::copy(first, last, std::back_inserter(cache));
                    }

                    key_type private_key;
                    input_block_type cache;
                };

                template<typename ProcessingMode>
                struct sign_impl<ProcessingMode,
                                 typename std::enable_if<std::is_same<
                                     pubkey::weighted_shamir_sss<
                                         typename ProcessingMode::key_type::sss_public_key_group_type::group_type>,
                                     typename ProcessingMode::key_type::sss_public_key_group_type>::value>::type>
                    : boost::accumulators::accumulator_base {
                protected:
                    typedef ProcessingMode mode_type;
                    typedef typename mode_type::scheme_type scheme_type;
                    typedef typename mode_type::padding_type padding_type;
                    typedef typename mode_type::key_type key_type;

                    constexpr static const auto block_bits = mode_type::input_block_bits;
                    typedef typename mode_type::input_block_type input_block_type;

                    constexpr static const auto value_bits = mode_type::input_value_bits;
                    typedef typename mode_type::input_value_type input_value_type;

                    typedef typename key_type::sss_public_key_no_key_ops_type::weights_type weights_type;

                public:
                    typedef typename mode_type::result_type result_type;

                    template<typename Args>
                    sign_impl(const Args &args) : private_key(args[boost::accumulators::sample]) {
                    }

                    template<typename Args>
                    inline void operator()(const Args &args) {
                        resolve_type(
                            args[boost::accumulators::sample],
                            args[::nil::crypto3::accumulators::iterator_last | typename input_block_type::iterator()]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        return mode_type::process(private_key, cache, confirmed_weights);
                    }

                protected:
                    template<
                        typename InputBlock,
                        typename InputIterator,
                        typename ValueType = typename std::iterator_traits<typename InputBlock::iterator>::value_type,
                        typename std::enable_if<std::is_same<input_value_type, ValueType>::value, bool>::type = true>
                    inline void resolve_type(const InputBlock &block, InputIterator) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const InputBlock>));
                        resolve_type(block.cbegin(), block.cend());
                    }

                    template<
                        typename ValueType,
                        typename InputIterator,
                        typename std::enable_if<std::is_same<input_value_type, ValueType>::value, bool>::type = true>
                    inline void resolve_type(const ValueType &value, InputIterator) {
                        cache.emplace_back(value);
                    }

                    template<
                        typename InputIterator,
                        typename ValueType = typename std::iterator_traits<InputIterator>::value_type,
                        typename std::enable_if<std::is_same<input_value_type, ValueType>::value, bool>::type = true>
                    inline void resolve_type(InputIterator first, InputIterator last) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
                        std::copy(first, last, std::back_inserter(cache));
                    }

                    template<
                        typename Weight,
                        typename InputIterator,
                        typename key_type::sss_public_key_no_key_ops_type::template check_weight_type<Weight> = true>
                    inline void resolve_type(const Weight &w, InputIterator) {
                        if (!confirmed_weights.count(w.first)) {
                            assert(confirmed_weights.emplace(w).second);
                        } else {
                            confirmed_weights.at(w.first) = w.second;
                        }
                    }

                    template<typename InputIterator,
                             typename key_type::sss_public_key_no_key_ops_type::template check_weight_type<
                                 typename std::iterator_traits<InputIterator>::value_type> = true>
                    inline void resolve_type(InputIterator first, InputIterator last) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
                        for (auto it = first; it != last; it++) {
                            resolve_type(*it, last);
                        }
                    }

                    template<
                        typename Weights,
                        typename InputIterator,
                        typename key_type::sss_public_key_no_key_ops_type::template check_weights_type<Weights> = true>
                    inline void resolve_type(const Weights &weights, InputIterator) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Weights>));
                        resolve_type(weights.begin(), weights.end());
                    }

                    key_type private_key;
                    input_block_type cache;
                    weights_type confirmed_weights;
                };
            }    // namespace impl
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_SIGN_HPP
