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

#ifndef CRYPTO3_ACCUMULATORS_PUBKEY_AGGREGATE_VERIFY_HPP
#define CRYPTO3_ACCUMULATORS_PUBKEY_AGGREGATE_VERIFY_HPP

#include <type_traits>
#include <iterator>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/pubkey/accumulators/parameters/key.hpp>
#include <nil/crypto3/pubkey/accumulators/parameters/iterator_last.hpp>
#include <nil/crypto3/pubkey/accumulators/parameters/signature.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Mode>
                struct aggregate_verify_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Mode mode_type;
                    typedef typename mode_type::scheme_type scheme_type;
                    typedef typename mode_type::padding_type padding_type;
                    typedef typename mode_type::key_type key_type;

                    constexpr static const auto block_bits = mode_type::input_block_bits;
                    typedef typename mode_type::input_block_type input_block_type;

                    constexpr static const auto value_bits = mode_type::input_value_bits;
                    typedef typename mode_type::input_value_type input_value_type;

                    typedef typename key_type::public_key_type public_key_type;
                    typedef typename key_type::private_key_type private_key_type;
                    typedef typename key_type::signature_type signature_type;
                    typedef typename key_type::aggregate_type cache_type;

                public:
                    typedef typename mode_type::result_type result_type;

                    template<typename Args>
                    aggregate_verify_impl(const Args &args) :
                        signature(args[boost::accumulators::sample]), is_current_key_set(false) {
                    }

                    template<typename Args,
                             typename std::enable_if<
                                 !std::is_same<signature_type,
                                               typename std::remove_cv<typename boost::parameter::value_type<
                                                   Args,
                                                   boost::accumulators::tag::sample,
                                                   int>::type>::type>::value &&
                                     !std::is_same<key_type,
                                                   typename std::remove_cv<typename boost::parameter::value_type<
                                                       Args,
                                                       boost::accumulators::tag::sample,
                                                       int>::type>::type>::value &&
                                     std::is_same<key_type,
                                                  typename std::remove_cv<typename boost::parameter::value_type<
                                                      Args,
                                                      ::nil::crypto3::accumulators::tag::key,
                                                      int>::type>::type>::value,
                                 bool>::type = true>
                    inline void operator()(const Args &args) {
                        resolve_type(
                            args[boost::accumulators::sample],
                            args[::nil::crypto3::accumulators::iterator_last | typename input_block_type::iterator()],
                            args[::nil::crypto3::accumulators::key]);
                    }

                    template<typename Args,
                             typename std::enable_if<
                                 !std::is_same<signature_type,
                                               typename std::remove_cv<typename boost::parameter::value_type<
                                                   Args,
                                                   boost::accumulators::tag::sample,
                                                   int>::type>::type>::value &&
                                     !std::is_same<key_type,
                                                   typename std::remove_cv<typename boost::parameter::value_type<
                                                       Args,
                                                       boost::accumulators::tag::sample,
                                                       int>::type>::type>::value &&
                                     !std::is_same<key_type,
                                                   typename std::remove_cv<typename boost::parameter::value_type<
                                                       Args,
                                                       ::nil::crypto3::accumulators::tag::key,
                                                       int>::type>::type>::value,
                                 bool>::type = true>
                    inline void operator()(const Args &args) {
                        assert(is_current_key_set);
                        resolve_type(
                            args[boost::accumulators::sample],
                            args[::nil::crypto3::accumulators::iterator_last | typename input_block_type::iterator()],
                            current_key);
                    }

                    template<typename Args,
                             typename std::enable_if<
                                 std::is_same<signature_type,
                                              typename std::remove_cv<typename boost::parameter::value_type<
                                                  Args,
                                                  boost::accumulators::tag::sample,
                                                  int>::type>::type>::value,
                                 bool>::type = true>
                    inline void operator()(const Args &args) {
                        signature = args[boost::accumulators::sample];
                    }

                    template<typename Args,
                             typename std::enable_if<
                                 std::is_same<key_type,
                                              typename std::remove_cv<typename boost::parameter::value_type<
                                                  Args,
                                                  boost::accumulators::tag::sample,
                                                  int>::type>::type>::value,
                                 bool>::type = true>
                    inline void operator()(const Args &args) {
                        current_key = args[boost::accumulators::sample];
                        is_current_key_set = true;
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        assert(cache.size() > 0);
                        return mode_type::process(cache, signature);
                    }

                protected:
                    template<
                        typename InputBlock,
                        typename InputIterator,
                        typename std::enable_if<std::is_same<input_value_type, typename InputBlock::value_type>::value,
                                                bool>::type = true>
                    inline void resolve_type(const InputBlock &block, InputIterator, const key_type &key) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const InputBlock>));
                        resolve_type(block.cbegin(), block.cend(), key);
                    }

                    template<
                        typename ValueType,
                        typename InputIterator,
                        typename std::enable_if<std::is_same<input_value_type, ValueType>::value, bool>::type = true>
                    inline void resolve_type(const ValueType &value, InputIterator, const key_type &key) {
                        key.append_aggregate_data(cache, value);
                    }

                    template<
                        typename InputIterator,
                        typename ValueType = typename std::iterator_traits<InputIterator>::value_type,
                        typename std::enable_if<std::is_same<input_value_type, ValueType>::value, bool>::type = true>
                    inline void resolve_type(InputIterator first, InputIterator last, const key_type &key) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
                        key.append_aggregate_data(cache, first, last);
                    }

                    cache_type cache;
                    signature_type signature;
                    key_type current_key;
                    bool is_current_key_set;
                };
            }    // namespace impl

            namespace tag {
                template<typename Mode>
                struct aggregate_verify : boost::accumulators::depends_on<> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::aggregate_verify_impl<mode_type>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::aggregate_verify<Mode>>::type::result_type
                    scheme(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::aggregate_verify<Mode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_AGGREGATE_VERIFY_HPP
