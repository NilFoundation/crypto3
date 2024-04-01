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

#ifndef CRYPTO3_HASH_STREAM_POSTPROCESSOR_HPP
#define CRYPTO3_HASH_STREAM_POSTPROCESSOR_HPP

#include <array>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>
#include <boost/array.hpp>

#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/hash/accumulators/hash.hpp>
#include <nil/crypto3/hash/detail/stream_processors/block_stream_processor.hpp>
#include <nil/crypto3/hash/detail/stream_processors/raw_stream_processor.hpp>
#include <nil/crypto3/hash/detail/stream_processors/raw_delegating_stream_processor.hpp>
#include <nil/crypto3/hash/detail/stream_processors/stream_processors_enum.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename HashAccumulatorSet>
                struct ref_hash_impl {
                    typedef HashAccumulatorSet accumulator_set_type;
                    typedef
                        typename boost::mpl::front<typename accumulator_set_type::features_type>::type accumulator_type;

                    typedef typename accumulator_type::hash_type hash_type;

                    // Having accumulator_set_type&& is an rvalue, NOT a universal reference.
                    // ref_hash_impl will NOT accept rvalues for safety reasons.
                    ref_hash_impl(accumulator_set_type &stream_hash)
                        : accumulator_set(stream_hash) {
                    }

                    accumulator_set_type &accumulator_set;
                };

                template<typename HashAccumulatorSet>
                struct value_hash_impl {
                    typedef HashAccumulatorSet accumulator_set_type;
                    typedef
                        typename boost::mpl::front<typename accumulator_set_type::features_type>::type accumulator_type;

                    typedef typename accumulator_type::hash_type hash_type;

                    // Having accumulator_set_type&& is an rvalue, NOT a universal reference.
                    value_hash_impl(accumulator_set_type &&stream_hash)
                        : accumulator_set(std::move(stream_hash)) {
                    }

                    value_hash_impl(accumulator_set_type &stream_hash)
                        : accumulator_set(stream_hash) {
                    }

                    mutable accumulator_set_type accumulator_set;
                };

                template<typename HashStateImpl>
                struct range_hash_impl : public HashStateImpl {
                    typedef HashStateImpl hash_state_impl_type;

                    typedef typename hash_state_impl_type::accumulator_type accumulator_type;
                    typedef typename hash_state_impl_type::accumulator_set_type accumulator_set_type;

                    typedef typename hash_state_impl_type::hash_type hash_type;

                    typedef typename boost::mpl::apply<accumulator_set_type, accumulator_type>::type::result_type
                        result_type;

                    template<typename SinglePassRange>
                    range_hash_impl(const SinglePassRange &range, accumulator_set_type &ise)
                            : HashStateImpl(ise) {
                        process(range);
                    }

                    // Having accumulator_set_type&& is an rvalue, NOT a universal reference.
                    template<typename SinglePassRange>
                    range_hash_impl(const SinglePassRange &range, accumulator_set_type &&ise)
                            : HashStateImpl(std::move(ise)) {
                        process(range);
                    }

                    template<typename SinglePassRange>
                    void process(const SinglePassRange &range) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                        process(range.begin(), range.end());
                    }

                    template<typename InputIterator>
                    range_hash_impl(InputIterator first, InputIterator last, accumulator_set_type &ise)
                            : HashStateImpl(ise) {
                        process(first, last);
                    }

                    // Having accumulator_set_type&& is an rvalue, NOT a universal reference.
                    template<typename InputIterator>
                    range_hash_impl(InputIterator first, InputIterator last, accumulator_set_type &&ise)
                            : HashStateImpl(std::move(ise)) {
                        process(first, last);
                    }

                    template<typename InputIterator>
                    void process(InputIterator first, InputIterator last) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        typedef typename std::iterator_traits<InputIterator>::value_type value_type;
                        if constexpr (hash_type::stream_processor == detail::stream_processor_type::Block) {
                            BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                            using StreamProcessor = typename nil::crypto3::hashes::block_stream_processor<
                                typename hash_type::policy_type,
                                accumulator_set_type,
                                std::numeric_limits<value_type>::digits + std::numeric_limits<value_type>::is_signed>;

                            StreamProcessor(this->accumulator_set)(first, last);
                        } else if constexpr (hash_type::stream_processor == detail::stream_processor_type::Raw) {
                            using StreamProcessor = typename nil::crypto3::hashes::raw_stream_processor<accumulator_set_type>;

                            StreamProcessor(this->accumulator_set)(first, last);
                        } else if constexpr (hash_type::stream_processor == detail::stream_processor_type::RawDelegating) {
                            using StreamProcessor = typename nil::crypto3::hashes::raw_delegating_stream_processor<accumulator_set_type>;

                            StreamProcessor(this->accumulator_set)(first, last);
                        }
                    }

                    template<typename T, std::size_t Size>
                    inline operator std::array<T, Size>() const {
                        result_type result =
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                        std::array<T, Size> out;
                        std::copy(result.begin(), result.end(), out.begin());
                        return out;
                    }

                    template<typename T, std::size_t Size>
                    inline operator boost::array<T, Size>() const {
                        result_type result =
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                        boost::array<T, Size> out;
                        std::copy(result.begin(), result.end(), out.begin());
                        return out;
                    }

                    template<typename OutputRange>
                    inline operator OutputRange() const {
                        result_type result =
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                        return OutputRange(result.begin(), result.end());
                    }

                    inline operator result_type() const {
                        return boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                    }

                    inline operator accumulator_set_type &() const {
                        return this->accumulator_set;
                    }

                    template<typename Integral,
                             typename = typename std::enable_if<std::is_integral<Integral>::value &&
                                                                hash_type::digest_bits <=
                                                                    std::numeric_limits<Integral>::digits>::type>
                    inline operator Integral() const {
                        std::array<Integral, 1> out;
                        result_type res = boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                        ::nil::crypto3::detail::pack_to<stream_endian::little_octet_big_bit>(res, out);
                        return out[0];
                    }

#ifndef CRYPTO3_RAW_HASH_STRING_OUTPUT

                    template<typename Char, typename CharTraits, typename Alloc>
                    inline operator std::basic_string<Char, CharTraits, Alloc>() const {
                        return std::to_string(
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set));
                    }
#endif
                };

                template<typename HashStateImpl, typename OutputIterator>
                struct itr_hash_impl {
                private:
                    mutable OutputIterator out;

                public:
                    typedef HashStateImpl hash_state_impl_type;

                    typedef typename hash_state_impl_type::accumulator_type accumulator_type;
                    typedef typename hash_state_impl_type::accumulator_set_type accumulator_set_type;

                    typedef typename hash_state_impl_type::hash_type hash_type;

                    typedef typename boost::mpl::apply<accumulator_set_type, accumulator_type>::type::result_type
                        result_type;

                    template<typename SinglePassRange>
                    itr_hash_impl(const SinglePassRange &range, OutputIterator out, accumulator_set_type &&ise) :
                        out(std::move(out)), range_hash_(range, std::move(ise)) {
                    }

                    template<typename InputIterator>
                    itr_hash_impl(InputIterator first, InputIterator last, OutputIterator out,
                                  accumulator_set_type &&ise) :
                        out(std::move(out)), range_hash_(first, last, std::move(ise)) {
                    }

                    inline operator accumulator_set_type &() const {
                        return range_hash_;
                    }

                    inline operator OutputIterator() const {
                        result_type result = range_hash_;
                        return std::move(result.cbegin(), result.cend(), out);
                    }

                private:
                    range_hash_impl<HashStateImpl> range_hash_;
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif
