//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLOCK_CIPHER_VALUE_HPP
#define CRYPTO3_BLOCK_CIPHER_VALUE_HPP

//#include <type_traits>
//#include <iterator>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

#include <nil/crypto3/block/accumulators/block.hpp>
#include <nil/crypto3/block/cipher_state.hpp>

#include <nil/crypto3/detail/digest.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<typename CipherAccumulator>
                struct ref_cipher_impl {
                    typedef CipherAccumulator accumulator_set_type;
                    typedef
                        typename boost::mpl::front<typename accumulator_set_type::features_type>::type accumulator_type;

                    typedef typename accumulator_type::mode_type mode_type;
                    typedef typename mode_type::cipher_type cipher_type;

                    ref_cipher_impl(const accumulator_set_type &acc) : accumulator_set(acc) {
                    }

                    accumulator_set_type &accumulator_set;
                };

                template<typename CipherAccumulator>
                struct value_cipher_impl {
                    typedef CipherAccumulator accumulator_set_type;
                    typedef
                        typename boost::mpl::front<typename accumulator_set_type::features_type>::type accumulator_type;

                    typedef typename accumulator_type::mode_type mode_type;
                    typedef typename mode_type::cipher_type cipher_type;

                    value_cipher_impl(const accumulator_set_type &acc) : accumulator_set(acc) {
                    }

                    mutable accumulator_set_type accumulator_set;
                };

                template<typename CipherStateImpl>
                struct range_cipher_impl : public CipherStateImpl {
                    typedef CipherStateImpl cipher_state_impl_type;

                    typedef typename cipher_state_impl_type::accumulator_type accumulator_type;
                    typedef typename cipher_state_impl_type::accumulator_set_type accumulator_set_type;

                    typedef typename cipher_state_impl_type::mode_type mode_type;
                    typedef typename cipher_state_impl_type::cipher_type cipher_type;

                    typedef typename boost::mpl::apply<accumulator_set_type, accumulator_type>::type::result_type
                        result_type;

                    template<typename SinglePassRange>
                    range_cipher_impl(const SinglePassRange &range, const accumulator_set_type &ise) :
                        CipherStateImpl(ise) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                        typedef
                            typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;
                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);
                        typedef typename cipher_type::template stream_processor<
                            mode_type, accumulator_set_type,
                            std::numeric_limits<value_type>::digits + std::numeric_limits<value_type>::is_signed>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(range.begin(), range.end());
                    }

                    template<typename InputIterator>
                    range_cipher_impl(InputIterator first, InputIterator last, const accumulator_set_type &ise) :
                        CipherStateImpl(ise) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        typedef typename std::iterator_traits<InputIterator>::value_type value_type;
                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);
                        typedef typename cipher_type::template stream_processor<
                            mode_type, accumulator_set_type,
                            std::numeric_limits<value_type>::digits + std::numeric_limits<value_type>::is_signed>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(first, last);
                    }

                    template<typename T, std::size_t Size>
                    inline operator std::array<T, Size>() const {
                        result_type result =
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                        std::array<T, Size> out;
                        std::copy(result.begin(), result.end(), out.end());
                        return out;
                    }

                    template<typename T, std::size_t Size>
                    inline operator boost::array<T, Size>() const {
                        result_type result =
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                        boost::array<T, Size> out;
                        std::copy(result.begin(), result.end(), out.end());
                        return out;
                    }

                    template<typename OutputRange>
                    operator OutputRange() const {
                        result_type result =
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                        return OutputRange(result.cbegin(), result.cend());
                    }

                    operator result_type() const {
                        return boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                    }

                    operator accumulator_set_type() const {
                        return this->accumulator_set;
                    }

#ifndef CRYPTO3_RAW_HASH_STRING_OUTPUT

                    template<typename Char, typename CharTraits, typename Alloc>
                    operator std::basic_string<Char, CharTraits, Alloc>() const {
                        return std::to_string(
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set));
                    }

#endif
                };

                template<typename CipherStateImpl, typename OutputIterator>
                struct itr_cipher_impl : public CipherStateImpl {
                private:
                    mutable OutputIterator out;

                public:
                    typedef CipherStateImpl cipher_state_impl_type;

                    typedef typename cipher_state_impl_type::accumulator_type accumulator_type;
                    typedef typename cipher_state_impl_type::accumulator_set_type accumulator_set_type;

                    typedef typename cipher_state_impl_type::mode_type mode_type;
                    typedef typename cipher_state_impl_type::cipher_type cipher_type;

                    typedef typename boost::mpl::apply<accumulator_set_type, accumulator_type>::type::result_type
                        result_type;

                    template<typename SinglePassRange>
                    itr_cipher_impl(const SinglePassRange &range, OutputIterator out, const accumulator_set_type &ise) :
                        CipherStateImpl(ise), out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                        typedef
                            typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;
                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);
                        typedef typename cipher_type::template stream_processor<
                            mode_type, accumulator_set_type,
                            std::numeric_limits<value_type>::digits + std::numeric_limits<value_type>::is_signed>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(range.begin(), range.end());
                    }

                    template<typename InputIterator>
                    itr_cipher_impl(InputIterator first, InputIterator last, OutputIterator out,
                                    const accumulator_set_type &ise) :
                        CipherStateImpl(ise),
                        out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        typedef typename std::iterator_traits<InputIterator>::value_type value_type;
                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);
                        typedef typename cipher_type::template stream_processor<
                            mode_type, accumulator_set_type,
                            std::numeric_limits<value_type>::digits + std::numeric_limits<value_type>::is_signed>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(first, last);
                    }

                    operator OutputIterator() const {
                        result_type result =
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);

                        return std::move(result.cbegin(), result.cend(), out);
                    }
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CODEC_POSTPROCESSOR_HPP
