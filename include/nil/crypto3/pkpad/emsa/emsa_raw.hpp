//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PK_PAD_EMSA_RAW_HPP
#define CRYPTO3_PK_PAD_EMSA_RAW_HPP

#include <type_traits>
#include <vector>
#include <algorithm>

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/optional.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                namespace detail {
                    template<typename ValueType, typename = void>
                    struct emsa_raw_encoding_policy;

                    template<typename ValueType, typename = void>
                    struct emsa_raw_verification_policy;

                    template<typename ValueType>
                    struct emsa_raw_encoding_policy<ValueType,
                                                    typename std::enable_if<std::is_integral<ValueType>::value>::type> {
                        typedef std::vector<ValueType> internal_accumulator_type;
                        typedef internal_accumulator_type result_type;

                        static inline void init_accumulator(internal_accumulator_type &acc) {
                        }

                        // TODO: pack data from input::value_type to accumulator::value_type
                        template<typename InputRange>
                        static inline typename std::enable_if<std::is_same<
                            ValueType,
                            typename std::iterator_traits<typename InputRange::iterator>::value_type>::value>::type
                            update(internal_accumulator_type &acc, const InputRange &range) {
                            std::copy(std::cbegin(range), std::cend(range), std::back_inserter(acc));
                        }

                        // TODO: pack data from input::value_type to accumulator::value_type
                        template<typename InputIterator>
                        static inline typename std::enable_if<std::is_same<
                            ValueType, typename std::iterator_traits<InputIterator>::value_type>::value>::type
                            update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                            std::copy(first, last, std::back_inserter(acc));
                        }

                        static inline result_type process(internal_accumulator_type &acc) {
                            return acc;
                        }
                    };

                    template<typename ValueType>
                    struct emsa_raw_verification_policy<
                        ValueType, typename std::enable_if<std::is_integral<ValueType>::value>::type> {
                    protected:
                        typedef emsa_raw_encoding_policy<ValueType> encoding_policy;

                    public:
                        typedef typename encoding_policy::internal_accumulator_type internal_accumulator_type;
                        typedef bool result_type;

                        static inline void init_accumulator(internal_accumulator_type &acc) {
                            encoding_policy::init_accumulator(acc);
                        }

                        template<typename InputRange>
                        static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                            encoding_policy::update(range, acc);
                        }

                        template<typename InputIterator>
                        static inline void update(internal_accumulator_type &acc, InputIterator first,
                                                  InputIterator last) {
                            encoding_policy::update(first, last, acc);
                        }

                        // TODO: pack data from input::value_type to accumulator::value_type
                        template<typename InputRange>
                        static inline typename std::enable_if<
                            std::is_same<ValueType, typename std::iterator_traits<
                                                        typename InputRange::iterator>::value_type>::value,
                            result_type>::type
                            process(internal_accumulator_type &acc, const InputRange &msg_repr) {
                            return std::equal(std::cbegin(acc), std::cend(acc), std::cbegin(msg_repr),
                                              std::cend(msg_repr));
                        }
                    };
                }    // namespace detail

                /*!
                 * @brief EMSA raw.
                 * Essentially, accumulate input data in the container with elements of ValueType and return it
                 * unchanged.
                 *
                 * @tparam ValueType
                 */
                template<typename ValueType>
                struct emsa_raw {
                    typedef ValueType value_type;

                    typedef detail::emsa_raw_encoding_policy<ValueType> encoding_policy;
                    typedef detail::emsa_raw_verification_policy<ValueType> verification_policy;
                };
            }    // namespace padding
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif
