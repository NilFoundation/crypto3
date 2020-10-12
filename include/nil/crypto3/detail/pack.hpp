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

#ifndef CRYPTO3_DETAIL_PACK_HPP
#define CRYPTO3_DETAIL_PACK_HPP

#include <nil/crypto3/detail/type_traits.hpp>
#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/detail/exploder.hpp>
#include <nil/crypto3/detail/imploder.hpp>
#include <nil/crypto3/detail/predef.hpp>

#include <boost/assert.hpp>
#include <boost/static_assert.hpp>

#ifndef CRYPTO3_NO_OPTIMIZATION

#include <boost/endian.hpp>
#include <boost/utility/enable_if.hpp>

#endif

namespace nil {
    namespace crypto3 {
        namespace detail {
#ifndef CRYPTO3_NO_OPTIMIZATION

            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct host_can_memcpy {
                static bool const value = !(UnitBits % CHAR_BIT) && InputBits >= UnitBits && OutputBits >= UnitBits &&
                                          sizeof(InT) * CHAR_BIT == InputBits && sizeof(OutT) * CHAR_BIT == OutputBits;
            };

            template<typename Endianness, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy {
                static bool const value = InputBits == OutputBits && sizeof(InT) == sizeof(OutT);
            };

            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::host_unit<UnitBits>, InputBits, OutputBits, InT, OutT>
                : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> {};

#ifdef BOOST_ENDIAN_LITTLE_BYTE_AVAILABLE
            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::little_unit_big_bit<UnitBits>, InputBits, OutputBits, InT, OutT>
                : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> {};
            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::little_unit_little_bit<UnitBits>, InputBits, OutputBits, InT, OutT>
                : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> {};
#endif

#ifdef CRYPTO3_TARGET_CPU_IS_BIG_ENDIAN
            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::big_unit_big_bit<UnitBits>, InputBits, OutputBits, InT, OutT>
                : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> {};
            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::big_unit_little_bit<UnitBits>, InputBits, OutputBits, InT, OutT>
                : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> {};
#endif

#endif

            template<typename Endianness, int InputBits, int OutputBits, bool Explode = (InputBits > OutputBits),
                     bool Implode = (InputBits < OutputBits)>
            struct real_packer;

            template<typename Endianness, int Bits>
            struct real_packer<Endianness, Bits, Bits, false, false> {

                template<typename InIter, typename OutIter>
                static void pack_n(InIter in, size_t in_n, OutIter out) {
                    std::copy(in, in + in_n, out);
                }

                template<typename InIter, typename OutIter>
                static void pack(InIter in, InIter in_e, OutIter out) {
                    std::copy(in, in_e, out);
                }
            };

            template<typename Endianness, int InputBits, int OutputBits>
            struct real_packer<Endianness, InputBits, OutputBits, true, false> {

                BOOST_STATIC_ASSERT(InputBits % OutputBits == 0);

                template<typename InIter, typename OutIter>
                static void pack_n(InIter in, size_t in_n, OutIter out) {
                    while (in_n--) {
                        typedef typename std::iterator_traits<InIter>::value_type InValue;
                        InValue const value = *in++;
                        detail::exploder<Endianness, InputBits, OutputBits>::explode(value, out);
                    }
                }

                template<typename InIter, typename OutIter>
                static void pack(InIter in, InIter in_e, OutIter out) {
                    while (in != in_e) {
                        typedef typename std::iterator_traits<InIter>::value_type InValue;
                        InValue const value = *in++;
                        detail::exploder<Endianness, InputBits, OutputBits>::explode(value, out);
                    }
                }
            };

            template<typename Endianness, int InputBits, int OutputBits>
            struct real_packer<Endianness, InputBits, OutputBits, false, true> {

                BOOST_STATIC_ASSERT(OutputBits % InputBits == 0);

                template<typename InIter, typename OutIter>
                static void pack_n(InIter in, size_t in_n, OutIter out) {
                    size_t out_n = in_n / (OutputBits / InputBits);
                    while (out_n--) {
                        typedef typename detail::outvalue_helper<OutIter, OutputBits>::type OutValue;
                        OutValue value = OutValue();
                        detail::imploder<Endianness, InputBits, OutputBits>::implode(in, value);
                        *out++ = value;
                    }
                }

                template<typename InIter, typename OutIter>
                static void pack(InIter in, InIter in_e, OutIter out) {
                    while (in != in_e) {
                        typedef typename detail::outvalue_helper<OutIter, OutputBits>::type OutValue;
                        OutValue value = OutValue();
                        detail::imploder<Endianness, InputBits, OutputBits>::implode(in, value);
                        *out++ = value;
                    }
                }
            };

            template<typename Endianness, int InputBits, int OutputBits>
            struct packer : real_packer<Endianness, InputBits, OutputBits> {

#ifndef CRYPTO3_NO_OPTIMIZATION

                using real_packer<Endianness, InputBits, OutputBits>::pack_n;

                template<typename InT, typename OutT>
                static typename std::enable_if<can_memcpy<Endianness, InputBits, OutputBits, InT, OutT>::value>::type
                    pack_n(InT const *in, size_t n, OutT *out) {
                    std::memcpy(out, in, n * sizeof(InT));
                }

                template<typename InT, typename OutT>
                static typename std::enable_if<can_memcpy<Endianness, InputBits, OutputBits, InT, OutT>::value>::type
                    pack_n(InT *in, size_t n, OutT *out) {
                    std::memcpy(out, in, n * sizeof(InT));
                }

#endif
            };

            template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1,
                     typename InputIterator2>
            void pack_n(InputIterator1 in, size_t in_n, InputIterator2 out) {
                typedef packer<Endianness, InValueBits, OutValueBits> packer_type;
                packer_type::pack_n(in, in_n, out);
            }

            template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1,
                     typename InputIterator2>
            void pack_n(InputIterator1 in, size_t in_n, InputIterator2 out, size_t out_n) {
                BOOST_ASSERT(in_n * InValueBits == out_n * OutValueBits);
                pack_n<Endianness, InValueBits, OutValueBits>(in, in_n, out);
            }

            template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1,
                     typename InputIterator2>
            void pack(InputIterator1 b1, InputIterator1 e1, std::random_access_iterator_tag, InputIterator2 b2) {
                pack_n<Endianness, InValueBits, OutValueBits>(b1, e1 - b1, b2);
            }

            template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1, typename CatT1,
                     typename InputIterator2,
                     typename = typename std::enable_if<detail::is_iterator<InputIterator1>::value>::type,
                     typename = typename std::enable_if<detail::is_iterator<InputIterator2>::value>::type>
            void pack(InputIterator1 b1, InputIterator1 e1, CatT1, InputIterator2 b2) {
                typedef packer<Endianness, InValueBits, OutValueBits> packer_type;
                packer_type::pack(b1, e1, b2);
            }

            template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1,
                     typename InputIterator2,
                     typename = typename std::enable_if<detail::is_iterator<InputIterator2>::value>::type>
            void pack(InputIterator1 b1, InputIterator1 e1, InputIterator2 b2) {
                typedef typename std::iterator_traits<InputIterator1>::iterator_category cat1;
                pack<Endianness, InValueBits, OutValueBits>(b1, e1, cat1(), b2);
            }

            template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1,
                     typename InputIterator2>
            void pack(InputIterator1 b1, InputIterator1 e1, std::random_access_iterator_tag, InputIterator2 b2,
                      InputIterator2 e2, std::random_access_iterator_tag) {
                pack_n<Endianness, InValueBits, OutValueBits>(b1, e1 - b1, b2, e2 - b2);
            }

            template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1, typename CatT1,
                     typename InputIterator2, typename CatT2>
            void pack(InputIterator1 b1, InputIterator1 e1, CatT1, InputIterator2 b2, InputIterator2, CatT2) {
                pack<Endianness, InValueBits, OutValueBits>(b1, e1, b2);
            }

            template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1,
                     typename InputIterator2>
            void pack(InputIterator1 b1, InputIterator1 e1, InputIterator2 b2, InputIterator2 e2) {
                typedef typename std::iterator_traits<InputIterator1>::iterator_category cat1;
                typedef typename std::iterator_traits<InputIterator2>::iterator_category cat2;
                pack<Endianness, InValueBits, OutValueBits>(b1, e1, cat1(), b2, e2, cat2());
            }

            template<typename Endianness, int InValueBits, int OutValueBits, typename InputType, typename OutputType>
            void pack(const InputType &in, OutputType &out) {
                pack_n<Endianness, InValueBits, OutValueBits>(in.data(), in.size(), out.data(), out.size());
            }

            template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator,
                     typename OutputType,
                     typename = typename std::enable_if<!std::is_arithmetic<OutputType>::value>::type>
            inline void pack(InputIterator first, InputIterator last, OutputType &out) {
                pack_n<Endianness, InValueBits, OutValueBits>(first, std::distance(first, last), out.begin(),
                    out.size());
            }
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_PACK_HPP
