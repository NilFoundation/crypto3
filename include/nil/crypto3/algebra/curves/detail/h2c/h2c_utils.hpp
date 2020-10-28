//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_UTILS_HPP
#define CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_UTILS_HPP

#include <cstdint>
#include <array>
#include <type_traits>
#include <iterator>
#include <algorithm>
#include <string>

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <boost/concept/assert.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/accumulators/hash.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    using namespace boost::multiprecision;
                    using namespace nil::crypto3::algebra::fields::detail;

                    template<typename InputType, typename OutputType>
                    constexpr inline void strxor(const InputType &in1, const InputType &in2, OutputType &out) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<InputType>));
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<OutputType>));
                        BOOST_CONCEPT_ASSERT((boost::WriteableRangeConcept<OutputType>));

                        BOOST_ASSERT(std::distance(in1.begin(), in1.end()) == std::distance(in2.begin(), in2.end()));
                        BOOST_ASSERT(std::distance(in1.begin(), in1.end()) == std::distance(out.begin(), out.end()));

                        auto in1_iter = in1.begin();
                        auto in2_iter = in2.begin();
                        auto out_iter = out.begin();

                        while (in1_iter != in1.end() && in2_iter != in2.end() && out_iter != out.end()) {
                            *out_iter++ = *in1_iter++ ^ *in2_iter++;
                        }
                    }

                    template<typename FieldParams>
                    inline bool sgn0(const element_fp<FieldParams> &e) {
                        using number_type = typename element_fp<FieldParams>::number_type;

                        static number_type two = number_type(2, element_fp<FieldParams>::modulus);

                        return static_cast<bool>(e.data % two);
                    }

                    template<typename FieldParams>
                    inline bool sgn0(const element_fp2<FieldParams> &e) {
                        using underlying_type = typename element_fp2<FieldParams>::underlying_type;
                        using number_type = typename underlying_type::number_type;

                        static number_type two = number_type(2, underlying_type::modulus);
                        static number_type zero = number_type(0, underlying_type::modulus);

                        number_type sign_0 = e.data[0].data % two;
                        bool zero_0 = sign_0 == zero;
                        number_type sign_1 = e.data[1].data % two;
                        return static_cast<bool>(sign_0) || (zero_0 && static_cast<bool>(sign_1));
                    }

                    template<typename HashType,
                             /// HashType::digest_type is required to be uint8_t[]
                             typename = typename std::enable_if<
                                 std::is_same<std::uint8_t, typename HashType::digest_type::value_type>::value>::type>
                    struct DefaultDstCreator {
                        static_assert((HashType::digest_bits / 8) <= 255, "too long output size of hash function");

                        typedef std::vector<std::uint8_t> dst_type;

                        template<typename InputType,
                                 typename = typename std::enable_if<
                                     std::is_same<std::uint8_t, typename InputType::value_type>::value>::type>
                        inline dst_type get_dst(const InputType &suite_id) {
                            BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<InputType>));

                            std::string tag_str = "QUUX-V01-CS02-with-";
                            std::vector<std::uint8_t> tag(tag_str.begin(), tag_str.end());

                            std::vector<std::uint8_t> dst_raw;
                            dst_raw.insert(dst_raw.end(), tag.begin(), tag.end());
                            dst_raw.insert(dst_raw.end(), suite_id.begin(), suite_id.end());

                            std::vector<std::uint8_t> dst;
                            if (dst_raw.size() > 255) {
                                std::string large_dst_tag_str = "H2C-OVERSIZE-DST-";
                                std::vector<std::uint8_t> large_dst_tag(large_dst_tag_str.begin(), large_dst_tag_str.end());
                                dst_raw.insert(dst_raw.begin(), large_dst_tag.begin(), large_dst_tag.end());
                                typename HashType::digest_type hashed_dst = hash<HashType>(dst_raw);
                                std::copy(hashed_dst.begin(), hashed_dst.end(), dst.begin());
                                dst.insert(dst.end(), hashed_dst.begin(), hashed_dst.end());
                            }
                            else {
                                dst.insert(dst.end(), dst_raw.begin(), dst_raw.end());
                            }
                            return dst;
                        }
                    };

                    template<std::size_t k, typename HashType,
                             /// HashType::digest_type is required to be uint8_t[]
                             typename = typename std::enable_if<
                                 std::is_same<std::uint8_t, typename HashType::digest_type::value_type>::value>::type>
                    class expand_message_xmd {
                        // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-5.4.1
                        static_assert(HashType::block_bits % 8 == 0, "r_in_bytes is not a multiple of 8");
                        static_assert(HashType::digest_bits % 8 == 0, "b_in_bytes is not a multiple of 8");
                        static_assert(HashType::digest_bits >= 2 * k, "k-bit collision resistance is not fulfilled");

                        constexpr static std::size_t b_in_bytes = HashType::digest_bits / 8;
                        constexpr static std::size_t r_in_bytes = HashType::block_bits / 8;

                    public:
                        template<typename InputMsgType, typename InputDstType, typename OutputType,
                                 typename = typename std::enable_if<
                                     std::is_same<std::uint8_t, typename InputMsgType::value_type>::value &&
                                     std::is_same<std::uint8_t, typename InputDstType::value_type>::value &&
                                     std::is_same<std::uint8_t, typename OutputType::value_type>::value>::type>
                        static inline void process(std::size_t len_in_bytes, const InputMsgType &msg,
                                                   const InputDstType &dst, OutputType &uniform_bytes) {
                            BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<InputMsgType>));
                            BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<InputDstType>));
                            BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<OutputType>));
                            BOOST_CONCEPT_ASSERT((boost::WriteableRangeConcept<OutputType>));

                            // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-5.4.1
                            assert(len_in_bytes < 0x10000);
                            assert(std::distance(dst.begin(), dst.end()) <= 255);
                            assert(std::distance(uniform_bytes.begin(), uniform_bytes.end()) >= len_in_bytes);

                            static const std::array<std::uint8_t, r_in_bytes> Z_pad {0};
                            const std::array<std::uint8_t, 2> l_i_b_str = {
                                static_cast<std::uint8_t>(len_in_bytes >> 8u),
                                static_cast<std::uint8_t>(len_in_bytes % 0x100)};
                            const std::size_t ell = static_cast<std::size_t>(len_in_bytes / b_in_bytes) +
                                                    static_cast<std::size_t>(len_in_bytes % b_in_bytes != 0);

                            // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-5.4.1
                            assert(ell <= 255);

                            // TODO: use accumulators when they will be fixed
                            // accumulator_set<HashType> b0_acc;
                            // hash<HashType>(Z_pad, b0_acc);
                            // hash<HashType>(msg, b0_acc);
                            // hash<HashType>(l_i_b_str, b0_acc);
                            // hash<HashType>(std::array<std::uint8_t, 1> {0}, b0_acc);
                            // hash<HashType>(dst, b0_acc);
                            // hash<HashType>(std::array<std::uint8_t, 1> {static_cast<std::uint8_t>(dst.size())},
                            // b0_acc); typename HashType::digest_type b0 =
                            // accumulators::extract::hash<HashType>(b0_acc);
                            std::vector<std::uint8_t> msg_prime;
                            msg_prime.insert(msg_prime.end(), Z_pad.begin(), Z_pad.end());
                            msg_prime.insert(msg_prime.end(), msg.begin(), msg.end());
                            msg_prime.insert(msg_prime.end(), l_i_b_str.begin(), l_i_b_str.end());
                            msg_prime.insert(msg_prime.end(), static_cast<std::uint8_t>(0));
                            msg_prime.insert(msg_prime.end(), dst.begin(), dst.end());
                            msg_prime.insert(msg_prime.end(),
                                             static_cast<std::uint8_t>(std::distance(dst.begin(), dst.end())));
                            typename HashType::digest_type b0 = hash<HashType>(msg_prime);

                            // TODO: use accumulators when they will be fixed
                            // accumulator_set<HashType> bi_acc;
                            // hash<HashType>(b0, bi_acc);
                            // hash<HashType>(std::array<std::uint8_t, 1> {1}, bi_acc);
                            // hash<HashType>(dst, bi_acc);
                            // hash<HashType>(std::array<std::uint8_t, 1> {static_cast<std::uint8_t>(dst.size())},
                            // bi_acc); typename HashType::digest_type bi =
                            // accumulators::extract::hash<HashType>(bi_acc); std::copy(bi.begin(), bi.end(),
                            // uniform_bytes.begin());
                            std::vector<std::uint8_t> b_i_str;
                            b_i_str.insert(b_i_str.end(), b0.begin(), b0.end());
                            b_i_str.insert(b_i_str.end(), static_cast<std::uint8_t>(1));
                            b_i_str.insert(b_i_str.end(), dst.begin(), dst.end());
                            b_i_str.insert(b_i_str.end(),
                                           static_cast<std::uint8_t>(std::distance(dst.begin(), dst.end())));
                            typename HashType::digest_type bi = hash<HashType>(b_i_str);
                            std::copy(bi.begin(), bi.end(), uniform_bytes.begin());

                            typename HashType::digest_type xored_b;
                            for (std::size_t i = 2; i <= ell; i++) {
                                // TODO: use accumulators when they will be fixed
                                // accumulator_set<HashType> bi_acc;
                                // strxor(b0, bi, xored_b);
                                // hash<HashType>(xored_b, bi_acc);
                                // hash<HashType>(std::array<std::uint8_t, 1> {static_cast<std::uint8_t>(i)}, bi_acc);
                                // hash<HashType>(dst, bi_acc);
                                // hash<HashType>(std::array<std::uint8_t, 1> {static_cast<std::uint8_t>(dst.size())},
                                //                bi_acc);
                                // bi = accumulators::extract::hash<HashType>(bi_acc);
                                // std::copy(bi.begin(), bi.end(), uniform_bytes.begin() + (i - 1) * b_in_bytes);
                                strxor(b0, bi, xored_b);
                                std::vector<std::uint8_t> b_i_str;
                                b_i_str.insert(b_i_str.end(), xored_b.begin(), xored_b.end());
                                b_i_str.insert(b_i_str.end(), static_cast<std::uint8_t>(i));
                                b_i_str.insert(b_i_str.end(), dst.begin(), dst.end());
                                b_i_str.insert(b_i_str.end(),
                                               static_cast<std::uint8_t>(std::distance(dst.begin(), dst.end())));
                                bi = hash<HashType>(b_i_str);
                                std::copy(bi.begin(), bi.end(), uniform_bytes.begin() + (i - 1) * b_in_bytes);
                            }
                        }
                    };

                    template<typename FieldValueType, typename GroupValueType>
                    struct m2c_simple_swu {
                        static inline GroupValueType process(const FieldValueType &u, const FieldValueType &A,
                                                             const FieldValueType &B, const FieldValueType &Z) {
                            // TODO: We assume that Z meets the following criteria -- correct for predefined suites,
                            //  but wrong in general case
                            // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-6.6.2
                            // Preconditions:
                            // 1.  Z is non-square in F,
                            // 2.  Z != -1 in F,
                            // 3.  the polynomial g(x) - Z is irreducible over F, and
                            // 4.  g(B / (Z * A)) is square in F.
                            static FieldValueType one = FieldValueType::one();

                            FieldValueType tv1 = (Z.pow(2) * u.pow(4) + Z * u.pow(2)).inversed();
                            FieldValueType x1 = (-B / A) * (one + tv1);
                            if (tv1.is_zero()) {
                                x1 = B / (Z * A);
                            }
                            FieldValueType gx1 = x1.pow(3) + A * x1 + B;
                            FieldValueType x2 = Z * u.pow(2) * x1;
                            FieldValueType gx2 = x2.pow(3) + A * x2 + B;
                            FieldValueType x, y;
                            if (gx1.is_square()) {
                                x = x1;
                                y = gx1.sqrt();
                            } else {
                                x = x2;
                                y = gx2.sqrt();
                            }
                            if (sgn0(u) != sgn0(y)) {
                                y = -y;
                            }
                            return GroupValueType(x, y, 1);
                        }
                    };

                    template<typename IsoMap, typename FieldValueType, typename GroupValueType>
                    struct m2c_simple_swu_zeroAB {
                        static inline GroupValueType process(const FieldValueType &u, const FieldValueType &Ai,
                                                             const FieldValueType &Bi, const FieldValueType &Z) {
                            GroupValueType ci = m2c_simple_swu<FieldValueType, GroupValueType>::process(u, Ai, Bi, Z);
                            return IsoMap::process(ci);
                        }
                    };
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_UTILS_HPP
