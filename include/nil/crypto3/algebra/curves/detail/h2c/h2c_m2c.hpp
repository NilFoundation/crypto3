//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_MAP_TO_CURVE_HPP
#define CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_MAP_TO_CURVE_HPP

#include <nil/crypto3/algebra/curves/detail/h2c/h2c_suites.hpp>
#include <nil/crypto3/algebra/curves/detail/h2c/h2c_iso_map.hpp>
#include <nil/crypto3/algebra/curves/detail/h2c/h2c_sgn0.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    template<typename GroupType>
                    struct m2c_simple_swu {
                        typedef h2c_suite<GroupType> suite_type;

                        typedef typename suite_type::group_value_type group_value_type;
                        typedef typename suite_type::field_value_type field_value_type;

                        static inline group_value_type process(const field_value_type &u) {
                            // TODO: We assume that Z meets the following criteria -- correct for predefined suites,
                            //  but wrong in general case
                            // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-6.6.2
                            // Preconditions:
                            // 1.  Z is non-square in F,
                            // 2.  Z != -1 in F,
                            // 3.  the polynomial g(x) - Z is irreducible over F, and
                            // 4.  g(B / (Z * A)) is square in F.
                            static const field_value_type one = field_value_type::one();

                            field_value_type tv1 =
                                (suite_type::Z.pow(2) * u.pow(4) + suite_type::Z * u.pow(2)).inversed();
                            field_value_type x1 = (-suite_type::Bi / suite_type::Ai) * (one + tv1);
                            if (tv1.is_zero()) {
                                x1 = suite_type::Bi / (suite_type::Z * suite_type::Ai);
                            }
                            field_value_type gx1 = x1.pow(3) + suite_type::Ai * x1 + suite_type::Bi;
                            field_value_type x2 = suite_type::Z * u.pow(2) * x1;
                            field_value_type gx2 = x2.pow(3) + suite_type::Ai * x2 + suite_type::Bi;
                            field_value_type x, y;
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
                            return group_value_type(x, y, one);
                        }
                    };

                    template<typename GroupType>
                    struct m2c_simple_swu_zeroAB {
                        typedef h2c_suite<GroupType> suite_type;

                        typedef typename suite_type::group_value_type group_value_type;
                        typedef typename suite_type::field_value_type field_value_type;

                        static inline group_value_type process(const field_value_type &u) {
                            group_value_type ci = m2c_simple_swu<GroupType>::process(u);
                            return iso_map<GroupType>::process(ci);
                        }
                    };

                    template<typename GroupType>
                    struct map_to_curve;

                    template<>
                    struct map_to_curve<typename bls12_381::g1_type>
                        : m2c_simple_swu_zeroAB<typename bls12_381::g1_type> { };

                    template<>
                    struct map_to_curve<typename bls12_381::g2_type>
                        : m2c_simple_swu_zeroAB<typename bls12_381::g2_type> { };
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_MAP_TO_CURVE_HPP
