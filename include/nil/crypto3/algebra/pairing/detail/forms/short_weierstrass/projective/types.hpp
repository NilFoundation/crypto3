//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_PROJECTIVE_TYPES_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_PROJECTIVE_TYPES_POLICY_HPP

#include <vector>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<typename CurveType>
                    class short_weierstrass_projective_types_policy {
                        using curve_type = CurveType;

                    public:
                        using integral_type = typename curve_type::base_field_type::integral_type;
                        using extended_integral_type = typename curve_type::base_field_type::extended_integral_type;

                        using g1_field_value_type = typename curve_type::base_field_type::value_type;
                        using g2_field_value_type = typename curve_type::template g2_type<>::field_type::value_type;

                        struct affine_ate_g1_precomputation {
                            g1_field_value_type PX;
                            g1_field_value_type PY;
                            g2_field_value_type PY_twist_squared;
                        };

                        struct affine_ate_coeffs {
                            // TODO: trim (not all of them are needed)
                            g2_field_value_type old_RX;
                            g2_field_value_type old_RY;
                            g2_field_value_type gamma;
                            g2_field_value_type gamma_twist;
                            g2_field_value_type gamma_X;
                        };

                        struct affine_ate_g2_precomputation {
                            g2_field_value_type QX;
                            g2_field_value_type QY;
                            std::vector<affine_ate_coeffs> coeffs;
                        };

                        /* ate pairing */

                        struct ate_g1_precomputed_type {

                            g1_field_value_type PX;
                            g1_field_value_type PY;
                            g2_field_value_type PX_twist;
                            g2_field_value_type PY_twist;

                            bool operator==(const ate_g1_precomputed_type &other) const {
                                return (this->PX == other.PX && this->PY == other.PY &&
                                        this->PX_twist == other.PX_twist && this->PY_twist == other.PY_twist);
                            }
                        };

                        typedef ate_g1_precomputed_type g1_precomputed_type;

                        struct ate_dbl_coeffs {

                            g2_field_value_type c_H;
                            g2_field_value_type c_4C;
                            g2_field_value_type c_J;
                            g2_field_value_type c_L;

                            bool operator==(const ate_dbl_coeffs &other) const {
                                return (this->c_H == other.c_H && this->c_4C == other.c_4C && this->c_J == other.c_J &&
                                        this->c_L == other.c_L);
                            }
                        };

                        struct ate_add_coeffs {

                            g2_field_value_type c_L1;
                            g2_field_value_type c_RZ;

                            bool operator==(const ate_add_coeffs &other) const {
                                return (this->c_L1 == other.c_L1 && this->c_RZ == other.c_RZ);
                            }
                        };

                        struct ate_g2_precomputed_type {
                            typedef ate_dbl_coeffs dbl_coeffs_type;
                            typedef ate_add_coeffs add_coeffs_type;

                            g2_field_value_type QX;
                            g2_field_value_type QY;
                            g2_field_value_type QY2;
                            g2_field_value_type QX_over_twist;
                            g2_field_value_type QY_over_twist;
                            std::vector<dbl_coeffs_type> dbl_coeffs;
                            std::vector<add_coeffs_type> add_coeffs;

                            bool operator==(const ate_g2_precomputed_type &other) const {
                                return (this->QX == other.QX && this->QY == other.QY && this->QY2 == other.QY2 &&
                                        this->QX_over_twist == other.QX_over_twist &&
                                        this->QY_over_twist == other.QY_over_twist &&
                                        this->dbl_coeffs == other.dbl_coeffs && this->add_coeffs == other.add_coeffs);
                            }
                        };

                        typedef ate_g2_precomputed_type g2_precomputed_type;
                    };

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_PROJECTIVE_TYPES_POLICY_HPP
