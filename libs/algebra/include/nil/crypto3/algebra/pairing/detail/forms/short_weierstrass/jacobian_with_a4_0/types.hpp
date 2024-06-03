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

#ifndef CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_TYPES_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_TYPES_POLICY_HPP

#include <vector>
#include <iostream>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<typename CurveType>
                    class pairing_params;

                    template<typename CurveType>
                    class short_weierstrass_jacobian_with_a4_0_types_policy {
                        using curve_type = CurveType;

                    public:
                        using integral_type = typename curve_type::base_field_type::integral_type;
                        using extended_integral_type = typename curve_type::base_field_type::extended_integral_type;

                        using g1_field_value_type = typename curve_type::base_field_type::value_type;
                        using g2_field_value_type = typename curve_type::template g2_type<>::field_type::value_type;

                        struct ate_g1_precomputed_type {

                            g1_field_value_type PX;
                            g1_field_value_type PY;

                            bool operator==(const ate_g1_precomputed_type &other) const {
                                return (this->PX == other.PX && this->PY == other.PY);
                            }
                        };

                        struct ate_ell_coeffs {

                            g2_field_value_type ell_0;
                            g2_field_value_type ell_VW;
                            g2_field_value_type ell_VV;

                            bool operator==(const ate_ell_coeffs &other) const {
                                return (this->ell_0 == other.ell_0 && this->ell_VW == other.ell_VW &&
                                        this->ell_VV == other.ell_VV);
                            }
                        };

                        struct ate_g2_precomputed_type {
                            using coeffs_type = ate_ell_coeffs;

                            bool is_zero;

                            g2_field_value_type QX;
                            g2_field_value_type QY;
                            std::vector<coeffs_type> coeffs;

                            bool operator==(const ate_g2_precomputed_type &other) const {
                                return (this->QX == other.QX && this->QY == other.QY && this->coeffs == other.coeffs);
                            }
                        };

                        typedef ate_g1_precomputed_type g1_precomputed_type;
                        typedef ate_g2_precomputed_type g2_precomputed_type;

                        friend std::ostream& operator<<(std::ostream& os, ate_g1_precomputed_type const& p)
                        {
                            os << "{" << std::endl
                                << "\"PX\":" << p.PX << "," << std::endl
                                << "\"PY\":" << p.PY << "}";
                            return os;
                        }

                        friend std::ostream& operator<<(std::ostream& os, ate_g2_precomputed_type const& p)
                        {
                            os << "{" << std::endl
                                << "\"QX\":" << p.QX << "," << std::endl
                                << "\"QY\":" << p.QY << "," << std::endl
                                << "\"coeffs\":[" << std::endl;
                            for(auto d = p.coeffs.begin(); d != p.coeffs.end(); ++d) {
                                os << "[" << d->ell_0 << "," << d->ell_VW << "," << d->ell_VV << "]";
                                if (d != p.coeffs.end()) {
                                    os << "," << std::endl;
                                }
                            }
                            os << "]" << std::endl;
                            os << "}";
                            return os;
                        }
                    };

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_TYPES_POLICY_HPP
