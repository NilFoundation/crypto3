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

#ifndef CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_TYPES_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_TYPES_POLICY_HPP

#include <nil/crypto3/algebra/curves/edwards.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<typename CurveType>
                    class types_policy;

                    // Copy of the bls12<381> version
                    template<>
                    class types_policy<curves::edwards<183>> {
                        using curve_type = curves::edwards<183>;

                    public:
                        using integral_type = typename curve_type::base_field_type::integral_type;
                        using extended_integral_type = typename curve_type::base_field_type::extended_integral_type;

                        using g1_field_value_type = typename curve_type::base_field_type::value_type;
                        using g2_field_value_type = typename curve_type::template g2_type<>::field_type::value_type;

                        struct Fq_conic_coefficients {

                            g1_field_value_type c_ZZ;
                            g1_field_value_type c_XY;
                            g1_field_value_type c_XZ;

                            bool operator==(const Fq_conic_coefficients &other) const {
                                return (this->c_ZZ == other.c_ZZ && this->c_XY == other.c_XY &&
                                        this->c_XZ == other.c_XZ);
                            }
                        };

                        struct Fq3_conic_coefficients {
                            g2_field_value_type c_ZZ;
                            g2_field_value_type c_XY;
                            g2_field_value_type c_XZ;

                            bool operator==(const Fq3_conic_coefficients &other) const {
                                return (this->c_ZZ == other.c_ZZ && this->c_XY == other.c_XY &&
                                        this->c_XZ == other.c_XZ);
                            }
                        };

                        using tate_g1_precomp = std::vector<Fq_conic_coefficients>;
                        using ate_g2_precomputed_type = std::vector<Fq3_conic_coefficients>;

                        struct ate_g1_precomputed_type {
                            g1_field_value_type P_XY;
                            g1_field_value_type P_XZ;
                            g1_field_value_type P_ZZplusYZ;

                            bool operator==(const ate_g1_precomputed_type &other) const {
                                return (this->P_XY == other.P_XY && this->P_XZ == other.P_XZ &&
                                        this->P_ZZplusYZ == other.P_ZZplusYZ);
                            }
                        };

                        struct tate_g2_precomp {
                            g2_field_value_type y0, eta;

                            bool operator==(const tate_g2_precomp &other) const {
                                return (this->y0 == other.y0 && this->eta == other.eta);
                            }
                        };

                        using g1_precomputed_type = ate_g1_precomputed_type;
                        using g2_precomputed_type = ate_g2_precomputed_type;
                    };

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_TYPES_POLICY_HPP
