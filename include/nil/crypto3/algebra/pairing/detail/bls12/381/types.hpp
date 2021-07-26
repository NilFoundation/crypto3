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

#ifndef CRYPTO3_ALGEBRA_PAIRING_BLS12_381_TYPES_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_BLS12_381_TYPES_POLICY_HPP

#include <nil/crypto3/algebra/curves/detail/bls12/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/bls12/g2.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<typename CurveType>
                    class types_policy;

                    template<>
                    class types_policy<curves::bls12<381>> {
                        using curve_type = curves::bls12<381>;

                    public:

                        using number_type = typename curve_type::base_field_type::modulus_type;
                        using extended_number_type = typename curve_type::base_field_type::extended_modulus_type;

                        struct ate_g1_precomp {
                            using value_type = typename curve_type::base_field_type::value_type;

                            value_type PX;
                            value_type PY;

                            bool operator==(const ate_g1_precomp &other) const {
                                return (this->PX == other.PX && this->PY == other.PY);
                            }
                        };

                        struct ate_ell_coeffs {
                            using value_type = 
                                typename curve_type::g2_type::field_type::value_type;

                            value_type ell_0;
                            value_type ell_VW;
                            value_type ell_VV;

                            bool operator==(const ate_ell_coeffs &other) const {
                                return (this->ell_0 == other.ell_0 && this->ell_VW == other.ell_VW &&
                                        this->ell_VV == other.ell_VV);
                            }
                        };

                        struct ate_g2_precomp {
                            using value_type = 
                                typename curve_type::g2_type::field_type::value_type;
                            using coeffs_type = ate_ell_coeffs;

                            value_type QX;
                            value_type QY;
                            std::vector<coeffs_type> coeffs;

                            bool operator==(const ate_g2_precomp &other) const {
                                return (this->QX == other.QX && this->QY == other.QY && this->coeffs == other.coeffs);
                            }
                        };

                        typedef ate_g1_precomp g1_precomp;
                        typedef ate_g2_precomp g2_precomp;
                    };

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_PAIRING_BLS12_381_TYPES_POLICY_HPP
