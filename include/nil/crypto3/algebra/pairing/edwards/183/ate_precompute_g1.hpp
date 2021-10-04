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

#ifndef CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_ATE_PRECOMPUTE_G1_HPP
#define CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_ATE_PRECOMPUTE_G1_HPP

#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/pairing/detail/edwards/183/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<std::size_t Version = 183>
                class edwards_ate_precompute_g1;

                template<>
                class edwards_ate_precompute_g1<183> {
                    using curve_type = curves::edwards<183>;

                    typedef detail::types_policy<curve_type> policy_type;

                    using g1_type = typename curve_type::template g1_type<>;
                    using g1_affine_type = typename curve_type::template g1_type<curves::coordinates::affine>;

                public:
                    using g1_precomputed_type = typename policy_type::ate_g1_precomputed_type;

                    static typename policy_type::ate_g1_precomputed_type
                        process(const typename g1_type::value_type &P) {

                        typename g1_affine_type::value_type Pcopy = P.to_affine();
                        typename policy_type::ate_g1_precomputed_type result;
                        result.P_XY = Pcopy.X * Pcopy.Y;
                        result.P_XZ = Pcopy.X;    // P.X * P.Z but P.Z = 1
                        result.P_ZZplusYZ =
                            (g1_type::field_type::value_type::one() + Pcopy.Y);    // (P.Z + P.Y) * P.Z but P.Z =

                        return result;
                    }
                };
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_ATE_PRECOMPUTE_G1_HPP
