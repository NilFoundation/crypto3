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

#ifndef CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_TATE_PRECOMPUTE_G2_HPP
#define CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_TATE_PRECOMPUTE_G2_HPP

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

                    using g2_type = typename curve_type::template g2_type<>;
                    using g2_affine_type = typename curve_type::template g2_type<curves::coordinates::affine>;

                public:
                    using g2_precomputed_type = typename policy_type::tate_g2_precomp;

                    static typename policy_type::tate_g2_precomp process(const typename g2_type::value_type &P) {

                        typename g2_affine_type::value_type Qcopy = Q.to_affine();
                        typename policy_type::tate_g2_precomp result;
                        result.y0 = Qcopy.Y * Qcopy.Z.inversed();
                        result.eta = (Qcopy.Z + Qcopy.Y) * gt::mul_by_non_residue(Qcopy.X).inversed();

                        return result;
                    }
                };
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_TATE_PRECOMPUTE_G2_HPP
