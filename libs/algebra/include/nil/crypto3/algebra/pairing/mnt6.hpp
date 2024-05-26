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

#ifndef CRYPTO3_ALGEBRA_PAIRING_MNT6_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_MNT6_POLICY_HPP

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/detail/mnt6/298/params.hpp>
#include <nil/crypto3/algebra/pairing/mnt6/298/ate_double_miller_loop.hpp>
#include <nil/crypto3/algebra/pairing/mnt6/298/ate_miller_loop.hpp>
#include <nil/crypto3/algebra/pairing/forms/short_weierstrass/projective/ate_precompute_g1.hpp>
#include <nil/crypto3/algebra/pairing/forms/short_weierstrass/projective/ate_precompute_g2.hpp>
#include <nil/crypto3/algebra/pairing/mnt6/298/final_exponentiation.hpp>
#include <nil/crypto3/algebra/pairing/pairing_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<>
                struct pairing_policy<curves::mnt6<298>> {
                    using curve_type = curves::mnt6<298>;

                    using chained_curve_type = curves::mnt4<298>;

                    using precompute_g1 = pairing::short_weierstrass_projective_ate_precompute_g1<curve_type>;
                    using precompute_g2 = pairing::short_weierstrass_projective_ate_precompute_g2<curve_type>;
                    using miller_loop = pairing::mnt6_ate_miller_loop<298>;
                    using double_miller_loop = pairing::mnt6_ate_double_miller_loop<298>;
                    using final_exponentiation = pairing::mnt6_final_exponentiation<298>;

                    using g1_precomputed_type = typename precompute_g1::g1_precomputed_type;
                    using g2_precomputed_type = typename precompute_g2::g2_precomputed_type;
                };

            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_MNT6_POLICY_HPP
