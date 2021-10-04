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

#ifndef CRYPTO3_ALGEBRA_PAIRING_MNT4_298_AFFINE_ATE_MILLER_LOOP_HPP
#define CRYPTO3_ALGEBRA_PAIRING_MNT4_298_AFFINE_ATE_MILLER_LOOP_HPP

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/detail/mnt4/298/params.hpp>
#include <nil/crypto3/algebra/pairing/detail/forms/short_weierstrass/projective/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<std::size_t Version = 298>
                class mnt4_affine_ate_miller_loop;

                template<>
                class mnt4_affine_ate_miller_loop<298> {
                    using curve_type = curves::mnt4<298>;

                    typedef detail::short_weierstrass_projective_types_policy<curve_type> policy_type;
                    using gt_type = typename curve_type::gt_type;

                public:
                    static typename gt_type::value_type
                        process(const typename policy_type::affine_ate_g1_precomputation &prec_P,
                                const typename policy_type::affine_ate_g2_precomputation &prec_Q) {

                        typename gt_type::value_type f = gt_type::value_type::one();

                        bool found_nonzero = false;
                        std::size_t idx = 0;

                        std::vector<long> NAF = multiprecision::find_wnaf(1, policy_type::ate_loop_count);

                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            /* code below gets executed for all bits (EXCEPT the MSB itself) of
                               param_p (skipping leading zeros) in MSB to LSB
                               order */
                            typename policy_type::affine_ate_coeffs c = prec_Q.coeffs[idx++];

                            typename gt_type::value_type g_RR_at_P = typename gt_type::value_type(
                                prec_P.PY_twist_squared, -prec_P.PX * c.gamma_twist + c.gamma_X - c.old_RY);
                            f = f.squared().mul_by_023(g_RR_at_P);

                            if (NAF[i] != 0) {
                                typename policy_type::affine_ate_coeffs c = prec_Q.coeffs[idx++];
                                typename gt_type::value_type g_RQ_at_P;
                                if (NAF[i] > 0) {
                                    g_RQ_at_P = typename gt_type::value_type(
                                        prec_P.PY_twist_squared, -prec_P.PX * c.gamma_twist + c.gamma_X - prec_Q.QY);
                                } else {
                                    g_RQ_at_P = typename gt_type::value_type(
                                        prec_P.PY_twist_squared, -prec_P.PX * c.gamma_twist + c.gamma_X + prec_Q.QY);
                                }
                                f = f.mul_by_023(g_RQ_at_P);
                            }
                        }

                        return f;
                    }
                };
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_MNT4_298_AFFINE_ATE_MILLER_LOOP_HPP
