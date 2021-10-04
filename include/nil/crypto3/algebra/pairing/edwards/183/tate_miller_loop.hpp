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

#ifndef CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_TATE_MILLER_LOOP_HPP
#define CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_TATE_MILLER_LOOP_HPP

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/pairing/detail/edwards/183/params.hpp>
#include <nil/crypto3/algebra/pairing/detail/edwards/183/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<std::size_t Version = 183>
                class edwards_tate_miller_loop;

                template<>
                class edwards_tate_miller_loop<183> {
                    using curve_type = curves::edwards<183>;

                    using params_type = detail::pairing_params<curve_type>;
                    typedef detail::types_policy<curve_type> policy_type;
                    using gt_type = typename curve_type::gt_type;

                public:
                    static typename gt_type::value_type process(const policy_type::tate_g1_precomp &prec_P,
                                                                const policy_type::tate_g2_precomp &prec_Q) {

                        typename gt_type::value_type f = gt_type::value_type::one();

                        bool found_one = false;
                        std::size_t idx = 0;
                        for (long i = policy_type::scalar_field_bits - 1; i >= 0; --i) {
                            const bool bit =
                                nil::crypto3::multiprecision::bit_test(policy_type::scalar_field_modulus, i);
                            if (!found_one) {
                                /* this skips the MSB itself */
                                found_one |= bit;
                                continue;
                            }

                            /* code below gets executed for all bits (EXCEPT the MSB itself) of
                               policy_type::scalar_field_modulus (skipping leading zeros) in MSB to LSB
                               order */
                            typename policy_type::Fq_conic_coefficients cc = prec_P[idx++];
                            typename gt_type::value_type g_RR_at_Q = typename gt_type::value_type(
                                Fq3(cc.c_XZ, Fq(0l), Fq(0l)) + cc.c_XY * prec_Q.y0, cc.c_ZZ * prec_Q.eta);
                            f = f.squared() * g_RR_at_Q;
                            if (bit) {
                                cc = prec_P[idx++];

                                typename gt_type::value_type g_RP_at_Q = typename gt_type::value_type(
                                    Fq3(cc.c_XZ, Fq(0l), Fq(0l)) + cc.c_XY * prec_Q.y0, cc.c_ZZ * prec_Q.eta);
                                f = f * g_RP_at_Q;
                            }
                        }

                        return f;
                    }
                };
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_TATE_MILLER_LOOP_HPP
