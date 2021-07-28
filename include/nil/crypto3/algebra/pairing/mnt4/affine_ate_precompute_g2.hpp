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

#ifndef CRYPTO3_ALGEBRA_PAIRING_MNT4_298_AFFINE_ATE_PRECOMPUTE_G2_HPP
#define CRYPTO3_ALGEBRA_PAIRING_MNT4_298_AFFINE_ATE_PRECOMPUTE_G2_HPP

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/detail/mnt4/298/params.hpp>
#include <nil/crypto3/algebra/pairing/detail/mnt4/298/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<std::size_t Version = 298>
                class mnt4_affine_ate_precompute_g2;

                template<>
                class mnt4_affine_ate_precompute_g2<298> {
                    using curve_type = curves::mnt4<298>;

                    using params_type = detail::params_type<curve_type>;
                    using types_policy = detail::types_policy<curve_type>;

                    using base_field_type = typename curve_type::base_field_type;
                    using g2_type = typename curve_type::g2_type;
                    using g2_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;

                    using g2_field_type_value = typename g2_type::field_type::value_type;

                public:

                    using g2_precomputed_type = typename types_policy::affine_ate_g2_precomputation;

                    static g2_precomputed_type process(const typename g2_type::value_type &Q) {

                        typename g2_affine_type::value_type Qcopy = Q.to_affine();

                        g2_precomputed_type result;
                        result.QX = Qcopy.X;
                        result.QY = Qcopy.Y;

                        g2_field_type_value RX = Qcopy.X;
                        g2_field_type_value RY = Qcopy.Y;
                        bool found_nonzero = false;

                        std::vector<long> NAF = multiprecision::find_wnaf(1, policy_type::ate_loop_count);

                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            typename types_policy::affine_ate_coeffs c;
                            c.old_RX = RX;
                            c.old_RY = RY;
                            g2_field_type_value old_RX_2 = c.old_RX.squared();
                            c.gamma = (old_RX_2 + old_RX_2 + old_RX_2 + 
                                       g2_type::value_type::twist_coeff_a) *
                                      (c.old_RY + c.old_RY).inversed();
                            c.gamma_twist = c.gamma * g2_type::value_type::twist;

                            c.gamma_X = c.gamma * c.old_RX;
                            result.coeffs.push_back(c);

                            RX = c.gamma.squared() - (c.old_RX + c.old_RX);
                            RY = c.gamma * (c.old_RX - RX) - c.old_RY;

                            if (NAF[i] != 0) {
                                typename types_policy::affine_ate_coeffs c;
                                c.old_RX = RX;
                                c.old_RY = RY;
                                if (NAF[i] > 0) {
                                    c.gamma = (c.old_RY - result.QY) * (c.old_RX - result.QX).inversed();
                                } else {
                                    c.gamma = (c.old_RY + result.QY) * (c.old_RX - result.QX).inversed();
                                }
                                c.gamma_twist = c.gamma * g2_type::value_type::twist;

                                c.gamma_X = c.gamma * result.QX;
                                result.coeffs.push_back(c);

                                RX = c.gamma.squared() - (c.old_RX + result.QX);
                                RY = c.gamma * (c.old_RX - RX) - c.old_RY;
                            }
                        }

                        return result;
                    }
                };
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_MNT4_298_AFFINE_ATE_PRECOMPUTE_G2_HPP
