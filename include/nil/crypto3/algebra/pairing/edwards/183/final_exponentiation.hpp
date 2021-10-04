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

#ifndef CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_FINAL_EXPONENTIATION_HPP
#define CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_FINAL_EXPONENTIATION_HPP

#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/pairing/detail/edwards/183/params.hpp>
#include <nil/crypto3/algebra/pairing/detail/edwards/183/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<std::size_t Version = 183>
                class edwards_final_exponentiation;

                template<>
                class edwards_final_exponentiation<183> {
                    using curve_type = curves::edwards<183>;

                    using params_type = detail::pairing_params<curve_type>;
                    typedef detail::types_policy<curve_type> policy_type;

                    using base_field_type = typename curve_type::base_field_type;
                    using gt_type = typename curve_type::gt_type;

                    static typename gt_type::value_type
                        final_exponentiation_last_chunk(const typename gt_type::value_type &elt,
                                                        const typename gt_type::value_type &elt_inv) {

                        const typename gt_type::value_type elt_q = elt.Frobenius_map(1);

                        typename gt_type::value_type w1_part =
                            elt_q.cyclotomic_exp(params_type::final_exponent_last_chunk_w1);
                        typename gt_type::value_type w0_part = gt_type::value_type::zero();

                        if (params_type::final_exponent_last_chunk_is_w0_neg) {
                            w0_part = elt_inv.cyclotomic_exp(params_type::final_exponent_last_chunk_abs_of_w0);
                        } else {
                            w0_part = elt.cyclotomic_exp(params_type::final_exponent_last_chunk_abs_of_w0);
                        }

                        return w1_part * w0_part;
                    }

                    static typename gt_type::value_type
                        final_exponentiation_first_chunk(const typename gt_type::value_type &elt,
                                                         const typename gt_type::value_type &elt_inv) {

                        /* (q^3-1)*(q+1) */

                        /* elt_q3 = elt^(q^3) */
                        const typename gt_type::value_type elt_q3 = elt.Frobenius_map(3);
                        /* elt_q3_over_elt = elt^(q^3-1) */
                        const typename gt_type::value_type elt_q3_over_elt = elt_q3 * elt_inv;
                        /* alpha = elt^((q^3-1) * q) */
                        const typename gt_type::value_type alpha = elt_q3_over_elt.Frobenius_map(1);
                        /* beta = elt^((q^3-1)*(q+1) */
                        const typename gt_type::value_type beta = alpha * elt_q3_over_elt;

                        return beta;
                    }

                public:
                    static typename gt_type::value_type process(const typename gt_type::value_type &elt) {

                        const typename gt_type::value_type elt_inv = elt.inversed();
                        const typename gt_type::value_type elt_to_first_chunk =
                            final_exponentiation_first_chunk(elt, elt_inv);
                        const typename gt_type::value_type elt_inv_to_first_chunk =
                            final_exponentiation_first_chunk(elt_inv, elt);
                        return final_exponentiation_last_chunk(elt_to_first_chunk, elt_inv_to_first_chunk);
                    }
                };
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_FINAL_EXPONENTIATION_HPP
