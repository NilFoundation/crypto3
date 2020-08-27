//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_EDWARDS_PAIRING_HPP
#define ALGEBRA_CURVES_EDWARDS_PAIRING_HPP

#include <sstream>

#include <nil/algebra/curves/detail/edwards/edwards_g1.hpp>
#include <nil/algebra/curves/detail/edwards/edwards_g2.hpp>
#include <nil/algebra/curves/detail/edwards/edwards_gt.hpp>
#include <nil/algebra/curves/detail/edwards/edwards_init.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                using fp_value_type = element_fp<ModulusBits, GeneratorBits>;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                using fp2_value_type = element_fp2<ModulusBits, GeneratorBits>;

                struct edwards_ate_g1_precomp {
                    fp_value_type P[3];

                    bool operator==(const edwards_ate_g1_precomp &other) const {
                        return (P[0] == other.P[0] && P[1] == other.P[1] && P[2] == other.P[2]);
                    }
                };

                typedef element_fp6_3over2 edwards_ate_ell_coeffs;

                struct edwards_ate_g2_precomp {
                    fp2_value_type Q[3];
                    std::vector<edwards_ate_ell_coeffs> coeffs;

                    bool operator==(const edwards_ate_g2_precomp &other) const {
                        if (!(Q[0] == other.Q[0] && Q[1] == other.Q[1] && Q[2] == other.Q[2] &&
                              coeffs.size() == other.coeffs.size())) {
                            return false;
                        }

                        /* work around for upstream serialization bug */
                        for (size_t i = 0; i < coeffs.size(); ++i) {
                            std::stringstream this_ss, other_ss;
                            this_ss << coeffs[i];
                            other_ss << other.coeffs[i];
                            if (this_ss.str() != other_ss.str()) {
                                return false;
                            }
                        }

                        return true;
                    }
                };

                edwards_ate_g1_precomp edwards_ate_precompute_g1(const edwards_g1 &P) {

                    edwards_ate_g1_precomp result;
                    nil::algebra::pairing::detail::NormalizeJac(result.P, P.coord);

                    return result;
                }
                edwards_ate_g2_precomp edwards_ate_precompute_g2(const edwards_g2 &Q) {

                    edwards_ate_g2_precomp result;
                    nil::algebra::pairing::precomputeg2(result.coeffs, result.Q, Q.coord);

                    return result;
                }

                edwards_Fq12 edwards_double_ate_miller_loop(const edwards_ate_g1_precomp &prec_P1,
                                                        const edwards_ate_g2_precomp &prec_Q1,
                                                        const edwards_ate_g1_precomp &prec_P2,
                                                        const edwards_ate_g2_precomp &prec_Q2) {
                    edwards_Fq12 f;

                    nil::algebra::pairing::millerLoop2(f.elem, prec_Q1.coeffs, prec_P1.P, prec_Q2.coeffs, prec_P2.P);
                    return f;
                }

                edwards_Fq12 edwards_ate_miller_loop(const edwards_ate_g1_precomp &prec_P,
                                                 const edwards_ate_g2_precomp &prec_Q) {
                    edwards_Fq12 f;
                    nil::algebra::pairing::millerLoop(f.elem, prec_Q.coeffs, prec_P.P);
                    return f;
                }

                edwards_gt edwards_final_exponentiation(const edwards_Fq12 &elt) {
                    edwards_gt eltcopy = elt;
                    eltcopy.elem.final_exp();
                    return eltcopy;
                }

                template <std::size_t ModulusBits, std::size_t GeneratorBits>
                static edwards_gt final_exponentiation<edwards<ModulusBits, GeneratorBits>>(const edwards_Fq12 &elt) {
                    return edwards_final_exponentiation(elt);
                }

                template <std::size_t ModulusBits, std::size_t GeneratorBits>
                static edwards_Fq12 miller_loop<edwards<ModulusBits, GeneratorBits>>(const edwards_ate_g1_precomp &prec_P,
                                              const edwards_ate_g2_precomp &prec_Q) {

                    edwards_Fq12 result = edwards_ate_miller_loop(prec_P, prec_Q);

                    return result;
                }

                template <std::size_t ModulusBits, std::size_t GeneratorBits>
                static edwards_Fq12 double_miller_loop<edwards<ModulusBits, GeneratorBits>>(const edwards_ate_g1_precomp &prec_P1,
                                                     const edwards_ate_g2_precomp &prec_Q1,
                                                     const edwards_ate_g1_precomp &prec_P2,
                                                     const edwards_ate_g2_precomp &prec_Q2) {

                    edwards_Fq12 result = edwards_double_ate_miller_loop(prec_P1, prec_Q1, prec_P2, prec_Q2);

                    return result;
                }
                
            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_EDWARDS_PAIRING_HPP
