//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_BN128_PAIRING_HPP
#define ALGEBRA_FF_BN128_PAIRING_HPP

#include <sstream>

#include <nil/algebra/curves/detail/bn128/bn128_g1.hpp>
#include <nil/algebra/curves/detail/bn128/bn128_g2.hpp>
#include <nil/algebra/curves/detail/bn128/bn128_gt.hpp>
#include <nil/algebra/curves/detail/bn128/bn128_init.hpp>

namespace nil {
    namespace algebra {

        struct bn128_ate_G1_precomp {
            bn::Fp P[3];

            bool operator==(const bn128_ate_G1_precomp &other) const {
                return (P[0] == other.P[0] && P[1] == other.P[1] && P[2] == other.P[2]);
            }
        };

        typedef bn::Fp6 bn128_ate_ell_coeffs;

        struct bn128_ate_G2_precomp {
            bn::Fp2 Q[3];
            std::vector<bn128_ate_ell_coeffs> coeffs;

            bool operator==(const bn128_ate_G2_precomp &other) const {
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

        bn128_ate_G1_precomp bn128_ate_precompute_G1(const bn128_G1 &P) {
            enter_block("Call to bn128_ate_precompute_G1");

            bn128_ate_G1_precomp result;
            bn::ecop::NormalizeJac(result.P, P.coord);

            leave_block("Call to bn128_ate_precompute_G1");
            return result;
        }
        bn128_ate_G2_precomp bn128_ate_precompute_G2(const bn128_G2 &Q) {
            enter_block("Call to bn128_ate_precompute_G2");

            bn128_ate_G2_precomp result;
            bn::components::precomputeG2(result.coeffs, result.Q, Q.coord);

            leave_block("Call to bn128_ate_precompute_G2");
            return result;
        }

        bn128_Fq12 bn128_double_ate_miller_loop(const bn128_ate_G1_precomp &prec_P1,
                                                const bn128_ate_G2_precomp &prec_Q1,
                                                const bn128_ate_G1_precomp &prec_P2,
                                                const bn128_ate_G2_precomp &prec_Q2) {
            bn128_Fq12 f;
            bn::components::millerLoop2(f.elem, prec_Q1.coeffs, prec_P1.P, prec_Q2.coeffs, prec_P2.P);
            return f;
        }

        bn128_Fq12 bn128_ate_miller_loop(const bn128_ate_G1_precomp &prec_P, const bn128_ate_G2_precomp &prec_Q) {
            bn128_Fq12 f;
            bn::components::millerLoop(f.elem, prec_Q.coeffs, prec_P.P);
            return f;
        }

        bn128_GT bn128_final_exponentiation(const bn128_Fq12 &elt) {
            enter_block("Call to bn128_final_exponentiation");
            bn128_GT eltcopy = elt;
            eltcopy.elem.final_exp();
            leave_block("Call to bn128_final_exponentiation");
            return eltcopy;
        }

    }    // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_FF_BN128_PAIRING_HPP
