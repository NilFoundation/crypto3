//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BN128_PP_HPP
#define ALGEBRA_CURVES_BN128_PP_HPP

#include <nil/algebra/curves/detail/bn128/bn128_g1.hpp>
#include <nil/algebra/curves/detail/bn128/bn128_g2.hpp>
#include <nil/algebra/curves/detail/bn128/bn128_gt.hpp>
#include <nil/algebra/curves/detail/bn128/bn128_init.hpp>
#include <nil/algebra/curves/detail/bn128/bn128_pairing.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                struct bn128_pp {
                    typedef bn128_Fr Fp_type;
                    typedef bn128_G1 G1_type;
                    typedef bn128_G2 G2_type;
                    typedef bn128_ate_G1_precomp G1_precomp_type;
                    typedef bn128_ate_G2_precomp G2_precomp_type;
                    typedef bn128_Fq Fq_type;
                    typedef bn128_Fq12 Fqk_type;
                    typedef bn128_GT GT_type;

                    static void init_public_params() {
                        init_bn128_params();
                    }

                    static bn128_GT final_exponentiation(const bn128_Fq12 &elt) {
                        return bn128_final_exponentiation(elt);
                    }

                    static bn128_Fq12 miller_loop(const bn128_ate_G1_precomp &prec_P, const bn128_ate_G2_precomp &prec_Q) {
                        
                        bn128_Fq12 result = bn128_ate_miller_loop(prec_P, prec_Q);
                        
                        return result;
                    }

                    static bn128_Fq12 double_miller_loop(const bn128_ate_G1_precomp &prec_P1,
                                                         const bn128_ate_G2_precomp &prec_Q1,
                                                         const bn128_ate_G1_precomp &prec_P2,
                                                         const bn128_ate_G2_precomp &prec_Q2) {
                        
                        bn128_Fq12 result = bn128_double_ate_miller_loop(prec_P1, prec_Q1, prec_P2, prec_Q2);
                        
                        return result;
                    }

                private:
                    static const bool has_affine_pairing = false;
                };
                
            }    // namespace detail
        }    // namespace curves
    }    // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_BN128_PP_HPP
