//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_BN128_INIT_HPP
#define ALGEBRA_FF_BN128_INIT_HPP

#include <nil/algebra/pairing/include/bn.h>

#include <nil/algebra/curves/detail/bn128/bn128_g1.hpp>
#include <nil/algebra/curves/detail/bn128/bn128_g2.hpp>
#include <nil/algebra/curves/detail/bn128/bn128_gt.hpp>

#include <nil/algebra/fields/fp.hpp>

#include <boost/multiprecision/modular/base_params.hpp>

namespace nil {
    namespace algebra {

        const mp_size_t bn128_r_bitcount = 254;
        const mp_size_t bn128_q_bitcount = 254;

        const mp_size_t bn128_r_limbs = (bn128_r_bitcount + GMP_NUMB_BITS - 1) / GMP_NUMB_BITS;
        const mp_size_t bn128_q_limbs = (bn128_q_bitcount + GMP_NUMB_BITS - 1) / GMP_NUMB_BITS;

        NumberType bn128_modulus_r;
        NumberType bn128_modulus_q;

        bn::Fp bn128_coeff_b;
        size_t bn128_Fq_s;
        bn::Fp bn128_Fq_nqr_to_t;
        mie::Vuint bn128_Fq_t_minus_1_over_2;

        bn::Fp2 bn128_twist_coeff_b;
        size_t bn128_Fq2_s;
        bn::Fp2 bn128_Fq2_nqr_to_t;
        mie::Vuint bn128_Fq2_t_minus_1_over_2;

        template<typename NumberType>
        void init_bn128_params() {

            /* additional parameters for square roots in Fq/Fq2 */
            bn128_coeff_b = bn::Fp(3);
            bn128_Fq_s = 1;
            bn128_Fq_nqr_to_t = bn::Fp("21888242871839275222246405745257275088696311157297823662689037894645226208582");
            bn128_Fq_t_minus_1_over_2 =
                mie::Vuint("5472060717959818805561601436314318772174077789324455915672259473661306552145");

            bn128_twist_coeff_b =
                bn::Fp2(bn::Fp("19485874751759354771024239261021720505790618469301721065564631296452457478373"),
                        bn::Fp("266929791119991161246907387137283842545076965332900288569378510910307636690"));
            bn128_Fq2_s = 4;
            bn128_Fq2_nqr_to_t =
                bn::Fp2(bn::Fp("5033503716262624267312492558379982687175200734934877598599011485707452665730"),
                        bn::Fp("314498342015008975724433667930697407966947188435857772134235984660852259084"));
            bn128_Fq2_t_minus_1_over_2 = mie::Vuint(
                "14971724250519463826312126413021210649976634891596900701138993820439690427699319920245032869357433"
                "49909963"
                "2259837909383182382988566862092145199781964621");

            /* choice of group G1 */
            bn128_G1::G1_zero.coord[0] = bn::Fp(1);
            bn128_G1::G1_zero.coord[1] = bn::Fp(1);
            bn128_G1::G1_zero.coord[2] = bn::Fp(0);

            bn128_G1::G1_one.coord[0] = bn::Fp(1);
            bn128_G1::G1_one.coord[1] = bn::Fp(2);
            bn128_G1::G1_one.coord[2] = bn::Fp(1);

            /* choice of group G2 */
            bn128_G2::G2_zero.coord[0] = bn::Fp2(bn::Fp(1), bn::Fp(0));
            bn128_G2::G2_zero.coord[1] = bn::Fp2(bn::Fp(1), bn::Fp(0));
            bn128_G2::G2_zero.coord[2] = bn::Fp2(bn::Fp(0), bn::Fp(0));

            bn128_G2::G2_one.coord[0] =
                bn::Fp2(bn::Fp("15267802884793550383558706039165621050290089775961208824303765753922461897946"),
                        bn::Fp("9034493566019742339402378670461897774509967669562610788113215988055021632533"));
            bn128_G2::G2_one.coord[1] =
                bn::Fp2(bn::Fp("644888581738283025171396578091639672120333224302184904896215738366765861164"),
                        bn::Fp("20532875081203448695448744255224543661959516361327385779878476709582931298750"));
            bn128_G2::G2_one.coord[2] = bn::Fp2(bn::Fp(1), bn::Fp(0));

            bn128_GT::GT_one.elem = bn::Fp12(1);
        }

        class bn128_G1;
        class bn128_G2;
        class bn128_GT;
        typedef bn128_GT bn128_Fq12;

    }    // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_FF_BN128_INIT_HPP
