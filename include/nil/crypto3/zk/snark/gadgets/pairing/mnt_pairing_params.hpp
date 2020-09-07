//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of specializations of pairing_selector<CurveType> to
// - pairing_selector<algebra::algebra::curves::mnt4>, and
// - pairing_selector<algebra::algebra::curves::mnt6>.
//
// See pairing_params.hpp .
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MNT_PAIRING_PARAMS_HPP
#define CRYPTO3_MNT_PAIRING_PARAMS_HPP

#include <nil/crypto3/zk/snark/gadgets/fields/fp2_gadgets.hpp>
#include <nil/crypto3/zk/snark/gadgets/fields/fp3_gadgets.hpp>
#include <nil/crypto3/zk/snark/gadgets/fields/fp4_gadgets.hpp>
#include <nil/crypto3/zk/snark/gadgets/fields/fp6_gadgets.hpp>
#include <nil/crypto3/zk/snark/gadgets/pairing/pairing_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType>
                class mnt_e_over_e_miller_loop_gadget;

                template<typename CurveType>
                class mnt_e_times_e_over_e_miller_loop_gadget;

                template<typename CurveType>
                class mnt4_final_exp_gadget;

                template<typename CurveType>
                class mnt6_final_exp_gadget;

                /**
                 * Specialization for MNT4.
                 */
                template<>
                class pairing_selector<algebra::curves::mnt4> {
                public:
                    typedef typename algebra::curves::mnt4::scalar_field_type FieldType;
                    typedef algebra::Fqe<algebra::curves::mnt6> fqe_type;
                    typedef algebra::Fqk<algebra::curves::mnt6> fqk_type;

                    typedef Fp3_variable<fqe_type> Fqe_variable_type;
                    typedef Fp3_mul_gadget<fqe_type> Fqe_mul_gadget_type;
                    typedef Fp3_mul_by_lc_gadget<fqe_type> Fqe_mul_by_lc_gadget_type;
                    typedef Fp3_sqr_gadget<fqe_type> Fqe_sqr_gadget_type;

                    typedef Fp6_variable<fqk_type> Fqk_variable_type;
                    typedef Fp6_mul_gadget<fqk_type> Fqk_mul_gadget_type;
                    typedef Fp6_mul_by_2345_gadget<fqk_type> Fqk_special_mul_gadget_type;
                    typedef Fp6_sqr_gadget<fqk_type> Fqk_sqr_gadget_type;

                    typedef algebra::curves::mnt6 other_curve_type;

                    typedef mnt_e_over_e_miller_loop_gadget<algebra::curves::mnt4> e_over_e_miller_loop_gadget_type;
                    typedef mnt_e_times_e_over_e_miller_loop_gadget<algebra::curves::mnt4>
                        e_times_e_over_e_miller_loop_gadget_type;
                    typedef mnt4_final_exp_gadget<algebra::curves::mnt4> final_exp_gadget_type;

                    static const constexpr algebra::bigint<algebra::mnt6_Fr::num_limbs> &pairing_loop_count =
                        algebra::mnt6_ate_loop_count;
                };

                /**
                 * Specialization for MNT6.
                 */
                template<>
                class pairing_selector<algebra::curves::mnt6> {
                public:
                    typedef typename algebra::curves::mnt6::scalar_field_type FieldType;

                    typedef algebra::Fqe<algebra::curves::mnt4> fqe_type;
                    typedef algebra::Fqk<algebra::curves::mnt4> fqk_type;

                    typedef Fp2_variable<fqe_type> Fqe_variable_type;
                    typedef Fp2_mul_gadget<fqe_type> Fqe_mul_gadget_type;
                    typedef Fp2_mul_by_lc_gadget<fqe_type> Fqe_mul_by_lc_gadget_type;
                    typedef Fp2_sqr_gadget<fqe_type> Fqe_sqr_gadget_type;

                    typedef Fp4_variable<fqk_type> Fqk_variable_type;
                    typedef Fp4_mul_gadget<fqk_type> Fqk_mul_gadget_type;
                    typedef Fp4_mul_gadget<fqk_type> Fqk_special_mul_gadget_type;
                    typedef Fp4_sqr_gadget<fqk_type> Fqk_sqr_gadget_type;

                    typedef algebra::curves::mnt4 other_curve_type;

                    typedef mnt_e_over_e_miller_loop_gadget<algebra::curves::mnt6> e_over_e_miller_loop_gadget_type;
                    typedef mnt_e_times_e_over_e_miller_loop_gadget<algebra::curves::mnt6>
                        e_times_e_over_e_miller_loop_gadget_type;
                    typedef mnt6_final_exp_gadget<algebra::curves::mnt6> final_exp_gadget_type;

                    static const constexpr algebra::bigint<algebra::mnt4_Fr::num_limbs> &pairing_loop_count =
                        algebra::mnt4_ate_loop_count;
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MNT_PAIRING_PARAMS_HPP
