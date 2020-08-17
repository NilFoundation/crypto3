//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of specializations of pairing_selector<ppT> to
// - pairing_selector<algebra::algebra::mnt4_pp>, and
// - pairing_selector<algebra::algebra::mnt6_pp>.
//
// See pairing_params.hpp .
//---------------------------------------------------------------------------//

#ifndef MNT_PAIRING_PARAMS_HPP_
#define MNT_PAIRING_PARAMS_HPP_

#include <nil/crypto3/zk/snark/gadgets/fields/fp2_gadgets.hpp>
#include <nil/crypto3/zk/snark/gadgets/fields/fp3_gadgets.hpp>
#include <nil/crypto3/zk/snark/gadgets/fields/fp4_gadgets.hpp>
#include <nil/crypto3/zk/snark/gadgets/fields/fp6_gadgets.hpp>
#include <nil/crypto3/zk/snark/gadgets/pairing/pairing_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename ppT>
                class mnt_e_over_e_miller_loop_gadget;

                template<typename ppT>
                class mnt_e_times_e_over_e_miller_loop_gadget;

                template<typename ppT>
                class mnt4_final_exp_gadget;

                template<typename ppT>
                class mnt6_final_exp_gadget;

                /**
                 * Specialization for MNT4.
                 */
                template<>
                class pairing_selector<algebra::mnt4_pp> {
                public:
                    typedef algebra::Fr<algebra::mnt4_pp> FieldType;
                    typedef algebra::Fqe<algebra::mnt6_pp> FqeT;
                    typedef algebra::Fqk<algebra::mnt6_pp> FqkT;

                    typedef Fp3_variable<FqeT> Fqe_variable_type;
                    typedef Fp3_mul_gadget<FqeT> Fqe_mul_gadget_type;
                    typedef Fp3_mul_by_lc_gadget<FqeT> Fqe_mul_by_lc_gadget_type;
                    typedef Fp3_sqr_gadget<FqeT> Fqe_sqr_gadget_type;

                    typedef Fp6_variable<FqkT> Fqk_variable_type;
                    typedef Fp6_mul_gadget<FqkT> Fqk_mul_gadget_type;
                    typedef Fp6_mul_by_2345_gadget<FqkT> Fqk_special_mul_gadget_type;
                    typedef Fp6_sqr_gadget<FqkT> Fqk_sqr_gadget_type;

                    typedef algebra::mnt6_pp other_curve_type;

                    typedef mnt_e_over_e_miller_loop_gadget<algebra::mnt4_pp> e_over_e_miller_loop_gadget_type;
                    typedef mnt_e_times_e_over_e_miller_loop_gadget<algebra::mnt4_pp>
                        e_times_e_over_e_miller_loop_gadget_type;
                    typedef mnt4_final_exp_gadget<algebra::mnt4_pp> final_exp_gadget_type;

                    static const constexpr algebra::bigint<algebra::mnt6_Fr::num_limbs> &pairing_loop_count =
                        algebra::mnt6_ate_loop_count;
                };

                /**
                 * Specialization for MNT6.
                 */
                template<>
                class pairing_selector<algebra::mnt6_pp> {
                public:
                    typedef algebra::Fr<algebra::mnt6_pp> FieldType;

                    typedef algebra::Fqe<algebra::mnt4_pp> FqeT;
                    typedef algebra::Fqk<algebra::mnt4_pp> FqkT;

                    typedef Fp2_variable<FqeT> Fqe_variable_type;
                    typedef Fp2_mul_gadget<FqeT> Fqe_mul_gadget_type;
                    typedef Fp2_mul_by_lc_gadget<FqeT> Fqe_mul_by_lc_gadget_type;
                    typedef Fp2_sqr_gadget<FqeT> Fqe_sqr_gadget_type;

                    typedef Fp4_variable<FqkT> Fqk_variable_type;
                    typedef Fp4_mul_gadget<FqkT> Fqk_mul_gadget_type;
                    typedef Fp4_mul_gadget<FqkT> Fqk_special_mul_gadget_type;
                    typedef Fp4_sqr_gadget<FqkT> Fqk_sqr_gadget_type;

                    typedef algebra::mnt4_pp other_curve_type;

                    typedef mnt_e_over_e_miller_loop_gadget<algebra::mnt6_pp> e_over_e_miller_loop_gadget_type;
                    typedef mnt_e_times_e_over_e_miller_loop_gadget<algebra::mnt6_pp>
                        e_times_e_over_e_miller_loop_gadget_type;
                    typedef mnt6_final_exp_gadget<algebra::mnt6_pp> final_exp_gadget_type;

                    static const constexpr algebra::bigint<algebra::mnt4_Fr::num_limbs> &pairing_loop_count =
                        algebra::mnt4_ate_loop_count;
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // MNT_PAIRING_PARAMS_HPP_
