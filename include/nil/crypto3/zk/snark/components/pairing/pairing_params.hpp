//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of selector for the pairing gadget.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_PAIRING_PARAMS_HPP_
#define CRYPTO3_ZK_PAIRING_PARAMS_HPP_

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * The interfaces of pairing gadgets are templatized via the parameter
                 * ec_ppT. When used, the interfaces must be invoked with
                 * a particular parameter choice; let 'my_ec_pp' denote this choice.
                 *
                 * Moreover, one must provide a template specialization for the class
                 * pairing_selector (below), containing typedefs for the typenames
                 * - FieldType
                 * - fqe_type
                 * - fqk_type
                 * - Fqe_variable_type;
                 * - Fqe_mul_component_type
                 * - Fqe_mul_by_lc_component_type
                 * - Fqe_sqr_component_type
                 * - Fqk_variable_type
                 * - Fqk_mul_component_type
                 * - Fqk_special_mul_component_type
                 * - Fqk_sqr_component_type
                 * - other_curve_type
                 * - e_over_e_miller_loop_component_type
                 * - e_times_e_over_e_miller_loop_component_type
                 * - final_exp_component_type
                 * and also containing a static constant
                 * - const constexpr algebra::algebra::bigint<m> pairing_loop_count
                 *
                 * For example, if you want to use the types my_Field, my_Fqe, etc,
                 * then you would do as follows. First declare a new type:
                 *
                 *   class my_ec_pp;
                 *
                 * Second, specialize pairing_selector<ec_ppT> for the
                 * case ec_ppT = my_ec_pp, using the above types:
                 *
                 *   template<>
                 *   class pairing_selector<my_ec_pp> {
                 *       typedef my_Field FieldType;
                 *       typedef my_Fqe fqe_type;
                 *       typedef my_Fqk fqk_type;
                 *       typedef my_Fqe_variable_type Fqe_variable_type;
                 *       typedef my_Fqe_mul_component_type Fqe_mul_component_type;
                 *       typedef my_Fqe_mul_by_lc_component_type Fqe_mul_by_lc_component_type;
                 *       typedef my_Fqe_sqr_component_type Fqe_sqr_component_type;
                 *       typedef my_Fqk_variable_type Fqk_variable_type;
                 *       typedef my_Fqk_mul_component_type Fqk_mul_component_type;
                 *       typedef my_Fqk_special_mul_component_type Fqk_special_mul_component_type;
                 *       typedef my_Fqk_sqr_component_type Fqk_sqr_component_type;
                 *       typedef my_other_curve_type other_curve_type;
                 *       typedef my_e_over_e_miller_loop_component_type e_over_e_miller_loop_component_type;
                 *       typedef my_e_times_e_over_e_miller_loop_component_type e_times_e_over_e_miller_loop_component_type;
                 *       typedef my_final_exp_component_type final_exp_component_type;
                 *       static const constexpr algebra::algebra::bigint<...> &pairing_loop_count = ...;
                 *   };
                 *
                 * Having done the above, my_ec_pp can be used as a template parameter.
                 *
                 * See mnt_pairing_params.hpp for examples for the case of fixing
                 * ec_ppT to "MNT4" and "MNT6".
                 *
                 */
                template<typename CurveType>
                class pairing_selector;

                /**
                 * Below are various template aliases (used for convenience).
                 */

                template<typename CurveType>
                using fqk_type = typename pairing_selector<CurveType>::fqk_type;    // TODO: better name when stable

                template<typename CurveType>
                using Fqe_variable = typename pairing_selector<CurveType>::Fqe_variable_type;
                template<typename CurveType>
                using Fqe_mul_component = typename pairing_selector<CurveType>::Fqe_mul_component_type;
                template<typename CurveType>
                using Fqe_mul_by_lc_component = typename pairing_selector<CurveType>::Fqe_mul_by_lc_component_type;
                template<typename CurveType>
                using Fqe_sqr_component = typename pairing_selector<CurveType>::Fqe_sqr_component_type;

                template<typename CurveType>
                using Fqk_variable = typename pairing_selector<CurveType>::Fqk_variable_type;
                template<typename CurveType>
                using Fqk_mul_component = typename pairing_selector<CurveType>::Fqk_mul_component_type;
                template<typename CurveType>
                using Fqk_special_mul_component = typename pairing_selector<CurveType>::Fqk_special_mul_component_type;
                template<typename CurveType>
                using Fqk_sqr_component = typename pairing_selector<CurveType>::Fqk_sqr_component_type;

                template<typename CurveType>
                using other_curve = typename pairing_selector<CurveType>::other_curve_type;

                template<typename CurveType>
                using e_over_e_miller_loop_component = typename pairing_selector<CurveType>::e_over_e_miller_loop_component_type;
                template<typename CurveType>
                using e_times_e_over_e_miller_loop_component =
                    typename pairing_selector<CurveType>::e_times_e_over_e_miller_loop_component_type;
                template<typename CurveType>
                using final_exp_component = typename pairing_selector<CurveType>::final_exp_component_type;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // PAIRING_PARAMS_HPP_
