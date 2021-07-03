//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ZK_USCS_PPZKSNARK_BASIC_GENERATOR_HPP
#define CRYPTO3_ZK_USCS_PPZKSNARK_BASIC_GENERATOR_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/snark/reductions/uscs_to_ssp.hpp>
#include <nil/crypto3/zk/snark/relations/arithmetic_programs/ssp.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/uscs_ppzksnark/detail/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A generator algorithm for the USCS ppzkSNARK.
                 *
                 * Given a USCS constraint system CS, this algorithm produces proving and verification keys for
                 * CS.
                 */
                template<typename CurveType>
                class uscs_ppzksnark_generator {
                    typedef detail::uscs_ppzksnark_policy<CurveType> policy_type;

                public:
                    typedef typename policy_type::constraint_system_type constraint_system_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    static inline keypair_type process(const constraint_system_type &constraint_system) {

                        /* draw random element at which the SSP is evaluated */

                        const typename CurveType::scalar_field_type::value_type t =
                            algebra::random_element<typename CurveType::scalar_field_type>();

                        /* perform USCS-to-SSP reduction */

                        ssp_instance_evaluation<typename CurveType::scalar_field_type> ssp_inst =
                            reductions::uscs_to_ssp<
                                typename CurveType::scalar_field_type>::instance_map_with_evaluation(constraint_system, t);

                        /* construct various tables of typename FieldType::value_type elements */

                        std::vector<typename CurveType::scalar_field_type::value_type> Vt_table = std::move(
                            ssp_inst.Vt);    // ssp_inst.Vt is now in unspecified state, but we do not use it later
                        std::vector<typename CurveType::scalar_field_type::value_type> Ht_table = std::move(
                            ssp_inst.Ht);    // ssp_inst.Ht is now in unspecified state, but we do not use it later

                        Vt_table.emplace_back(ssp_inst.Zt);

                        std::vector<typename CurveType::scalar_field_type::value_type> Xt_table =
                            std::vector<typename CurveType::scalar_field_type::value_type>(
                                Vt_table.begin(), Vt_table.begin() + ssp_inst.num_inputs + 1);
                        std::vector<typename CurveType::scalar_field_type::value_type> Vt_table_minus_Xt_table =
                            std::vector<typename CurveType::scalar_field_type::value_type>(
                                Vt_table.begin() + ssp_inst.num_inputs + 1, Vt_table.end());

                        /* sanity checks */

                        assert(Vt_table.size() == ssp_inst.num_variables + 2);
                        assert(Ht_table.size() == ssp_inst.degree + 1);
                        assert(Xt_table.size() == ssp_inst.num_inputs + 1);
                        assert(Vt_table_minus_Xt_table.size() ==
                               ssp_inst.num_variables + 2 - ssp_inst.num_inputs - 1);
                        for (std::size_t i = 0; i < ssp_inst.num_inputs + 1; ++i) {
                            assert(!Xt_table[i].is_zero());
                        }

                        const typename CurveType::scalar_field_type::value_type alpha =
                            algebra::random_element<typename CurveType::scalar_field_type>();

                        const std::size_t g1_exp_count =
                            Vt_table.size() + Vt_table_minus_Xt_table.size() + Ht_table.size();
                        const std::size_t g2_exp_count = Vt_table_minus_Xt_table.size();

                        std::size_t g1_window = algebra::get_exp_window_size<typename CurveType::g1_type>(g1_exp_count);
                        std::size_t g2_window = algebra::get_exp_window_size<typename CurveType::g2_type>(g2_exp_count);

                        algebra::window_table<typename CurveType::g1_type> g1_table = algebra::get_window_table<
                            typename CurveType::g1_type>(
                            CurveType::scalar_field_type::value_bits, g1_window, CurveType::g1_type::value_type::one());

                        algebra::window_table<typename CurveType::g2_type> g2_table = algebra::get_window_table<
                            typename CurveType::g2_type>(
                            CurveType::scalar_field_type::value_bits, g2_window, CurveType::g2_type::value_type::one());

                        typename std::vector<typename CurveType::g1_type::value_type> V_g1_query = algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                            CurveType::scalar_field_type::value_bits, g1_window, g1_table, Vt_table_minus_Xt_table);
#ifdef USE_MIXED_ADDITION
                        algebra::batch_to_special<typename CurveType::g1_type>(V_g1_query);
#endif

                        typename std::vector<typename CurveType::g1_type::value_type> alpha_V_g1_query =
                            algebra::batch_exp_with_coeff<typename CurveType::g1_type, typename CurveType::scalar_field_type>(CurveType::scalar_field_type::value_bits, g1_window, g1_table, alpha,
                                                 Vt_table_minus_Xt_table);
#ifdef USE_MIXED_ADDITION
                        algebra::batch_to_special<typename CurveType::g1_type>(alpha_V_g1_query);
#endif

                        typename std::vector<typename CurveType::g1_type::value_type> H_g1_query =
                            algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(CurveType::scalar_field_type::value_bits, g1_window, g1_table, Ht_table);
#ifdef USE_MIXED_ADDITION
                        algebra::batch_to_special<typename CurveType::g1_type>(H_g1_query);
#endif

                        typename std::vector<typename CurveType::g2_type::value_type> V_g2_query =
                            algebra::batch_exp<typename CurveType::g2_type, typename CurveType::scalar_field_type>(CurveType::scalar_field_type::value_bits, g2_window, g2_table, Vt_table);
#ifdef USE_MIXED_ADDITION
                        algebra::batch_to_special<typename CurveType::g2_type>(V_g2_query);
#endif
                        const typename CurveType::scalar_field_type::value_type tilde =
                            algebra::random_element<typename CurveType::scalar_field_type>();
                        typename CurveType::g2_type::value_type tilde_g2 =
                            tilde * CurveType::g2_type::value_type::one();
                        typename CurveType::g2_type::value_type alpha_tilde_g2 =
                            (alpha * tilde) * CurveType::g2_type::value_type::one();
                        typename CurveType::g2_type::value_type Z_g2 =
                            ssp_inst.Zt * CurveType::g2_type::value_type::one();

                        typename CurveType::g1_type::value_type encoded_IC_base =
                            Xt_table[0] * CurveType::g1_type::value_type::one();
                        typename std::vector<typename CurveType::g1_type::value_type> encoded_IC_values =
                            algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(CurveType::scalar_field_type::value_bits, g1_window, g1_table,
                                      std::vector<typename CurveType::scalar_field_type::value_type>(
                                          Xt_table.begin() + 1, Xt_table.end()));

                        accumulation_vector<typename CurveType::g1_type> encoded_IC_query(std::move(encoded_IC_base),
                                                                                          std::move(encoded_IC_values));

                        verification_key_type vk =
                            verification_key_type(tilde_g2, alpha_tilde_g2, Z_g2, encoded_IC_query);

                        constraint_system_type cs_copy = constraint_system;
                        proving_key_type pk = proving_key_type(std::move(V_g1_query),
                                                               std::move(alpha_V_g1_query),
                                                               std::move(H_g1_query),
                                                               std::move(V_g2_query),
                                                               std::move(cs_copy));

                        return keypair_type(std::move(pk), std::move(vk));
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_USCS_PPZKSNARK_BASIC_GENERATOR_HPP
