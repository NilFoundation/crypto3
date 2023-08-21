#ifndef CRYPTO3_ZK_R1CS_GG_PPZKSNARK_CRS_OPERATIONS_HPP
#define CRYPTO3_ZK_R1CS_GG_PPZKSNARK_CRS_OPERATIONS_HPP

#include <vector>

#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>
#include <nil/crypto3/container/accumulation_vector.hpp>
#include <nil/crypto3/zk/commitments/polynomial/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/powers_of_tau/result.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/r1cs_gg_ppzksnark_mpc/private_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                namespace detail {
                    template<typename CurveType>
                    typename snark::r1cs_gg_ppzksnark<CurveType>::keypair_type
                    make_r1cs_gg_ppzksnark_keypair_from_powers_of_tau(
                            const typename snark::r1cs_gg_ppzksnark<CurveType>::constraint_system_type
                            &constraint_system,
                            const powers_of_tau_result<CurveType> &powers_of_tau_result) {
                        using curve_type = CurveType;
                        using scalar_field_type = typename curve_type::scalar_field_type;
                        using g1_type = typename curve_type::template g1_type<>;
                        using g2_type = typename curve_type::template g2_type<>;
                        using kc_type = commitments::knowledge_commitment<g2_type, g1_type>;
                        using g1_value_type = typename g1_type::value_type;
                        using g2_value_type = typename g2_type::value_type;
                        using kc_value_type = typename kc_type::value_type;

                        using namespace nil::crypto3::zk::snark;

                        using proving_scheme_type = r1cs_gg_ppzksnark<CurveType>;

                        typename proving_scheme_type::constraint_system_type r1cs_copy(constraint_system);
                        r1cs_copy.swap_AB_if_beneficial();

                        qap_instance<scalar_field_type> qap =
                                reductions::r1cs_to_qap<scalar_field_type>::instance_map(r1cs_copy);

                        BOOST_ASSERT_MSG(powers_of_tau_result.coeffs_g1.size() == qap.domain->m,
                                         "powers_of_tau_result size does not match the constraint system");
                        BOOST_ASSERT_MSG(powers_of_tau_result.coeffs_g2.size() == qap.domain->m,
                                         "powers_of_tau_result size does not match the constraint system");
                        BOOST_ASSERT_MSG(powers_of_tau_result.alpha_coeffs_g1.size() == qap.domain->m,
                                         "powers_of_tau_result size does not match the constraint system");
                        BOOST_ASSERT_MSG(powers_of_tau_result.beta_coeffs_g1.size() == qap.domain->m,
                                         "powers_of_tau_result size does not match the constraint system");
                        BOOST_ASSERT_MSG(powers_of_tau_result.h.size() == qap.domain->m - 1,
                                         "powers_of_tau_result size does not match the constraint system");

                        std::vector<g1_value_type> beta_a_alpha_b_c(qap.num_variables + 1, g1_value_type::zero());
                        std::vector<g1_value_type> a_g1(qap.num_variables + 1, g1_value_type::zero());
                        std::vector<kc_value_type> b_kc(qap.num_variables + 1, kc_value_type::zero());

                        for (std::size_t i = 0; i < qap.num_variables + 1; ++i) {
                            for (auto [lag, coeff]: qap.A_in_Lagrange_basis[i]) {
                                a_g1[i] = a_g1[i] + coeff * powers_of_tau_result.coeffs_g1[lag];
                                beta_a_alpha_b_c[i] =
                                        beta_a_alpha_b_c[i] + coeff * powers_of_tau_result.beta_coeffs_g1[lag];
                            }
                            for (auto [lag, coeff]: qap.B_in_Lagrange_basis[i]) {
                                b_kc[i] = b_kc[i] + coeff * kc_value_type(powers_of_tau_result.coeffs_g2[lag],
                                                                          powers_of_tau_result.coeffs_g1[lag]);
                                beta_a_alpha_b_c[i] =
                                        beta_a_alpha_b_c[i] + coeff * powers_of_tau_result.alpha_coeffs_g1[lag];
                            }
                            for (auto [lag, coeff]: qap.C_in_Lagrange_basis[i]) {
                                beta_a_alpha_b_c[i] = beta_a_alpha_b_c[i] + coeff * powers_of_tau_result.coeffs_g1[lag];
                            }
                        }

                        auto alpha_g1 = powers_of_tau_result.alpha_g1;
                        auto beta_g1 = powers_of_tau_result.beta_g1;
                        auto beta_g2 = powers_of_tau_result.beta_g2;

                        auto alpha_g1_beta_g2 = algebra::pair_reduced<curve_type>(alpha_g1, beta_g2);
                        auto gamma_g2 = g2_value_type::one();
                        auto delta_g1 = g1_value_type::one();
                        auto delta_g2 = g2_value_type::one();
                        auto gamma_ABC_g1_0 = beta_a_alpha_b_c[0];
                        std::vector<g1_value_type> gamma_ABC_g1_values(beta_a_alpha_b_c.begin() + 1,
                                                                       beta_a_alpha_b_c.begin() + 1 + qap.num_inputs);
                        container::accumulation_vector<g1_type> gamma_ABC(std::move(gamma_ABC_g1_0),
                                                                          std::move(gamma_ABC_g1_values));
                        typename proving_scheme_type::verification_key_type vk(
                                alpha_g1_beta_g2, gamma_g2, delta_g2, gamma_ABC);

                        commitments::knowledge_commitment_vector<g2_type, g1_type> B_query(std::move(b_kc));
                        std::vector<g1_value_type> H_query(powers_of_tau_result.h.begin(),
                                                           powers_of_tau_result.h.begin() + qap.degree - 1);
                        std::size_t Lt_offset = qap.num_inputs + 1;
                        std::vector<g1_value_type> L_query(beta_a_alpha_b_c.begin() + Lt_offset,
                                                           beta_a_alpha_b_c.end());
                        typename proving_scheme_type::proving_key_type pk(std::move(alpha_g1),
                                                                          std::move(beta_g1),
                                                                          std::move(beta_g2),
                                                                          std::move(delta_g1),
                                                                          std::move(delta_g2),
                                                                          std::move(a_g1),
                                                                          std::move(B_query),
                                                                          std::move(H_query),
                                                                          std::move(L_query),
                                                                          std::move(r1cs_copy));

                        typename proving_scheme_type::keypair_type keypair{std::move(pk), std::move(vk)};

                        return keypair;
                    }

                    template<typename CurveType>
                    void transform_keypair(typename snark::r1cs_gg_ppzksnark<CurveType>::keypair_type &keypair,
                                           const r1cs_gg_ppzksnark_mpc_private_key<CurveType> &private_key) {
                        auto delta_inv = private_key.delta.inversed();
                        for (auto &g: keypair.first.H_query) {
                            g = g * delta_inv;
                        }

                        for (auto &g: keypair.first.L_query) {
                            g = g * delta_inv;
                        }

                        keypair.first.delta_g1 = private_key.delta * keypair.first.delta_g1;
                        keypair.first.delta_g2 = private_key.delta * keypair.first.delta_g2;
                        keypair.second.delta_g2 = private_key.delta * keypair.second.delta_g2;
                    }
                }    // namespace detail
            }        // namespace commitments
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_GG_PPZKSNARK_CRS_OPERATIONS_HPP
