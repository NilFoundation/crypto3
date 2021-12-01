//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ZK_R1CS_GG_PPZKSNARK_ENCRYPTED_INPUT_GENERATOR_HPP
#define CRYPTO3_ZK_R1CS_GG_PPZKSNARK_ENCRYPTED_INPUT_GENERATOR_HPP

#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/generator.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /**
                 * A generator algorithm for the R1CS GG-ppzkSNARK with encrypted input.
                 *
                 * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for
                 * CS.
                 */
                template<typename CurveType>
                class r1cs_gg_ppzksnark_generator<CurveType, ProvingMode::EncryptedInput> {
                    typedef detail::r1cs_gg_ppzksnark_basic_policy<CurveType, ProvingMode::EncryptedInput> policy_type;
                    typedef r1cs_gg_ppzksnark_generator<CurveType, ProvingMode::Basic> basic_generator;

                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::template g1_type<> g1_type;
                    typedef typename CurveType::template g2_type<> g2_type;
                    typedef typename CurveType::gt_type gt_type;

                public:
                    static constexpr ProvingMode mode = ProvingMode::EncryptedInput;
                    typedef typename policy_type::constraint_system_type constraint_system_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    template<typename DistributionType =
                                 boost::random::uniform_int_distribution<typename scalar_field_type::integral_type>,
                             typename GeneratorType = boost::random::mt19937>
                    static inline keypair_type
                        process(const typename basic_generator::extended_verification_key_type &gg_keypair,
                                const scalar_field_type &rho, const size_t msg_size) {

                        const size_t input_size = gg_keypair.second.gamma_ABC_g1.rest.values.size();

                        typename scalar_field_type::value_type s_sum = scalar_field_type::zero();

                        // typename g1_type::value_type delta_g1 = gg_keypair.second.delta_g1;
                        std::vector<typename g1_type::value_type> delta_s_g1;
                        typename g1_type::value_type delta_sum_s_g1;
                        typename g1_type::value_type gamma_inverse_sum_s_g1 = gg_keypair.second.gamma_g1;

                        typename g2_type::value_type rho_g2 = rho * typename g2_type::value_type::one();
                        std::vector<typename g2_type::value_type> rho_sv_g2;
                        std::vector<typename g2_type::value_type> rho_rhov_g2;

                        std::vector<typename g1_type::value_type> t_g1;
                        std::vector<typename g2_type::value_type> t_g2;

                        delta_s_g1.reserve(input_size);
                        rho_sv_g2.reserve(input_size);
                        rho_rhov_g2.reserve(input_size);
                        t_g1.reserve(input_size);
                        t_g2.reserve(input_size + 1);

                        typename scalar_field_type::value_type t =
                            algebra::random_element<scalar_field_type, DistributionType, GeneratorType>();
                        t_g2.emplace_back(t * typename g2_type::value_type::one());
                        delta_sum_s_g1 = t * gg_keypair.second.delta_g1;

                        for (size_t i = 1; i < msg_size + 1; i++) {
                            typename scalar_field_type::value_type s =
                                algebra::random_element<scalar_field_type, DistributionType, GeneratorType>();
                            typename scalar_field_type::value_type v =
                                algebra::random_element<scalar_field_type, DistributionType, GeneratorType>();
                            typename scalar_field_type::value_type sv = s * v;
                            t = algebra::random_element<scalar_field_type, DistributionType, GeneratorType>();

                            delta_s_g1.emplace_back(s * gg_keypair.second.delta_g1);
                            t_g1.emplace_back(t * gg_keypair.second.gamma_ABC_g1.rest.values[i]);
                            t_g2.emplace_back(t * typename g2_type::value_type::one());
                            delta_sum_s_g1 = delta_sum_s_g1 + (s * t) * gg_keypair.second.delta_g1;
                            gamma_inverse_sum_s_g1 = gamma_inverse_sum_s_g1 + s * gg_keypair.second.gamma_g1;

                            rho_sv_g2.emplace_back(sv * typename g2_type::value_type::one());
                            rho_rhov_g2.emplace_back(v * rho_g2);
                        }
                        gamma_inverse_sum_s_g1 = -gamma_inverse_sum_s_g1;
                        proving_key_type pk(gg_keypair.second.delta_g1, delta_s_g1, t_g1, t_g2, delta_sum_s_g1,
                                            gamma_inverse_sum_s_g1);
                        verification_key_type vk(rho_g2, rho_sv_g2, rho_rhov_g2);

                        return {pk, vk};
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_GG_PPZKSNARK_ENCRYPTED_INPUT_GENERATOR_HPP
