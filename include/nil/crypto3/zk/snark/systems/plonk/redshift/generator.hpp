//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ZK_R1CS_GG_PPZKSNARK_BASIC_GENERATOR_HPP
#define CRYPTO3_ZK_R1CS_GG_PPZKSNARK_BASIC_GENERATOR_HPP

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/commitments/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/commitments/knowledge_commitment_multiexp.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/detail/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A generator algorithm for the R1CS GG-ppzkSNARK.
                 *
                 * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for
                 * CS.
                 */
                template<typename TCurve>
                class redshift_generator {
                    typedef detail::redshift_types<TCurve> types_policy;

                    // static inline math::polynomial::polynom<...> tau(
                    //     std::size_t input, std::size_t n, std::array<typename TCurve::scalar_field_type::value_type,
                    //     3> &k){

                    //     std::size_t i = input % n;
                    //     std::size_t j = (input - i)/n + 1;

                    //     return (math::polynomial::polynom<...>(k[j]) << i);

                    // }

                    // static inline std::size_t tau_reverted(
                    //     math::polynomial::polynom<...> k_jgi, std::size_t n, std::array<typename
                    //     TCurve::scalar_field_type::value_type, 3> &k){

                    //     std::size_t i = math::polynomial::get_index_of_non_zero_coeff(k_jgi);

                    //     std::size_t j = std::find(k.begin(), k.end(), math::polynomial::get_non_zero_coeff(k_jgi));

                    //     return n*(j - 1) + i;
                    // }

                    // static inline std::size_t sigma_p1_permutation(
                    //     std::size_t input, std::size_t n, std::array<typename TCurve::scalar_field_type::value_type,
                    //     3> &k){
                    //     ...
                    // }

                    // static inline math::polynomial::polynom<...> sigma_p2_permutation(
                    //     math::polynomial::polynom<...> input, std::size_t n, std::array<typename
                    //     TCurve::scalar_field_type::value_type, 3> &k){

                    //     return (tau(sigma_p1_permutation(tau_reverted(input, n, k), n, k), n, k));
                    // }

                public:
                    template<typename DistributionType =
                                 boost::random::uniform_int_distribution<typename scalar_field_type::integral_type>,
                             typename GeneratorType = boost::random::mt19937>
                    static inline keypair_type
                        process(const typename types_policy::constraint_system_type &constraint_system) {

                        std::array<typename TCurve::scalar_field_type::value_type, 3> k =
                            get_cosets_generators<typename TCurve::scalar_field_type>();

                        std::array<math::permutation<...>::polynomial, 3> S_id;
                        std::array<math::permutation<...>::polynomial, 3> S_sigma;

                        typename TCurve::scalar_field_type::value_type omega =
                            algebra::get_root_of_unity<scalar_field_type>();
                        typename TCurve::scalar_field_type::value_type delta =
                            algebra::get_root_of_unity<scalar_field_type>();

                        std::size_t Nperm = ...;

                        for (std::size_t i = 0; i < 3; i++) {
                            std::vector<std::pair<typename TCurve::scalar_field_type::value_type,
                                                  typename TCurve::scalar_field_type::value_type>>
                                interpolation_points(Nperm);
                            for (std::size_t j = 0; j < Nperm; j++) {
                                interpolation_points.push_back(std::make_pair(omega.pow(j), delta??? * omega.pow(j)));
                            }

                            S_id[i] = math::polynomial::lagrange_interpolation(interpolation_points);
                        }

                        for (std::size_t i = 0; i < 3; i++) {
                            std::vector<std::pair<typename TCurve::scalar_field_type::value_type,
                                                  typename TCurve::scalar_field_type::value_type>>
                                interpolation_points(Nperm);
                            for (std::size_t j = 0; j < Nperm; j++) {
                                interpolation_points.push_back(
                                    std::make_pair(omega.pow(j), delta.pow(i) * omega.pow(j)));
                            }

                            S_sigma[i] = math::polynomial::lagrange_interpolation(interpolation_points);
                        }

                        math::polynomial::polynom Z = polynom_by_zeros(H_star);

                        typename types_policy::verification_key_type vk(S_id, S_sigma, q_selectors, L_basis, PI, Z);

                        typename types_policy::proving_key_type pk(S_id, S_sigma, q_selectors, L_basis, f, Z);

                        return {std::move(pk), std::move(vk)};
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_GG_PPZKSNARK_BASIC_GENERATOR_HPP
