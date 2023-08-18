//---------------------------------------------------------------------------//
// Copyright (c) 2022 Noam Y <@NoamDev>
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

#ifndef CRYPTO3_ZK_POWERS_OF_TAU_ACCUMULATOR_HPP
#define CRYPTO3_ZK_POWERS_OF_TAU_ACCUMULATOR_HPP

#include <vector>

#include <nil/crypto3/zk/commitments/detail/polynomial/powers_of_tau/private_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                namespace detail {
                    template<typename CurveType, unsigned TauPowersLength>
                    struct powers_of_tau_accumulator {
                        typedef CurveType curve_type;
                        using g1_type = typename CurveType::template g1_type<>;
                        using g2_type = typename CurveType::template g2_type<>;
                        using g1_value_type = typename g1_type::value_type;
                        using g2_value_type = typename g2_type::value_type;
                        using field_value_type = typename curve_type::scalar_field_type::value_type;
                        using private_key_type = powers_of_tau_private_key<curve_type>;

                        // The maximum number of multiplication gates supported
                        static constexpr unsigned tau_powers_length = TauPowersLength;

                        // More tau powers are needed in G1 because the Groth16 H query
                        // includes terms of the form tau^i * (tau^m - 1) = tau^(i+m) - tau^i
                        // where the largest i = m - 2, requiring the computation of tau^(2m - 2)
                        // and thus giving us a vector length of 2m - 1.
                        static constexpr unsigned tau_powers_g1_length = (tau_powers_length << 1) - 1;

                        // tau^0, tau^1, tau^2, ..., tau^{tau_powers_g1_length - 1}
                        std::vector<g1_value_type> tau_powers_g1;
                        // tau^0, tau^1, tau^2, ..., tau^{tau_powers_length - 1}
                        std::vector<g2_value_type> tau_powers_g2;
                        // alpha * tau^0, alpha * tau^1, alpha * tau^2, ..., alpha * tau^{tau_powers_length - 1}
                        std::vector<g1_value_type> alpha_tau_powers_g1;
                        // beta * tau^0, beta * tau^1, beta * tau^2, ..., beta * tau^{tau_powers_length - 1}
                        std::vector<g1_value_type> beta_tau_powers_g1;
                        // beta
                        g2_value_type beta_g2;

                        powers_of_tau_accumulator() :
                                tau_powers_g1(tau_powers_g1_length, g1_value_type::one()),
                                tau_powers_g2(tau_powers_length, g2_value_type::one()),
                                alpha_tau_powers_g1(tau_powers_length, g1_value_type::one()),
                                beta_tau_powers_g1(tau_powers_length, g1_value_type::one()),
                                beta_g2(g2_value_type::one()) {
                        }

                        powers_of_tau_accumulator(const std::vector<g1_value_type> &tau_powers_g1,
                                                  const std::vector<g2_value_type> &tau_powers_g2,
                                                  const std::vector<g1_value_type> &alpha_tau_powers_g1,
                                                  const std::vector<g1_value_type> &beta_tau_powers_g1,
                                                  g2_value_type beta_g2) :
                                tau_powers_g1(tau_powers_g1),
                                tau_powers_g2(tau_powers_g2), alpha_tau_powers_g1(alpha_tau_powers_g1),
                                beta_tau_powers_g1(beta_tau_powers_g1), beta_g2(beta_g2) {
                            BOOST_ASSERT(tau_powers_g1.size() == tau_powers_g1_length);
                            BOOST_ASSERT(tau_powers_g2.size() == tau_powers_length);
                            BOOST_ASSERT(alpha_tau_powers_g1.size() == tau_powers_length);
                            BOOST_ASSERT(beta_tau_powers_g1.size() == tau_powers_length);
                        }

                        void transform(const private_key_type &key) {
                            std::vector<field_value_type> taupowers;

                            // Construct exponents
                            // This could be parallelized
                            auto acc = field_value_type::one();
                            for (std::size_t i = 0; i < tau_powers_g1_length; ++i) {
                                // taupowers[i] = tau^i
                                taupowers.emplace_back(acc);
                                acc *= key.tau;
                            }

                            // naive exp, could be parallelized
                            naive_batch_exp(
                                    tau_powers_g1.begin(), tau_powers_g1.end(), taupowers.begin(), taupowers.end());

                            naive_batch_exp(
                                    tau_powers_g2.begin(), tau_powers_g2.end(), taupowers.begin(), taupowers.end());

                            naive_batch_exp_with_coeff(alpha_tau_powers_g1.begin(),
                                                       alpha_tau_powers_g1.end(),
                                                       taupowers.begin(),
                                                       taupowers.end(),
                                                       key.alpha);

                            naive_batch_exp_with_coeff(beta_tau_powers_g1.begin(),
                                                       beta_tau_powers_g1.end(),
                                                       taupowers.begin(),
                                                       taupowers.end(),
                                                       key.beta);

                            beta_g2 = beta_g2 * key.beta;
                        }

                    private:
                        template<typename PointIterator, typename ScalarIterator>
                        void naive_batch_exp(const PointIterator &bases_begin,
                                             const PointIterator &bases_end,
                                             const ScalarIterator &pow_begin,
                                             const ScalarIterator &pow_end) {
                            BOOST_ASSERT(std::distance(bases_begin, bases_end) <= std::distance(pow_begin, pow_end));

                            auto base_iter = bases_begin;
                            auto pow_iter = pow_begin;
                            while (base_iter < bases_end) {
                                *base_iter = *pow_iter * *base_iter;
                                ++base_iter;
                                ++pow_iter;
                            }
                        }

                        template<typename PointIterator, typename ScalarIterator>
                        void naive_batch_exp_with_coeff(const PointIterator &bases_begin,
                                                        const PointIterator &bases_end,
                                                        const ScalarIterator &pow_begin,
                                                        const ScalarIterator &pow_end,
                                                        const field_value_type &coeff) {
                            BOOST_ASSERT(std::distance(bases_begin, bases_end) <= std::distance(pow_begin, pow_end));

                            auto base_iter = bases_begin;
                            auto pow_iter = pow_begin;
                            while (base_iter < bases_end) {
                                *base_iter = (coeff * *pow_iter) * *base_iter;
                                ++base_iter;
                                ++pow_iter;
                            }
                        }
                    };

                }    // namespace detail
            }        // namespace commitments
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_POWERS_OF_TAU_ACCUMULATOR_HPP
