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

#ifndef CRYPTO3_ZK_POWERS_OF_TAU_RESULT_HPP
#define CRYPTO3_ZK_POWERS_OF_TAU_RESULT_HPP

#include <vector>

#include <nil/crypto3/zk/commitments/detail/polynomial/powers_of_tau/accumulator.hpp>

#include <nil/crypto3/math/polynomial/basic_operations.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                namespace detail {
                    template<typename CurveType>
                    struct powers_of_tau_result {
                        typedef CurveType curve_type;
                        using g1_type = typename CurveType::template g1_type<>;
                        using g2_type = typename CurveType::template g2_type<>;
                        using g1_value_type = typename g1_type::value_type;
                        using g2_value_type = typename g2_type::value_type;
                        using scalar_field_type = typename curve_type::scalar_field_type; 
                        using scalar_field_value_type = typename scalar_field_type::value_type; 
                        
                        g1_value_type alpha_g1;
                        g1_value_type beta_g1;
                        g2_value_type beta_g2;
                        std::vector<g1_value_type> coeffs_g1;
                        std::vector<g2_value_type> coeffs_g2;
                        std::vector<g1_value_type> alpha_coeffs_g1;
                        std::vector<g1_value_type> beta_coeffs_g1;
                        std::vector<g1_value_type> h;

                        powers_of_tau_result(
                            const g1_value_type &alpha_g1,
                            const g1_value_type &beta_g1,
                            const g2_value_type &beta_g2,
                            const std::vector<g1_value_type> &coeffs_g1,
                            const std::vector<g2_value_type> &coeffs_g2,
                            const std::vector<g1_value_type> &alpha_coeffs_g1,
                            const std::vector<g1_value_type> &beta_coeffs_g1,
                            const std::vector<g1_value_type> &h) :
                            alpha_g1(alpha_g1), beta_g1(beta_g1), beta_g2(beta_g2),
                            coeffs_g1(coeffs_g1), coeffs_g2(coeffs_g2),
                            alpha_coeffs_g1(alpha_coeffs_g1), beta_coeffs_g1(beta_coeffs_g1),
                            h(h) {
                        }

                        template<unsigned TauPowersLength>
                        static powers_of_tau_result from_accumulator(
                                const powers_of_tau_accumulator<curve_type, TauPowersLength> &acc,
                                std::size_t m) {
                            
                            auto alpha_g1 = acc.alpha_tau_powers_g1[0];
                            auto beta_g1 = acc.beta_tau_powers_g1[0];
                            auto beta_g2 = acc.beta_g2; 
                            
                            BOOST_ASSERT(m <= TauPowersLength);
                            BOOST_ASSERT(m == math::detail::power_of_two(m));
                            
                            std::vector<g1_value_type> coeffs_g1 = evaluate_lagrange_polynomials(acc.tau_powers_g1, m);
                            
                            std::vector<g2_value_type> coeffs_g2 = evaluate_lagrange_polynomials(acc.tau_powers_g2, m);
                            
                            std::vector<g1_value_type> alpha_coeffs_g1 = evaluate_lagrange_polynomials(acc.alpha_tau_powers_g1, m);
                            
                            std::vector<g1_value_type> beta_coeffs_g1 = evaluate_lagrange_polynomials(acc.beta_tau_powers_g1, m);
                            
                            std::vector<g1_value_type> h;
                            for(std::size_t i=0; i < m-1; ++i) {
                                h.emplace_back(acc.tau_powers_g1[i + m] - acc.tau_powers_g1[i]);
                            }

                            return powers_of_tau_result(
                                std::move(alpha_g1),
                                std::move(beta_g1),
                                std::move(beta_g2),
                                std::move(coeffs_g1),
                                std::move(coeffs_g2),
                                std::move(alpha_coeffs_g1),
                                std::move(beta_coeffs_g1),
                                std::move(h));
                        } 

                        template<typename GroupValueType>
                        static std::vector<GroupValueType> evaluate_lagrange_polynomials(
                                const std::vector<GroupValueType> &powers,
                                std::size_t degree) {
                            
                            BOOST_ASSERT(degree <= powers.size());
                            BOOST_ASSERT(degree == math::detail::power_of_two(degree));
                            
                            std::vector<GroupValueType> res(powers.begin(), powers.begin() + degree);
                            auto domain = math::make_evaluation_domain<scalar_field_type, GroupValueType>(degree);
                            domain->inverse_fft(res);
                            return res;
                        }
                    };
                } // detail
            }   // commitments
        }   // zk
    }   // crypto3
}   // nil

#endif  // CRYPTO3_ZK_POWERS_OF_TAU_RESULT_HPP
