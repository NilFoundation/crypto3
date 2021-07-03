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
// @file Declaration of interfaces for a USCS-to-SSP reduction, that is, constructing
// a SSP ("Square Span Program") from a USCS ("boolean circuit with 2-input gates").
//
// SSPs are defined in \[DFGK14], and constructed for USCS also in \[DFGK14].
//
// The implementation of the reduction adapts to \[DFGK14], extends, and optimizes
// the efficient QAP-based approach described in Appendix E of \[BCGTV13].
//
// References:
//
// \[BCGTV13]
// "SNARKs for C: Verifying Program Executions Succinctly and in Zero Knowledge",
// Eli Ben-Sasson, Alessandro Chiesa, Daniel Genkin, Eran Tromer, Madars Virza,
// CRYPTO 2013,
// <http://eprint.iacr.org/2013/507>
//
// \[DFGK14]:
// "Square Span Programs with Applications to Succinct NIZK Arguments"
// George Danezis, Cedric Fournet, Jens Groth, Markulf Kohlweiss,
// ASIACRYPT 2014,
// <http://eprint.iacr.org/2014/718>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_USCS_TO_SSP_REDUCTION_HPP
#define CRYPTO3_ZK_USCS_TO_SSP_REDUCTION_HPP

#include <nil/crypto3/fft/coset.hpp>
#include <nil/crypto3/fft/domains/evaluation_domain.hpp>
#include <nil/crypto3/fft/make_evaluation_domain.hpp>

#include <nil/crypto3/zk/snark/relations/arithmetic_programs/ssp.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace reductions {
                    template<typename FieldType>
                    struct uscs_to_ssp {
                        typedef FieldType field_type;

                        /**
                         * Instance map for the USCS-to-SSP reduction.
                         *
                         * Namely, given a USCS constraint system cs, construct a SSP instance for which:
                         *   V := (V_0(z),V_1(z),...,V_m(z))
                         * where
                         *   m = number of variables of the SSP
                         * and
                         *   each V_i is expressed in the Lagrange basis.
                         */
                        static ssp_instance<FieldType> instance_map(const uscs_constraint_system<FieldType> &cs) {
                            const std::shared_ptr<evaluation_domain<FieldType>> domain =
                                fft::make_evaluation_domain<FieldType>(cs.num_constraints());
                            std::vector<std::map<std::size_t, typename FieldType::value_type>> V_in_Lagrange_basis(cs.num_variables() + 1);
                            for (std::size_t i = 0; i < cs.num_constraints(); ++i) {
                                for (std::size_t j = 0; j < cs.constraints[i].terms.size(); ++j) {
                                    V_in_Lagrange_basis[cs.constraints[i].terms[j].index][i] +=
                                        cs.constraints[i].terms[j].coeff;
                                }
                            }
                            for (std::size_t i = cs.num_constraints(); i < domain->m; ++i) {
                                V_in_Lagrange_basis[0][i] += FieldType::value_type::one();
                            }

                            return ssp_instance<FieldType>(
                                domain, cs.num_variables(), domain->m, cs.num_inputs(), std::move(V_in_Lagrange_basis));
                        }

                        /**
                         * Instance map for the USCS-to-SSP reduction followed by evaluation of the resulting SSP
                         * instance.
                         *
                         * Namely, given a USCS constraint system cs and a field element t, construct
                         * a SSP instance (evaluated at t) for which:
                         *   Vt := (V_0(t),V_1(t),...,V_m(t))
                         *   Ht := (1,t,t^2,...,t^n)
                         *   Zt := Z(t) = "vanishing polynomial of a certain set S, evaluated at t"
                         * where
                         *   m = number of variables of the SSP
                         *   n = degree of the SSP
                         */
                        static ssp_instance_evaluation<FieldType>
                            instance_map_with_evaluation(const uscs_constraint_system<FieldType> &cs,
                                                         const typename FieldType::value_type &t) {
                            const std::shared_ptr<evaluation_domain<FieldType>> domain =
                                fft::make_evaluation_domain<FieldType>(cs.num_constraints());

                            std::vector<typename FieldType::value_type> Vt(cs.num_variables() + 1,
                                                                           FieldType::value_type::zero());
                            std::vector<typename FieldType::value_type> Ht(domain->m + 1);

                            const typename FieldType::value_type Zt = domain->compute_vanishing_polynomial(t);

                            const std::vector<typename FieldType::value_type> u =
                                domain->evaluate_all_lagrange_polynomials(t);
                            for (std::size_t i = 0; i < cs.num_constraints(); ++i) {
                                for (std::size_t j = 0; j < cs.constraints[i].terms.size(); ++j) {
                                    Vt[cs.constraints[i].terms[j].index] += u[i] * cs.constraints[i].terms[j].coeff;
                                }
                            }
                            for (std::size_t i = cs.num_constraints(); i < domain->m; ++i) {
                                Vt[0] += u[i]; /* dummy constraint: 1^2 = 1 */
                            }
                            typename FieldType::value_type ti = FieldType::value_type::one();
                            for (std::size_t i = 0; i < domain->m + 1; ++i) {
                                Ht[i] = ti;
                                ti *= t;
                            }

                            return ssp_instance_evaluation<FieldType>(domain,
                                                                      cs.num_variables(),
                                                                      domain->m,
                                                                      cs.num_inputs(),
                                                                      t,
                                                                      std::move(Vt),
                                                                      std::move(Ht),
                                                                      Zt);
                        }

                        /**
                         * Witness map for the USCS-to-SSP reduction.
                         *
                         * The witness map takes zero knowledge into account when d is random.
                         *
                         * More precisely, compute the coefficients
                         *     h_0,h_1,...,h_n
                         * of the polynomial
                         *     H(z) := (V(z)^2-1)/Z(z)
                         * where
                         *   V(z) := V_0(z) + \sum_{k=1}^{m} w_k V_k(z) + d * Z(z)
                         *   Z(z) := "vanishing polynomial of set S"
                         * and
                         *   m = number of variables of the SSP
                         *   n = degree of the SSP
                         *
                         * This is done as follows:
                         *  (1) compute evaluations of V on S = {sigma_1,...,sigma_n}
                         *  (2) compute coefficients of V
                         *  (3) compute evaluations of V on T = "coset of S"
                         *  (4) compute evaluation of H on T
                         *  (5) compute coefficients of H
                         *  (6) patch H to account for d (i.e., add coefficients of the polynomial 2*d*V(z) + d*d*Z(z) )
                         *
                         * The code below is not as simple as the above high-level description due to
                         * some reshuffling to save space.
                         */
                        static ssp_witness<FieldType> witness_map(const uscs_constraint_system<FieldType> &cs,
                                                           const uscs_primary_input<FieldType> &primary_input,
                                                           const uscs_auxiliary_input<FieldType> &auxiliary_input,
                                                           const typename FieldType::value_type &d) {
                            /* sanity check */

                            assert(cs.is_satisfied(primary_input, auxiliary_input));

                            uscs_variable_assignment<FieldType> full_variable_assignment = primary_input;
                            full_variable_assignment.insert(
                                full_variable_assignment.end(), auxiliary_input.begin(), auxiliary_input.end());

                            const std::shared_ptr<evaluation_domain<FieldType>> domain =
                                make_evaluation_domain<FieldType>(cs.num_constraints());

                            std::vector<typename FieldType::value_type> aA(domain->m, FieldType::value_type::zero());
                            assert(domain->m >= cs.num_constraints());
                            for (std::size_t i = 0; i < cs.num_constraints(); ++i) {
                                aA[i] += cs.constraints[i].evaluate(full_variable_assignment);
                            }
                            for (std::size_t i = cs.num_constraints(); i < domain->m; ++i) {
                                aA[i] += FieldType::value_type::one();
                            }

                            domain->iFFT(aA);

                            std::vector<typename FieldType::value_type> coefficients_for_H(
                                domain->m + 1, FieldType::value_type::zero());
#ifdef MULTICORE
#pragma omp parallel for
#endif
                            /* add coefficients of the polynomial 2*d*V(z) + d*d*Z(z) */
                            for (std::size_t i = 0; i < domain->m; ++i) {
                                coefficients_for_H[i] = typename FieldType::value_type(2) * d * aA[i];
                            }
                            domain->add_poly_Z(d.squared(), coefficients_for_H);

                            fft::multiply_by_coset(aA,
                                                   typename FieldType::value_type(
                                                       fields::arithmetic_params<FieldType>::multiplicative_generator));
                            domain->FFT(aA);

                            std::vector<typename FieldType::value_type> &H_tmp =
                                aA;    // can overwrite aA because it is not used later
#ifdef MULTICORE
#pragma omp parallel for
#endif
                            for (std::size_t i = 0; i < domain->m; ++i) {
                                H_tmp[i] = aA[i].squared() - FieldType::value_type::one();
                            }

                            domain->divide_by_Z_on_coset(H_tmp);

                            domain->iFFT(H_tmp);
                            multiply_by_coset(H_tmp, typename FieldType::value_type(fields::arithmetic_params<FieldType>::multiplicative_generator).inversed());

#ifdef MULTICORE
#pragma omp parallel for
#endif
                            for (std::size_t i = 0; i < domain->m; ++i) {
                                coefficients_for_H[i] += H_tmp[i];
                            }

                            return ssp_witness<FieldType>(cs.num_variables(),
                                                          domain->m,
                                                          cs.num_inputs(),
                                                          d,
                                                          full_variable_assignment,
                                                          std::move(coefficients_for_H));
                        }
                    };
                }    // namespace reductions
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_USCS_TO_SSP_BASIC_POLICY_HPP
