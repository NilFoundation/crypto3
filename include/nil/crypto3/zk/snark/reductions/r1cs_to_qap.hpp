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
// @file Declaration of interfaces for a R1CS-to-QAP reduction, that is, constructing
// a QAP ("Quadratic Arithmetic Program") from a R1CS ("Rank-1 Constraint System").
//
// QAPs are defined in \[GGPR13], and constructed for R1CS also in \[GGPR13].
//
// The implementation of the reduction follows, extends, and optimizes
// the efficient approach described in Appendix E of \[BCGTV13].
//
// References:
//
// \[BCGTV13]
// "SNARKs for C: Verifying Program Executions Succinctly and in Zero Knowledge",
// Eli Ben-Sasson, Alessandro Chiesa, Daniel Genkin, Eran Tromer, Madars Virza,
// CRYPTO 2013,
// <http://eprint.iacr.org/2013/507>
//
// \[GGPR13]:
// "Quadratic span programs and succinct NIZKs without PCPs",
// Rosario Gennaro, Craig Gentry, Bryan Parno, Mariana Raykova,
// EUROCRYPT 2013,
// <http://eprint.iacr.org/2012/215>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_R1CS_TO_QAP_BASIC_POLICY_HPP
#define CRYPTO3_ZK_R1CS_TO_QAP_BASIC_POLICY_HPP

#include <nil/crypto3/fft/coset.hpp>
#include <nil/crypto3/fft/domains/evaluation_domain.hpp>
#include <nil/crypto3/fft/make_evaluation_domain.hpp>

#include <nil/crypto3/zk/snark/relations/arithmetic_programs/qap.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace reductions {
                    template<typename FieldType>
                    struct r1cs_to_qap {
                        typedef FieldType field_type;

                        /**
                         * Instance map for the R1CS-to-QAP reduction.
                         *
                         * Namely, given a R1CS constraint system cs, construct a QAP instance for which:
                         *   A := (A_0(z),A_1(z),...,A_m(z))
                         *   B := (B_0(z),B_1(z),...,B_m(z))
                         *   C := (C_0(z),C_1(z),...,C_m(z))
                         * where
                         *   m = number of variables of the QAP
                         * and
                         *   each A_i,B_i,C_i is expressed in the Lagrange basis.
                         */
                        static qap_instance<FieldType> instance_map(const r1cs_constraint_system<FieldType> &cs) {

                            const std::shared_ptr<fft::evaluation_domain<FieldType>> domain =
                                fft::make_evaluation_domain<FieldType>(cs.num_constraints() + cs.num_inputs() + 1);

                            std::vector<std::map<std::size_t, typename FieldType::value_type>> A_in_Lagrange_basis(cs.num_variables() + 1);
                            std::vector<std::map<std::size_t, typename FieldType::value_type>> B_in_Lagrange_basis(cs.num_variables() + 1);
                            std::vector<std::map<std::size_t, typename FieldType::value_type>> C_in_Lagrange_basis(cs.num_variables() + 1);

                            /**
                             * add and process the constraints
                             *     input_i * 0 = 0
                             * to ensure soundness of input consistency
                             */
                            for (std::size_t i = 0; i <= cs.num_inputs(); ++i) {
                                A_in_Lagrange_basis[i][cs.num_constraints() + i] = FieldType::value_type::one();
                            }
                            /* process all other constraints */
                            for (std::size_t i = 0; i < cs.num_constraints(); ++i) {
                                for (std::size_t j = 0; j < cs.constraints[i].a.terms.size(); ++j) {
                                    A_in_Lagrange_basis[cs.constraints[i].a.terms[j].index][i] +=
                                        cs.constraints[i].a.terms[j].coeff;
                                }

                                for (std::size_t j = 0; j < cs.constraints[i].b.terms.size(); ++j) {
                                    B_in_Lagrange_basis[cs.constraints[i].b.terms[j].index][i] +=
                                        cs.constraints[i].b.terms[j].coeff;
                                }

                                for (std::size_t j = 0; j < cs.constraints[i].c.terms.size(); ++j) {
                                    C_in_Lagrange_basis[cs.constraints[i].c.terms[j].index][i] +=
                                        cs.constraints[i].c.terms[j].coeff;
                                }
                            }

                            return qap_instance<FieldType>(
                                domain, cs.num_variables(), domain->m, cs.num_inputs(), std::move(A_in_Lagrange_basis),
                                std::move(B_in_Lagrange_basis), std::move(C_in_Lagrange_basis));
                        }

                        /**
                         * Instance map for the R1CS-to-QAP reduction followed by evaluation of the resulting QAP
                         * instance.
                         *
                         * Namely, given a R1CS constraint system cs and a field element t, construct
                         * a QAP instance (evaluated at t) for which:
                         *   At := (A_0(t),A_1(t),...,A_m(t))
                         *   Bt := (B_0(t),B_1(t),...,B_m(t))
                         *   Ct := (C_0(t),C_1(t),...,C_m(t))
                         *   Ht := (1,t,t^2,...,t^n)
                         *   Zt := Z(t) = "vanishing polynomial of a certain set S, evaluated at t"
                         * where
                         *   m = number of variables of the QAP
                         *   n = degree of the QAP
                         */
                        static qap_instance_evaluation<FieldType>
                            instance_map_with_evaluation(const r1cs_constraint_system<FieldType> &cs,
                                                         const typename FieldType::value_type &t) {
                            const std::shared_ptr<fft::evaluation_domain<FieldType>> domain =
                                fft::make_evaluation_domain<FieldType>(cs.num_constraints() + cs.num_inputs() + 1);

                            std::vector<typename FieldType::value_type> At, Bt, Ct, Ht;

                            At.resize(cs.num_variables() + 1, FieldType::value_type::zero());
                            Bt.resize(cs.num_variables() + 1, FieldType::value_type::zero());
                            Ct.resize(cs.num_variables() + 1, FieldType::value_type::zero());
                            Ht.reserve(domain->m + 1);

                            const typename FieldType::value_type Zt = domain->compute_vanishing_polynomial(t);

                            const std::vector<typename FieldType::value_type> u =
                                domain->evaluate_all_lagrange_polynomials(t);
                            /**
                             * add and process the constraints
                             *     input_i * 0 = 0
                             * to ensure soundness of input consistency
                             */
                            for (std::size_t i = 0; i <= cs.num_inputs(); ++i) {
                                At[i] = u[cs.num_constraints() + i];
                            }
                            /* process all other constraints */
                            for (std::size_t i = 0; i < cs.num_constraints(); ++i) {
                                for (std::size_t j = 0; j < cs.constraints[i].a.terms.size(); ++j) {
                                    At[cs.constraints[i].a.terms[j].index] += u[i] * cs.constraints[i].a.terms[j].coeff;
                                }

                                for (std::size_t j = 0; j < cs.constraints[i].b.terms.size(); ++j) {
                                    Bt[cs.constraints[i].b.terms[j].index] += u[i] * cs.constraints[i].b.terms[j].coeff;
                                }

                                for (std::size_t j = 0; j < cs.constraints[i].c.terms.size(); ++j) {
                                    Ct[cs.constraints[i].c.terms[j].index] += u[i] * cs.constraints[i].c.terms[j].coeff;
                                }
                            }

                            typename FieldType::value_type ti = FieldType::value_type::one();
                            for (std::size_t i = 0; i < domain->m + 1; ++i) {
                                Ht.emplace_back(ti);
                                ti *= t;
                            }

                            return qap_instance_evaluation<FieldType>(domain, cs.num_variables(), domain->m,
                                                                      cs.num_inputs(), t, std::move(At), std::move(Bt),
                                                                      std::move(Ct), std::move(Ht), Zt);
                        }

                        /**
                         * Witness map for the R1CS-to-QAP reduction.
                         *
                         * The witness map takes zero knowledge into account when d1,d2,d3 are random.
                         *
                         * More precisely, compute the coefficients
                         *     h_0,h_1,...,h_n
                         * of the polynomial
                         *     H(z) := (A(z)*B(z)-C(z))/Z(z)
                         * where
                         *   A(z) := A_0(z) + \sum_{k=1}^{m} w_k A_k(z) + d1 * Z(z)
                         *   B(z) := B_0(z) + \sum_{k=1}^{m} w_k B_k(z) + d2 * Z(z)
                         *   C(z) := C_0(z) + \sum_{k=1}^{m} w_k C_k(z) + d3 * Z(z)
                         *   Z(z) := "vanishing polynomial of set S"
                         * and
                         *   m = number of variables of the QAP
                         *   n = degree of the QAP
                         *
                         * This is done as follows:
                         *  (1) compute evaluations of A,B,C on S = {sigma_1,...,sigma_n}
                         *  (2) compute coefficients of A,B,C
                         *  (3) compute evaluations of A,B,C on T = "coset of S"
                         *  (4) compute evaluation of H on T
                         *  (5) compute coefficients of H
                         *  (6) patch H to account for d1,d2,d3 (i.e., add coefficients of the polynomial (A d2 + B d1 -
                         * d3) + d1*d2*Z )
                         *
                         * The code below is not as simple as the above high-level description due to
                         * some reshuffling to save space.
                         */
                        static qap_witness<FieldType>
                            witness_map(const r1cs_constraint_system<FieldType> &cs,
                                        const r1cs_primary_input<FieldType> &primary_input,
                                        const r1cs_auxiliary_input<FieldType> &auxiliary_input,
                                        const typename FieldType::value_type &d1,
                                        const typename FieldType::value_type &d2,
                                        const typename FieldType::value_type &d3) {
                            /* sanity check */
                            assert(cs.is_satisfied(primary_input, auxiliary_input));

                            const std::shared_ptr<fft::evaluation_domain<FieldType>> domain =
                                fft::make_evaluation_domain<FieldType>(cs.num_constraints() + cs.num_inputs() + 1);

                            r1cs_variable_assignment<FieldType> full_variable_assignment = primary_input;
                            full_variable_assignment.insert(full_variable_assignment.end(), auxiliary_input.begin(),
                                                            auxiliary_input.end());

                            std::vector<typename FieldType::value_type> aA(domain->m, FieldType::value_type::zero()),
                                aB(domain->m, FieldType::value_type::zero());

                            /* account for the additional constraints input_i * 0 = 0 */
                            for (std::size_t i = 0; i <= cs.num_inputs(); ++i) {
                                aA[i + cs.num_constraints()] =
                                    (i > 0 ? full_variable_assignment[i - 1] : FieldType::value_type::one());
                            }
                            /* account for all other constraints */
                            for (std::size_t i = 0; i < cs.num_constraints(); ++i) {
                                aA[i] += cs.constraints[i].a.evaluate(full_variable_assignment);
                                aB[i] += cs.constraints[i].b.evaluate(full_variable_assignment);
                            }

                            domain->iFFT(aA);

                            domain->iFFT(aB);

                            std::vector<typename FieldType::value_type> coefficients_for_H(
                                domain->m + 1, FieldType::value_type::zero());
#ifdef MULTICORE
#pragma omp parallel for
#endif
                            /* add coefficients of the polynomial (d2*A + d1*B - d3) + d1*d2*Z */
                            for (std::size_t i = 0; i < domain->m; ++i) {
                                coefficients_for_H[i] = d2 * aA[i] + d1 * aB[i];
                            }
                            coefficients_for_H[0] -= d3;
                            domain->add_poly_Z(d1 * d2, coefficients_for_H);

                            fft::multiply_by_coset(aA,
                                                   typename FieldType::value_type(
                                                       fields::arithmetic_params<FieldType>::multiplicative_generator));
                            domain->FFT(aA);

                            fft::multiply_by_coset(aB,
                                                   typename FieldType::value_type(
                                                       fields::arithmetic_params<FieldType>::multiplicative_generator));
                            domain->FFT(aB);

                            std::vector<typename FieldType::value_type> &H_tmp = aA;
                            // can overwrite aA because it is not used later
#ifdef MULTICORE
#pragma omp parallel for
#endif
                            for (std::size_t i = 0; i < domain->m; ++i) {
                                H_tmp[i] = aA[i] * aB[i];
                            }
                            std::vector<typename FieldType::value_type>().swap(aB);    // destroy aB

                            std::vector<typename FieldType::value_type> aC(domain->m, FieldType::value_type::zero());
                            for (std::size_t i = 0; i < cs.num_constraints(); ++i) {
                                aC[i] += cs.constraints[i].c.evaluate(full_variable_assignment);
                            }

                            domain->iFFT(aC);

                            fft::multiply_by_coset(aC,
                                                   typename FieldType::value_type(
                                                       fields::arithmetic_params<FieldType>::multiplicative_generator));
                            domain->FFT(aC);

#ifdef MULTICORE
#pragma omp parallel for
#endif
                            for (std::size_t i = 0; i < domain->m; ++i) {
                                H_tmp[i] = (H_tmp[i] - aC[i]);
                            }

                            domain->divide_by_Z_on_coset(H_tmp);

                            domain->iFFT(H_tmp);

                            multiply_by_coset(H_tmp,
                                              typename FieldType::value_type(
                                                  fields::arithmetic_params<FieldType>::multiplicative_generator)
                                                  .inversed());
#ifdef MULTICORE
#pragma omp parallel for
#endif
                            for (std::size_t i = 0; i < domain->m; ++i) {
                                coefficients_for_H[i] += H_tmp[i];
                            }

                            return qap_witness<FieldType>(cs.num_variables(), domain->m, cs.num_inputs(), d1, d2, d3,
                                                          full_variable_assignment, std::move(coefficients_for_H));
                        }
                    };
                }    // namespace reductions
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_TO_QAP_BASIC_POLICY_HPP
