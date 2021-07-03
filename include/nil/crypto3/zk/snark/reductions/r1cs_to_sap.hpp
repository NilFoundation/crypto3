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
// @file Declaration of interfaces for a R1CS-to-SAP reduction, that is, constructing
// a SAP ("Square Arithmetic Program") from a R1CS ("Rank-1 Constraint System").
//
// SAPs are defined and constructed from R1CS in \[GM17].
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
// \[GM17]:
// "Snarky Signatures: Minimal Signatures of Knowledge from
//  Simulation-Extractable SNARKs",
// Jens Groth and Mary Maller,
// IACR-CRYPTO-2017,
// <https://eprint.iacr.org/2017/540>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_R1CS_TO_SAP_BASIC_POLICY_HPP
#define CRYPTO3_ZK_R1CS_TO_SAP_BASIC_POLICY_HPP

#include <nil/crypto3/fft/coset.hpp>
#include <nil/crypto3/fft/domains/evaluation_domain.hpp>
#include <nil/crypto3/fft/make_evaluation_domain.hpp>

#include <nil/crypto3/zk/snark/relations/arithmetic_programs/sap.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace reductions {
                    template<typename FieldType>
                    class r1cs_to_sap {
                        typedef FieldType field_type;

                        /**
                         * Helper function to multiply a field element by 4 efficiently
                         */
                        static typename FieldType::value_type times_four(typename FieldType::value_type x) {
                            typename FieldType::value_type times_two = x + x;
                            return times_two + times_two;
                        }

                    public:
                        /**
                         * Helper function to find evaluation domain that will be used by the reduction
                         * for a given R1CS instance.
                         */
                        static std::shared_ptr<fft::evaluation_domain<FieldType>>
                            get_domain(const r1cs_constraint_system<FieldType> &cs) {
                            /*
                             * the SAP instance will have:
                             * - two constraints for every constraint in the original constraint system
                             * - two constraints for every public input, except the 0th, which
                             *   contributes just one extra constraint
                             * see comments in instance_map for details on where these
                             * constraints come from.
                             */
                            return fft::make_evaluation_domain<FieldType>(2 * cs.num_constraints() +
                                                                          2 * cs.num_inputs() + 1);
                        }

                        /**
                         * Instance map for the R1CS-to-SAP reduction.
                         */
                        static sap_instance<FieldType> instance_map(const r1cs_constraint_system<FieldType> &cs) {
                            const std::shared_ptr<fft::evaluation_domain<FieldType>> domain = get_domain(cs);

                            std::size_t sap_num_variables = cs.num_variables() + cs.num_constraints() + cs.num_inputs();

                            std::vector<std::map<std::size_t, typename FieldType::value_type>> A_in_Lagrange_basis(sap_num_variables + 1);
                            std::vector<std::map<std::size_t, typename FieldType::value_type>> C_in_Lagrange_basis(sap_num_variables + 1);

                            /**
                             * process R1CS constraints, converting a constraint of the form
                             *   \sum a_i x_i * \sum b_i x_i = \sum c_i x_i
                             * into two constraints
                             *   (\sum (a_i + b_i) x_i)^2 = 4 \sum c_i x_i + x'_i
                             *   (\sum (a_i - b_i) x_i)^2 = x'_i
                             * where x'_i is an extra variable (a separate one for each original
                             * constraint)
                             *
                             * this adds 2 * cs.num_constraints() constraints
                             *   (numbered 0 .. 2 * cs.num_constraints() - 1)
                             * and cs.num_constraints() extra variables
                             *   (numbered cs.num_variables() + 1 .. cs.num_variables() + cs.num_constraints())
                             */
                            std::size_t extra_var_offset = cs.num_variables() + 1;
                            for (std::size_t i = 0; i < cs.num_constraints(); ++i) {
                                for (std::size_t j = 0; j < cs.constraints[i].a.terms.size(); ++j) {
                                    A_in_Lagrange_basis[cs.constraints[i].a.terms[j].index][2 * i] +=
                                        cs.constraints[i].a.terms[j].coeff;
                                    A_in_Lagrange_basis[cs.constraints[i].a.terms[j].index][2 * i + 1] +=
                                        cs.constraints[i].a.terms[j].coeff;
                                }

                                for (std::size_t j = 0; j < cs.constraints[i].b.terms.size(); ++j) {
                                    A_in_Lagrange_basis[cs.constraints[i].b.terms[j].index][2 * i] +=
                                        cs.constraints[i].b.terms[j].coeff;
                                    A_in_Lagrange_basis[cs.constraints[i].b.terms[j].index][2 * i + 1] -=
                                        cs.constraints[i].b.terms[j].coeff;
                                }

                                for (std::size_t j = 0; j < cs.constraints[i].c.terms.size(); ++j) {
                                    C_in_Lagrange_basis[cs.constraints[i].c.terms[j].index][2 * i] +=
                                        times_four(cs.constraints[i].c.terms[j].coeff);
                                }

                                C_in_Lagrange_basis[extra_var_offset + i][2 * i] += FieldType::value_type::one();
                                C_in_Lagrange_basis[extra_var_offset + i][2 * i + 1] += FieldType::value_type::one();
                            }

                            /**
                             * add and convert the extra constraints
                             *     x_i * 1 = x_i
                             * to ensure that the polynomials 0 .. cs.num_inputs() are linearly
                             * independent from each other and the rest, which is required for security
                             * proofs (see [GM17, p. 29])
                             *
                             * note that i = 0 is a special case, where this constraint is expressible
                             * as x_0^2 = x_0,
                             * whereas for every other i we introduce an extra variable x''_i and do
                             *   (x_i + x_0)^2 = 4 x_i + x''_i
                             *   (x_i - x_0)^2 = x''_i
                             *
                             * this adds 2 * cs.num_inputs() + 1 extra constraints
                             *   (numbered 2 * cs.num_constraints() ..
                             *             2 * cs.num_constraints() + 2 * cs.num_inputs())
                             * and cs.num_inputs() extra variables
                             *   (numbered cs.num_variables() + cs.num_constraints() + 1 ..
                             *             cs.num_variables() + cs.num_constraints() + cs.num_inputs())
                             */

                            std::size_t extra_constr_offset = 2 * cs.num_constraints();
                            std::size_t extra_var_offset2 = cs.num_variables() + cs.num_constraints();
                            /**
                             * NB: extra variables start at (extra_var_offset2 + 1), because i starts at
                             *     1 below
                             */

                            A_in_Lagrange_basis[0][extra_constr_offset] = FieldType::value_type::one();
                            C_in_Lagrange_basis[0][extra_constr_offset] = FieldType::value_type::one();

                            for (std::size_t i = 1; i <= cs.num_inputs(); ++i) {
                                A_in_Lagrange_basis[i][extra_constr_offset + 2 * i - 1] +=
                                    FieldType::value_type::one();
                                A_in_Lagrange_basis[0][extra_constr_offset + 2 * i - 1] +=
                                    FieldType::value_type::one();
                                C_in_Lagrange_basis[i][extra_constr_offset + 2 * i - 1] +=
                                    times_four(FieldType::value_type::one());
                                C_in_Lagrange_basis[extra_var_offset2 + i][extra_constr_offset + 2 * i - 1] +=
                                    FieldType::value_type::one();

                                A_in_Lagrange_basis[i][extra_constr_offset + 2 * i] += FieldType::value_type::one();
                                A_in_Lagrange_basis[0][extra_constr_offset + 2 * i] -= FieldType::value_type::one();
                                C_in_Lagrange_basis[extra_var_offset2 + i][2 * cs.num_constraints() + 2 * i] +=
                                    FieldType::value_type::one();
                            }

                            return sap_instance<FieldType>(domain,
                                                           sap_num_variables,
                                                           domain->m,
                                                           cs.num_inputs(),
                                                           std::move(A_in_Lagrange_basis),
                                                           std::move(C_in_Lagrange_basis));
                        }

                        /**
                         * Instance map for the R1CS-to-SAP reduction followed by evaluation
                         * of the resulting QAP instance.
                         */
                        static sap_instance_evaluation<FieldType>
                            instance_map_with_evaluation(const r1cs_constraint_system<FieldType> &cs,
                                                         const typename FieldType::value_type &t) {

                            const std::shared_ptr<fft::evaluation_domain<FieldType>> domain = get_domain(cs);

                            std::size_t sap_num_variables = cs.num_variables() + cs.num_constraints() + cs.num_inputs();

                            std::vector<typename FieldType::value_type> At, Ct, Ht;

                            At.resize(sap_num_variables + 1, FieldType::value_type::zero());
                            Ct.resize(sap_num_variables + 1, FieldType::value_type::zero());
                            Ht.reserve(domain->m + 1);

                            const typename FieldType::value_type Zt = domain->compute_vanishing_polynomial(t);

                            const std::vector<typename FieldType::value_type> u =
                                domain->evaluate_all_lagrange_polynomials(t);
                            /**
                             * add and process all constraints as in instance_map
                             */
                            std::size_t extra_var_offset = cs.num_variables() + 1;
                            for (std::size_t i = 0; i < cs.num_constraints(); ++i) {
                                for (std::size_t j = 0; j < cs.constraints[i].a.terms.size(); ++j) {
                                    At[cs.constraints[i].a.terms[j].index] +=
                                        u[2 * i] * cs.constraints[i].a.terms[j].coeff;
                                    At[cs.constraints[i].a.terms[j].index] +=
                                        u[2 * i + 1] * cs.constraints[i].a.terms[j].coeff;
                                }

                                for (std::size_t j = 0; j < cs.constraints[i].b.terms.size(); ++j) {
                                    At[cs.constraints[i].b.terms[j].index] +=
                                        u[2 * i] * cs.constraints[i].b.terms[j].coeff;
                                    At[cs.constraints[i].b.terms[j].index] -=
                                        u[2 * i + 1] * cs.constraints[i].b.terms[j].coeff;
                                }

                                for (std::size_t j = 0; j < cs.constraints[i].c.terms.size(); ++j) {
                                    Ct[cs.constraints[i].c.terms[j].index] +=
                                        times_four(u[2 * i] * cs.constraints[i].c.terms[j].coeff);
                                }

                                Ct[extra_var_offset + i] += u[2 * i];
                                Ct[extra_var_offset + i] += u[2 * i + 1];
                            }

                            std::size_t extra_constr_offset = 2 * cs.num_constraints();
                            std::size_t extra_var_offset2 = cs.num_variables() + cs.num_constraints();

                            At[0] += u[extra_constr_offset];
                            Ct[0] += u[extra_constr_offset];

                            for (std::size_t i = 1; i <= cs.num_inputs(); ++i) {
                                At[i] += u[extra_constr_offset + 2 * i - 1];
                                At[0] += u[extra_constr_offset + 2 * i - 1];
                                Ct[i] += times_four(u[extra_constr_offset + 2 * i - 1]);
                                Ct[extra_var_offset2 + i] += u[extra_constr_offset + 2 * i - 1];

                                At[i] += u[extra_constr_offset + 2 * i];
                                At[0] -= u[extra_constr_offset + 2 * i];
                                Ct[extra_var_offset2 + i] += u[extra_constr_offset + 2 * i];
                            }

                            typename FieldType::value_type ti = FieldType::value_type::one();
                            for (std::size_t i = 0; i < domain->m + 1; ++i) {
                                Ht.emplace_back(ti);
                                ti *= t;
                            }

                            return sap_instance_evaluation<FieldType>(domain,
                                                                      sap_num_variables,
                                                                      domain->m,
                                                                      cs.num_inputs(),
                                                                      t,
                                                                      std::move(At),
                                                                      std::move(Ct),
                                                                      std::move(Ht),
                                                                      Zt);
                        }

                        /**
                         * Witness map for the R1CS-to-SAP reduction.
                         *
                         * The witness map takes zero knowledge into account when d1, d2 are random.
                         *
                         * More precisely, compute the coefficients
                         *     h_0,h_1,...,h_n
                         * of the polynomial
                         *     H(z) := (A(z)*A(z)-C(z))/Z(z)
                         * where
                         *   A(z) := A_0(z) + \sum_{k=1}^{m} w_k A_k(z) + d1 * Z(z)
                         *   C(z) := C_0(z) + \sum_{k=1}^{m} w_k C_k(z) + d2 * Z(z)
                         *   Z(z) := "vanishing polynomial of set S"
                         * and
                         *   m = number of variables of the SAP
                         *   n = degree of the SAP
                         *
                         * This is done as follows:
                         *  (1) compute evaluations of A,C on S = {sigma_1,...,sigma_n}
                         *  (2) compute coefficients of A,C
                         *  (3) compute evaluations of A,C on T = "coset of S"
                         *  (4) compute evaluation of H on T
                         *  (5) compute coefficients of H
                         *  (6) patch H to account for d1,d2
                                (i.e., add coefficients of the polynomial (2*d1*A - d2 + d1^2 * Z))
                         *
                         * The code below is not as simple as the above high-level description due to
                         * some reshuffling to save space.
                         */
                        static sap_witness<FieldType>
                            witness_map(const r1cs_constraint_system<FieldType> &cs,
                                        const r1cs_primary_input<FieldType> &primary_input,
                                        const r1cs_auxiliary_input<FieldType> &auxiliary_input,
                                        const typename FieldType::value_type &d1,
                                        const typename FieldType::value_type &d2) {
                            /* sanity check */
                            assert(cs.is_satisfied(primary_input, auxiliary_input));

                            const std::shared_ptr<fft::evaluation_domain<FieldType>> domain = get_domain(cs);

                            std::size_t sap_num_variables = cs.num_variables() + cs.num_constraints() + cs.num_inputs();

                            r1cs_variable_assignment<FieldType> full_variable_assignment = primary_input;
                            full_variable_assignment.insert(
                                full_variable_assignment.end(), auxiliary_input.begin(), auxiliary_input.end());
                            /**
                             * we need to generate values of all the extra variables that we added
                             * during the reduction
                             *
                             * note: below, we pass full_variable_assignment into the .evaluate()
                             * method of the R1CS constraints. however, these extra variables shouldn't
                             * be a problem, because .evaluate() only accesses the variables that are
                             * actually used in the constraint.
                             */
                            for (std::size_t i = 0; i < cs.num_constraints(); ++i) {
                                /**
                                 * this is variable (extra_var_offset + i), an extra variable
                                 * we introduced that is not present in the input.
                                 * its value is (a - b)^2
                                 */
                                typename FieldType::value_type extra_var =
                                    cs.constraints[i].a.evaluate(full_variable_assignment) -
                                    cs.constraints[i].b.evaluate(full_variable_assignment);
                                extra_var = extra_var * extra_var;
                                full_variable_assignment.push_back(extra_var);
                            }
                            for (std::size_t i = 1; i <= cs.num_inputs(); ++i) {
                                /**
                                 * this is variable (extra_var_offset2 + i), an extra variable
                                 * we introduced that is not present in the input.
                                 * its value is (x_i - 1)^2
                                 */
                                typename FieldType::value_type extra_var =
                                    full_variable_assignment[i - 1] - FieldType::value_type::one();
                                extra_var = extra_var * extra_var;
                                full_variable_assignment.push_back(extra_var);
                            }

                            std::vector<typename FieldType::value_type> aA(domain->m, FieldType::value_type::zero());

                            /* account for all constraints, as in instance_map */
                            for (std::size_t i = 0; i < cs.num_constraints(); ++i) {
                                aA[2 * i] += cs.constraints[i].a.evaluate(full_variable_assignment);
                                aA[2 * i] += cs.constraints[i].b.evaluate(full_variable_assignment);

                                aA[2 * i + 1] += cs.constraints[i].a.evaluate(full_variable_assignment);
                                aA[2 * i + 1] -= cs.constraints[i].b.evaluate(full_variable_assignment);
                            }

                            std::size_t extra_constr_offset = 2 * cs.num_constraints();

                            aA[extra_constr_offset] += FieldType::value_type::one();

                            for (std::size_t i = 1; i <= cs.num_inputs(); ++i) {
                                aA[extra_constr_offset + 2 * i - 1] += full_variable_assignment[i - 1];
                                aA[extra_constr_offset + 2 * i - 1] += FieldType::value_type::one();

                                aA[extra_constr_offset + 2 * i] += full_variable_assignment[i - 1];
                                aA[extra_constr_offset + 2 * i] -= FieldType::value_type::one();
                            }

                            domain->iFFT(aA);

                            std::vector<typename FieldType::value_type> coefficients_for_H(
                                domain->m + 1, FieldType::value_type::zero());
#ifdef MULTICORE
#pragma omp parallel for
#endif
                            /* add coefficients of the polynomial (2*d1*A - d2) + d1*d1*Z */
                            for (std::size_t i = 0; i < domain->m; ++i) {
                                coefficients_for_H[i] = (d1 * aA[i]) + (d1 * aA[i]);
                            }
                            coefficients_for_H[0] -= d2;
                            domain->add_poly_Z(d1 * d1, coefficients_for_H);

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
                                H_tmp[i] = aA[i] * aA[i];
                            }

                            std::vector<typename FieldType::value_type> aC(domain->m, FieldType::value_type::zero());
                            /* again, accounting for all constraints */
                            std::size_t extra_var_offset = cs.num_variables() + 1;
                            for (std::size_t i = 0; i < cs.num_constraints(); ++i) {
                                aC[2 * i] += times_four(cs.constraints[i].c.evaluate(full_variable_assignment));

                                aC[2 * i] += full_variable_assignment[extra_var_offset + i - 1];
                                aC[2 * i + 1] += full_variable_assignment[extra_var_offset + i - 1];
                            }

                            std::size_t extra_var_offset2 = cs.num_variables() + cs.num_constraints();
                            aC[extra_constr_offset] += FieldType::value_type::one();

                            for (std::size_t i = 1; i <= cs.num_inputs(); ++i) {
                                aC[extra_constr_offset + 2 * i - 1] += times_four(full_variable_assignment[i - 1]);

                                aC[extra_constr_offset + 2 * i - 1] +=
                                    full_variable_assignment[extra_var_offset2 + i - 1];
                                aC[extra_constr_offset + 2 * i] += full_variable_assignment[extra_var_offset2 + i - 1];
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

                            return sap_witness<FieldType>(sap_num_variables,
                                                          domain->m,
                                                          cs.num_inputs(),
                                                          d1,
                                                          d2,
                                                          full_variable_assignment,
                                                          std::move(coefficients_for_H));
                        }
                    };
                }    // namespace reductions
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_TO_SAP_BASIC_POLICY_HPP
