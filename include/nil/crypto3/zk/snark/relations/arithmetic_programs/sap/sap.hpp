//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a SAP ("Square Arithmetic Program").
//
// SAPs are defined in \[GM17].
//
// References:
//
// \[GM17]:
// "Snarky Signatures: Minimal Signatures of Knowledge from
//  Simulation-Extractable SNARKs",
// Jens Groth and Mary Maller,
// IACR-CRYPTO-2017,
// <https://eprint.iacr.org/2017/540>
//---------------------------------------------------------------------------//

#ifndef SAP_HPP_
#define SAP_HPP_

#include <map>
#include <memory>

#include <nil/algebra/scalar_multiplication/multiexp.hpp>
#include <nil/algebra/fft/evaluation_domain.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /* forward declaration */
                template<typename FieldType>
                class sap_witness;

                /**
                 * A SAP instance.
                 *
                 * Specifically, the datastructure stores:
                 * - a choice of domain (corresponding to a certain subset of the field);
                 * - the number of variables, the degree, and the number of inputs; and
                 * - coefficients of the A,C polynomials in the Lagrange basis.
                 *
                 * There is no need to store the Z polynomial because it is uniquely
                 * determined by the domain (as Z is its vanishing polynomial).
                 */
                template<typename FieldType>
                class sap_instance {
                private:
                    std::size_t num_variables_;
                    std::size_t degree_;
                    std::size_t num_inputs_;

                public:
                    std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> domain;

                    std::vector<std::map<std::size_t, FieldType>> A_in_Lagrange_basis;
                    std::vector<std::map<std::size_t, FieldType>> C_in_Lagrange_basis;

                    sap_instance(const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                                 const std::size_t num_variables,
                                 const std::size_t degree,
                                 const std::size_t num_inputs,
                                 const std::vector<std::map<std::size_t, FieldType>> &A_in_Lagrange_basis,
                                 const std::vector<std::map<std::size_t, FieldType>> &C_in_Lagrange_basis);

                    sap_instance(const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                                 const std::size_t num_variables,
                                 const std::size_t degree,
                                 const std::size_t num_inputs,
                                 std::vector<std::map<std::size_t, FieldType>> &&A_in_Lagrange_basis,
                                 std::vector<std::map<std::size_t, FieldType>> &&C_in_Lagrange_basis);

                    sap_instance(const sap_instance<FieldType> &other) = default;
                    sap_instance(sap_instance<FieldType> &&other) = default;
                    sap_instance &operator=(const sap_instance<FieldType> &other) = default;
                    sap_instance &operator=(sap_instance<FieldType> &&other) = default;

                    std::size_t num_variables() const;
                    std::size_t degree() const;
                    std::size_t num_inputs() const;

                    bool is_satisfied(const sap_witness<FieldType> &witness) const;
                };

                /**
                 * A SAP instance evaluation is a SAP instance that is evaluated at a field element t.
                 *
                 * Specifically, the datastructure stores:
                 * - a choice of domain (corresponding to a certain subset of the field);
                 * - the number of variables, the degree, and the number of inputs;
                 * - a field element t;
                 * - evaluations of the A,C (and Z) polynomials at t;
                 * - evaluations of all monomials of t;
                 * - counts about how many of the above evaluations are in fact non-zero.
                 */
                template<typename FieldType>
                class sap_instance_evaluation {
                private:
                    std::size_t num_variables_;
                    std::size_t degree_;
                    std::size_t num_inputs_;

                public:
                    std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> domain;

                    FieldType t;

                    std::vector<typename FieldType::value_type> At, Ct, Ht;

                    FieldType Zt;

                    sap_instance_evaluation(const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                                            const std::size_t num_variables,
                                            const std::size_t degree,
                                            const std::size_t num_inputs,
                                            const FieldType &t,
                                            const std::vector<typename FieldType::value_type> &At,
                                            const std::vector<typename FieldType::value_type> &Ct,
                                            const std::vector<typename FieldType::value_type> &Ht,
                                            const FieldType &Zt);
                    sap_instance_evaluation(const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                                            const std::size_t num_variables,
                                            const std::size_t degree,
                                            const std::size_t num_inputs,
                                            const FieldType &t,
                                            std::vector<typename FieldType::value_type> &&At,
                                            std::vector<typename FieldType::value_type> &&Ct,
                                            std::vector<typename FieldType::value_type> &&Ht,
                                            const FieldType &Zt);

                    sap_instance_evaluation(const sap_instance_evaluation<FieldType> &other) = default;
                    sap_instance_evaluation(sap_instance_evaluation<FieldType> &&other) = default;
                    sap_instance_evaluation &operator=(const sap_instance_evaluation<FieldType> &other) = default;
                    sap_instance_evaluation &operator=(sap_instance_evaluation<FieldType> &&other) = default;

                    std::size_t num_variables() const;
                    std::size_t degree() const;
                    std::size_t num_inputs() const;

                    bool is_satisfied(const sap_witness<FieldType> &witness) const;
                };

                /**
                 * A SAP witness.
                 */
                template<typename FieldType>
                class sap_witness {
                private:
                    std::size_t num_variables_;
                    std::size_t degree_;
                    std::size_t num_inputs_;

                public:
                    FieldType d1, d2;

                    std::vector<typename FieldType::value_type> coefficients_for_ACs;
                    std::vector<typename FieldType::value_type> coefficients_for_H;

                    sap_witness(const std::size_t num_variables,
                                const std::size_t degree,
                                const std::size_t num_inputs,
                                const FieldType &d1,
                                const FieldType &d2,
                                const std::vector<typename FieldType::value_type> &coefficients_for_ACs,
                                const std::vector<typename FieldType::value_type> &coefficients_for_H);

                    sap_witness(const std::size_t num_variables,
                                const std::size_t degree,
                                const std::size_t num_inputs,
                                const FieldType &d1,
                                const FieldType &d2,
                                const std::vector<typename FieldType::value_type> &coefficients_for_ACs,
                                std::vector<typename FieldType::value_type> &&coefficients_for_H);

                    sap_witness(const sap_witness<FieldType> &other) = default;
                    sap_witness(sap_witness<FieldType> &&other) = default;
                    sap_witness &operator=(const sap_witness<FieldType> &other) = default;
                    sap_witness &operator=(sap_witness<FieldType> &&other) = default;

                    std::size_t num_variables() const;
                    std::size_t degree() const;
                    std::size_t num_inputs() const;
                };

                template<typename FieldType>
                sap_instance<FieldType>::sap_instance(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    const std::vector<std::map<std::size_t, FieldType>> &A_in_Lagrange_basis,
                    const std::vector<std::map<std::size_t, FieldType>> &C_in_Lagrange_basis) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain), A_in_Lagrange_basis(A_in_Lagrange_basis),
                    C_in_Lagrange_basis(C_in_Lagrange_basis) {
                }

                template<typename FieldType>
                sap_instance<FieldType>::sap_instance(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    std::vector<std::map<std::size_t, FieldType>> &&A_in_Lagrange_basis,
                    std::vector<std::map<std::size_t, FieldType>> &&C_in_Lagrange_basis) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain),
                    A_in_Lagrange_basis(std::move(A_in_Lagrange_basis)),
                    C_in_Lagrange_basis(std::move(C_in_Lagrange_basis)) {
                }

                template<typename FieldType>
                std::size_t sap_instance<FieldType>::num_variables() const {
                    return num_variables_;
                }

                template<typename FieldType>
                std::size_t sap_instance<FieldType>::degree() const {
                    return degree_;
                }

                template<typename FieldType>
                std::size_t sap_instance<FieldType>::num_inputs() const {
                    return num_inputs_;
                }

                template<typename FieldType>
                bool sap_instance<FieldType>::is_satisfied(const sap_witness<FieldType> &witness) const {
                    const typename FieldType t = random_element<FieldType>();

                    std::vector<typename FieldType::value_type> At(this->num_variables() + 1, FieldType::value_type::zero());
                    std::vector<typename FieldType::value_type> Ct(this->num_variables() + 1, FieldType::value_type::zero());
                    std::vector<typename FieldType::value_type> Ht(this->degree() + 1);

                    const FieldType Zt = this->domain->compute_vanishing_polynomial(t);

                    const std::vector<typename FieldType::value_type> u = this->domain->evaluate_all_lagrange_polynomials(t);

                    for (std::size_t i = 0; i < this->num_variables() + 1; ++i) {
                        for (auto &el : A_in_Lagrange_basis[i]) {
                            At[i] += u[el.first] * el.second;
                        }

                        for (auto &el : C_in_Lagrange_basis[i]) {
                            Ct[i] += u[el.first] * el.second;
                        }
                    }

                    FieldType ti = FieldType::one();
                    for (std::size_t i = 0; i < this->degree() + 1; ++i) {
                        Ht[i] = ti;
                        ti *= t;
                    }

                    const sap_instance_evaluation<FieldType> eval_sap_inst(this->domain,
                                                                           this->num_variables(),
                                                                           this->degree(),
                                                                           this->num_inputs(),
                                                                           t,
                                                                           std::move(At),
                                                                           std::move(Ct),
                                                                           std::move(Ht),
                                                                           Zt);
                    return eval_sap_inst.is_satisfied(witness);
                }

                template<typename FieldType>
                sap_instance_evaluation<FieldType>::sap_instance_evaluation(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    const FieldType &t,
                    const std::vector<typename FieldType::value_type> &At,
                    const std::vector<typename FieldType::value_type> &Ct,
                    const std::vector<typename FieldType::value_type> &Ht,
                    const FieldType &Zt) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain), t(t), At(At), Ct(Ct), Ht(Ht), Zt(Zt) {
                }

                template<typename FieldType>
                sap_instance_evaluation<FieldType>::sap_instance_evaluation(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    const FieldType &t,
                    std::vector<typename FieldType::value_type> &&At,
                    std::vector<typename FieldType::value_type> &&Ct,
                    std::vector<typename FieldType::value_type> &&Ht,
                    const FieldType &Zt) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain), t(t), At(std::move(At)),
                    Ct(std::move(Ct)), Ht(std::move(Ht)), Zt(Zt) {
                }

                template<typename FieldType>
                std::size_t sap_instance_evaluation<FieldType>::num_variables() const {
                    return num_variables_;
                }

                template<typename FieldType>
                std::size_t sap_instance_evaluation<FieldType>::degree() const {
                    return degree_;
                }

                template<typename FieldType>
                std::size_t sap_instance_evaluation<FieldType>::num_inputs() const {
                    return num_inputs_;
                }

                template<typename FieldType>
                bool sap_instance_evaluation<FieldType>::is_satisfied(const sap_witness<FieldType> &witness) const {
                    if (this->num_variables() != witness.num_variables()) {
                        return false;
                    }

                    if (this->degree() != witness.degree()) {
                        return false;
                    }

                    if (this->num_inputs() != witness.num_inputs()) {
                        return false;
                    }

                    if (this->num_variables() != witness.coefficients_for_ACs.size()) {
                        return false;
                    }

                    if (this->degree() + 1 != witness.coefficients_for_H.size()) {
                        return false;
                    }

                    if (this->At.size() != this->num_variables() + 1 || this->Ct.size() != this->num_variables() + 1) {
                        return false;
                    }

                    if (this->Ht.size() != this->degree() + 1) {
                        return false;
                    }

                    if (this->Zt != this->domain->compute_vanishing_polynomial(this->t)) {
                        return false;
                    }

                    FieldType ans_A = this->At[0] + witness.d1 * this->Zt;
                    FieldType ans_C = this->Ct[0] + witness.d2 * this->Zt;
                    FieldType ans_H = FieldType::value_type::zero();

                    ans_A = ans_A + algebra::inner_product<FieldType>(this->At.begin() + 1,
                                                                      this->At.begin() + 1 + this->num_variables(),
                                                                      witness.coefficients_for_ACs.begin(),
                                                                      witness.coefficients_for_ACs.begin() +
                                                                          this->num_variables());
                    ans_C = ans_C + algebra::inner_product<FieldType>(this->Ct.begin() + 1,
                                                                      this->Ct.begin() + 1 + this->num_variables(),
                                                                      witness.coefficients_for_ACs.begin(),
                                                                      witness.coefficients_for_ACs.begin() +
                                                                          this->num_variables());
                    ans_H = ans_H +
                            algebra::inner_product<FieldType>(this->Ht.begin(),
                                                              this->Ht.begin() + this->degree() + 1,
                                                              witness.coefficients_for_H.begin(),
                                                              witness.coefficients_for_H.begin() + this->degree() + 1);

                    if (ans_A * ans_A - ans_C != ans_H * this->Zt) {
                        return false;
                    }

                    return true;
                }

                template<typename FieldType>
                sap_witness<FieldType>::sap_witness(const std::size_t num_variables,
                                                    const std::size_t degree,
                                                    const std::size_t num_inputs,
                                                    const FieldType &d1,
                                                    const FieldType &d2,
                                                    const std::vector<typename FieldType::value_type> &coefficients_for_ACs,
                                                    const std::vector<typename FieldType::value_type> &coefficients_for_H) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), d1(d1), d2(d2),
                    coefficients_for_ACs(coefficients_for_ACs), coefficients_for_H(coefficients_for_H) {
                }

                template<typename FieldType>
                sap_witness<FieldType>::sap_witness(const std::size_t num_variables,
                                                    const std::size_t degree,
                                                    const std::size_t num_inputs,
                                                    const FieldType &d1,
                                                    const FieldType &d2,
                                                    const std::vector<typename FieldType::value_type> &coefficients_for_ACs,
                                                    std::vector<typename FieldType::value_type> &&coefficients_for_H) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), d1(d1), d2(d2),
                    coefficients_for_ACs(coefficients_for_ACs), coefficients_for_H(std::move(coefficients_for_H)) {
                }

                template<typename FieldType>
                std::size_t sap_witness<FieldType>::num_variables() const {
                    return num_variables_;
                }

                template<typename FieldType>
                std::size_t sap_witness<FieldType>::degree() const {
                    return degree_;
                }

                template<typename FieldType>
                std::size_t sap_witness<FieldType>::num_inputs() const {
                    return num_inputs_;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // SAP_HPP_
