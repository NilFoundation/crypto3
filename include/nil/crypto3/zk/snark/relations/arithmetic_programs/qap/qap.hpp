//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a QAP ("Quadratic Arithmetic Program").
//
// QAPs are defined in \[GGPR13].
//
// References:
//
// \[GGPR13]:
// "Quadratic span programs and succinct NIZKs without PCPs",
// Rosario Gennaro, Craig Gentry, Bryan Parno, Mariana Raykova,
// EUROCRYPT 2013,
// <http://eprint.iacr.org/2012/215>
//---------------------------------------------------------------------------//

#ifndef QAP_HPP_
#define QAP_HPP_

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
                class qap_witness;

                /**
                 * A QAP instance.
                 *
                 * Specifically, the datastructure stores:
                 * - a choice of domain (corresponding to a certain subset of the field);
                 * - the number of variables, the degree, and the number of inputs; and
                 * - coefficients of the A,B,C polynomials in the Lagrange basis.
                 *
                 * There is no need to store the Z polynomial because it is uniquely
                 * determined by the domain (as Z is its vanishing polynomial).
                 */
                template<typename FieldType>
                class qap_instance {
                private:
                    std::size_t num_variables_;
                    std::size_t degree_;
                    std::size_t num_inputs_;

                public:
                    std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> domain;

                    std::vector<std::map<std::size_t, FieldType>> A_in_Lagrange_basis;
                    std::vector<std::map<std::size_t, FieldType>> B_in_Lagrange_basis;
                    std::vector<std::map<std::size_t, FieldType>> C_in_Lagrange_basis;

                    qap_instance(const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                                 const std::size_t num_variables,
                                 const std::size_t degree,
                                 const std::size_t num_inputs,
                                 const std::vector<std::map<std::size_t, FieldType>> &A_in_Lagrange_basis,
                                 const std::vector<std::map<std::size_t, FieldType>> &B_in_Lagrange_basis,
                                 const std::vector<std::map<std::size_t, FieldType>> &C_in_Lagrange_basis);

                    qap_instance(const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                                 const std::size_t num_variables,
                                 const std::size_t degree,
                                 const std::size_t num_inputs,
                                 std::vector<std::map<std::size_t, FieldType>> &&A_in_Lagrange_basis,
                                 std::vector<std::map<std::size_t, FieldType>> &&B_in_Lagrange_basis,
                                 std::vector<std::map<std::size_t, FieldType>> &&C_in_Lagrange_basis);

                    qap_instance(const qap_instance<FieldType> &other) = default;
                    qap_instance(qap_instance<FieldType> &&other) = default;
                    qap_instance &operator=(const qap_instance<FieldType> &other) = default;
                    qap_instance &operator=(qap_instance<FieldType> &&other) = default;

                    std::size_t num_variables() const;
                    std::size_t degree() const;
                    std::size_t num_inputs() const;

                    bool is_satisfied(const qap_witness<FieldType> &witness) const;
                };

                /**
                 * A QAP instance evaluation is a QAP instance that is evaluated at a field element t.
                 *
                 * Specifically, the datastructure stores:
                 * - a choice of domain (corresponding to a certain subset of the field);
                 * - the number of variables, the degree, and the number of inputs;
                 * - a field element t;
                 * - evaluations of the A,B,C (and Z) polynomials at t;
                 * - evaluations of all monomials of t;
                 * - counts about how many of the above evaluations are in fact non-zero.
                 */
                template<typename FieldType>
                class qap_instance_evaluation {
                private:
                    std::size_t num_variables_;
                    std::size_t degree_;
                    std::size_t num_inputs_;

                public:
                    std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> domain;

                    FieldType t;

                    std::vector<typename FieldType::value_type> At, Bt, Ct, Ht;

                    FieldType Zt;

                    qap_instance_evaluation(const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                                            const std::size_t num_variables,
                                            const std::size_t degree,
                                            const std::size_t num_inputs,
                                            const FieldType &t,
                                            const std::vector<typename FieldType::value_type> &At,
                                            const std::vector<typename FieldType::value_type> &Bt,
                                            const std::vector<typename FieldType::value_type> &Ct,
                                            const std::vector<typename FieldType::value_type> &Ht,
                                            const FieldType &Zt);
                    qap_instance_evaluation(const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                                            const std::size_t num_variables,
                                            const std::size_t degree,
                                            const std::size_t num_inputs,
                                            const FieldType &t,
                                            std::vector<typename FieldType::value_type> &&At,
                                            std::vector<typename FieldType::value_type> &&Bt,
                                            std::vector<typename FieldType::value_type> &&Ct,
                                            std::vector<typename FieldType::value_type> &&Ht,
                                            const FieldType &Zt);

                    qap_instance_evaluation(const qap_instance_evaluation<FieldType> &other) = default;
                    qap_instance_evaluation(qap_instance_evaluation<FieldType> &&other) = default;
                    qap_instance_evaluation &operator=(const qap_instance_evaluation<FieldType> &other) = default;
                    qap_instance_evaluation &operator=(qap_instance_evaluation<FieldType> &&other) = default;

                    std::size_t num_variables() const;
                    std::size_t degree() const;
                    std::size_t num_inputs() const;

                    bool is_satisfied(const qap_witness<FieldType> &witness) const;
                };

                /**
                 * A QAP witness.
                 */
                template<typename FieldType>
                class qap_witness {
                private:
                    std::size_t num_variables_;
                    std::size_t degree_;
                    std::size_t num_inputs_;

                public:
                    FieldType d1, d2, d3;

                    std::vector<typename FieldType::value_type> coefficients_for_ABCs;
                    std::vector<typename FieldType::value_type> coefficients_for_H;

                    qap_witness(const std::size_t num_variables,
                                const std::size_t degree,
                                const std::size_t num_inputs,
                                const FieldType &d1,
                                const FieldType &d2,
                                const FieldType &d3,
                                const std::vector<typename FieldType::value_type> &coefficients_for_ABCs,
                                const std::vector<typename FieldType::value_type> &coefficients_for_H);

                    qap_witness(const std::size_t num_variables,
                                const std::size_t degree,
                                const std::size_t num_inputs,
                                const FieldType &d1,
                                const FieldType &d2,
                                const FieldType &d3,
                                const std::vector<typename FieldType::value_type> &coefficients_for_ABCs,
                                std::vector<typename FieldType::value_type> &&coefficients_for_H);

                    qap_witness(const qap_witness<FieldType> &other) = default;
                    qap_witness(qap_witness<FieldType> &&other) = default;
                    qap_witness &operator=(const qap_witness<FieldType> &other) = default;
                    qap_witness &operator=(qap_witness<FieldType> &&other) = default;

                    std::size_t num_variables() const;
                    std::size_t degree() const;
                    std::size_t num_inputs() const;
                };

                template<typename FieldType>
                qap_instance<FieldType>::qap_instance(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    const std::vector<std::map<std::size_t, FieldType>> &A_in_Lagrange_basis,
                    const std::vector<std::map<std::size_t, FieldType>> &B_in_Lagrange_basis,
                    const std::vector<std::map<std::size_t, FieldType>> &C_in_Lagrange_basis) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain), A_in_Lagrange_basis(A_in_Lagrange_basis),
                    B_in_Lagrange_basis(B_in_Lagrange_basis), C_in_Lagrange_basis(C_in_Lagrange_basis) {
                }

                template<typename FieldType>
                qap_instance<FieldType>::qap_instance(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    std::vector<std::map<std::size_t, FieldType>> &&A_in_Lagrange_basis,
                    std::vector<std::map<std::size_t, FieldType>> &&B_in_Lagrange_basis,
                    std::vector<std::map<std::size_t, FieldType>> &&C_in_Lagrange_basis) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain),
                    A_in_Lagrange_basis(std::move(A_in_Lagrange_basis)),
                    B_in_Lagrange_basis(std::move(B_in_Lagrange_basis)),
                    C_in_Lagrange_basis(std::move(C_in_Lagrange_basis)) {
                }

                template<typename FieldType>
                std::size_t qap_instance<FieldType>::num_variables() const {
                    return num_variables_;
                }

                template<typename FieldType>
                std::size_t qap_instance<FieldType>::degree() const {
                    return degree_;
                }

                template<typename FieldType>
                std::size_t qap_instance<FieldType>::num_inputs() const {
                    return num_inputs_;
                }

                template<typename FieldType>
                bool qap_instance<FieldType>::is_satisfied(const qap_witness<FieldType> &witness) const {
                    const FieldType t = FieldType::random_element();

                    std::vector<typename FieldType::value_type> At(this->num_variables() + 1, FieldType::zero());
                    std::vector<typename FieldType::value_type> Bt(this->num_variables() + 1, FieldType::zero());
                    std::vector<typename FieldType::value_type> Ct(this->num_variables() + 1, FieldType::zero());
                    std::vector<typename FieldType::value_type> Ht(this->degree() + 1);

                    const FieldType Zt = this->domain->compute_vanishing_polynomial(t);

                    const std::vector<typename FieldType::value_type> u = this->domain->evaluate_all_lagrange_polynomials(t);

                    for (std::size_t i = 0; i < this->num_variables() + 1; ++i) {
                        for (auto &el : A_in_Lagrange_basis[i]) {
                            At[i] += u[el.first] * el.second;
                        }

                        for (auto &el : B_in_Lagrange_basis[i]) {
                            Bt[i] += u[el.first] * el.second;
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

                    const qap_instance_evaluation<FieldType> eval_qap_inst(this->domain,
                                                                           this->num_variables(),
                                                                           this->degree(),
                                                                           this->num_inputs(),
                                                                           t,
                                                                           std::move(At),
                                                                           std::move(Bt),
                                                                           std::move(Ct),
                                                                           std::move(Ht),
                                                                           Zt);
                    return eval_qap_inst.is_satisfied(witness);
                }

                template<typename FieldType>
                qap_instance_evaluation<FieldType>::qap_instance_evaluation(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    const FieldType &t,
                    const std::vector<typename FieldType::value_type> &At,
                    const std::vector<typename FieldType::value_type> &Bt,
                    const std::vector<typename FieldType::value_type> &Ct,
                    const std::vector<typename FieldType::value_type> &Ht,
                    const FieldType &Zt) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain), t(t), At(At), Bt(Bt), Ct(Ct), Ht(Ht),
                    Zt(Zt) {
                }

                template<typename FieldType>
                qap_instance_evaluation<FieldType>::qap_instance_evaluation(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    const FieldType &t,
                    std::vector<typename FieldType::value_type> &&At,
                    std::vector<typename FieldType::value_type> &&Bt,
                    std::vector<typename FieldType::value_type> &&Ct,
                    std::vector<typename FieldType::value_type> &&Ht,
                    const FieldType &Zt) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain), t(t), At(std::move(At)),
                    Bt(std::move(Bt)), Ct(std::move(Ct)), Ht(std::move(Ht)), Zt(Zt) {
                }

                template<typename FieldType>
                std::size_t qap_instance_evaluation<FieldType>::num_variables() const {
                    return num_variables_;
                }

                template<typename FieldType>
                std::size_t qap_instance_evaluation<FieldType>::degree() const {
                    return degree_;
                }

                template<typename FieldType>
                std::size_t qap_instance_evaluation<FieldType>::num_inputs() const {
                    return num_inputs_;
                }

                template<typename FieldType>
                bool qap_instance_evaluation<FieldType>::is_satisfied(const qap_witness<FieldType> &witness) const {

                    if (this->num_variables() != witness.num_variables()) {
                        return false;
                    }

                    if (this->degree() != witness.degree()) {
                        return false;
                    }

                    if (this->num_inputs() != witness.num_inputs()) {
                        return false;
                    }

                    if (this->num_variables() != witness.coefficients_for_ABCs.size()) {
                        return false;
                    }

                    if (this->degree() + 1 != witness.coefficients_for_H.size()) {
                        return false;
                    }

                    if (this->At.size() != this->num_variables() + 1 || this->Bt.size() != this->num_variables() + 1 ||
                        this->Ct.size() != this->num_variables() + 1) {
                        return false;
                    }

                    if (this->Ht.size() != this->degree() + 1) {
                        return false;
                    }

                    if (this->Zt != this->domain->compute_vanishing_polynomial(this->t)) {
                        return false;
                    }

                    FieldType ans_A = this->At[0] + witness.d1 * this->Zt;
                    FieldType ans_B = this->Bt[0] + witness.d2 * this->Zt;
                    FieldType ans_C = this->Ct[0] + witness.d3 * this->Zt;
                    FieldType ans_H = FieldType::zero();

                    ans_A = ans_A + algebra::inner_product<FieldType>(this->At.begin() + 1,
                                                                      this->At.begin() + 1 + this->num_variables(),
                                                                      witness.coefficients_for_ABCs.begin(),
                                                                      witness.coefficients_for_ABCs.begin() +
                                                                          this->num_variables());
                    ans_B = ans_B + algebra::inner_product<FieldType>(this->Bt.begin() + 1,
                                                                      this->Bt.begin() + 1 + this->num_variables(),
                                                                      witness.coefficients_for_ABCs.begin(),
                                                                      witness.coefficients_for_ABCs.begin() +
                                                                          this->num_variables());
                    ans_C = ans_C + algebra::inner_product<FieldType>(this->Ct.begin() + 1,
                                                                      this->Ct.begin() + 1 + this->num_variables(),
                                                                      witness.coefficients_for_ABCs.begin(),
                                                                      witness.coefficients_for_ABCs.begin() +
                                                                          this->num_variables());
                    ans_H = ans_H +
                            algebra::inner_product<FieldType>(this->Ht.begin(),
                                                              this->Ht.begin() + this->degree() + 1,
                                                              witness.coefficients_for_H.begin(),
                                                              witness.coefficients_for_H.begin() + this->degree() + 1);

                    if (ans_A * ans_B - ans_C != ans_H * this->Zt) {
                        return false;
                    }

                    return true;
                }

                template<typename FieldType>
                qap_witness<FieldType>::qap_witness(const std::size_t num_variables,
                                                    const std::size_t degree,
                                                    const std::size_t num_inputs,
                                                    const FieldType &d1,
                                                    const FieldType &d2,
                                                    const FieldType &d3,
                                                    const std::vector<typename FieldType::value_type> &coefficients_for_ABCs,
                                                    const std::vector<typename FieldType::value_type> &coefficients_for_H) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), d1(d1), d2(d2), d3(d3),
                    coefficients_for_ABCs(coefficients_for_ABCs), coefficients_for_H(coefficients_for_H) {
                }

                template<typename FieldType>
                qap_witness<FieldType>::qap_witness(const std::size_t num_variables,
                                                    const std::size_t degree,
                                                    const std::size_t num_inputs,
                                                    const FieldType &d1,
                                                    const FieldType &d2,
                                                    const FieldType &d3,
                                                    const std::vector<typename FieldType::value_type> &coefficients_for_ABCs,
                                                    std::vector<typename FieldType::value_type> &&coefficients_for_H) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), d1(d1), d2(d2), d3(d3),
                    coefficients_for_ABCs(coefficients_for_ABCs), coefficients_for_H(std::move(coefficients_for_H)) {
                }

                template<typename FieldType>
                std::size_t qap_witness<FieldType>::num_variables() const {
                    return num_variables_;
                }

                template<typename FieldType>
                std::size_t qap_witness<FieldType>::degree() const {
                    return degree_;
                }

                template<typename FieldType>
                std::size_t qap_witness<FieldType>::num_inputs() const {
                    return num_inputs_;
                }

                template<typename FieldType>
                qap_instance<FieldType>::qap_instance(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    const std::vector<std::map<std::size_t, FieldType>> &A_in_Lagrange_basis,
                    const std::vector<std::map<std::size_t, FieldType>> &B_in_Lagrange_basis,
                    const std::vector<std::map<std::size_t, FieldType>> &C_in_Lagrange_basis) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain), A_in_Lagrange_basis(A_in_Lagrange_basis),
                    B_in_Lagrange_basis(B_in_Lagrange_basis), C_in_Lagrange_basis(C_in_Lagrange_basis) {
                }

                template<typename FieldType>
                qap_instance<FieldType>::qap_instance(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    std::vector<std::map<std::size_t, FieldType>> &&A_in_Lagrange_basis,
                    std::vector<std::map<std::size_t, FieldType>> &&B_in_Lagrange_basis,
                    std::vector<std::map<std::size_t, FieldType>> &&C_in_Lagrange_basis) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain),
                    A_in_Lagrange_basis(std::move(A_in_Lagrange_basis)),
                    B_in_Lagrange_basis(std::move(B_in_Lagrange_basis)),
                    C_in_Lagrange_basis(std::move(C_in_Lagrange_basis)) {
                }

                template<typename FieldType>
                std::size_t qap_instance<FieldType>::num_variables() const {
                    return num_variables_;
                }

                template<typename FieldType>
                std::size_t qap_instance<FieldType>::degree() const {
                    return degree_;
                }

                template<typename FieldType>
                std::size_t qap_instance<FieldType>::num_inputs() const {
                    return num_inputs_;
                }

                template<typename FieldType>
                bool qap_instance<FieldType>::is_satisfied(const qap_witness<FieldType> &witness) const {
                    const FieldType t = FieldType::random_element();

                    std::vector<typename FieldType::value_type> At(this->num_variables() + 1, FieldType::zero());
                    std::vector<typename FieldType::value_type> Bt(this->num_variables() + 1, FieldType::zero());
                    std::vector<typename FieldType::value_type> Ct(this->num_variables() + 1, FieldType::zero());
                    std::vector<typename FieldType::value_type> Ht(this->degree() + 1);

                    const FieldType Zt = this->domain->compute_vanishing_polynomial(t);

                    const std::vector<typename FieldType::value_type> u = this->domain->evaluate_all_lagrange_polynomials(t);

                    for (std::size_t i = 0; i < this->num_variables() + 1; ++i) {
                        for (auto &el : A_in_Lagrange_basis[i]) {
                            At[i] += u[el.first] * el.second;
                        }

                        for (auto &el : B_in_Lagrange_basis[i]) {
                            Bt[i] += u[el.first] * el.second;
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

                    const qap_instance_evaluation<FieldType> eval_qap_inst(this->domain,
                                                                           this->num_variables(),
                                                                           this->degree(),
                                                                           this->num_inputs(),
                                                                           t,
                                                                           std::move(At),
                                                                           std::move(Bt),
                                                                           std::move(Ct),
                                                                           std::move(Ht),
                                                                           Zt);
                    return eval_qap_inst.is_satisfied(witness);
                }

                template<typename FieldType>
                qap_instance_evaluation<FieldType>::qap_instance_evaluation(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    const FieldType &t,
                    const std::vector<typename FieldType::value_type> &At,
                    const std::vector<typename FieldType::value_type> &Bt,
                    const std::vector<typename FieldType::value_type> &Ct,
                    const std::vector<typename FieldType::value_type> &Ht,
                    const FieldType &Zt) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain), t(t), At(At), Bt(Bt), Ct(Ct), Ht(Ht),
                    Zt(Zt) {
                }

                template<typename FieldType>
                qap_instance_evaluation<FieldType>::qap_instance_evaluation(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    const FieldType &t,
                    std::vector<typename FieldType::value_type> &&At,
                    std::vector<typename FieldType::value_type> &&Bt,
                    std::vector<typename FieldType::value_type> &&Ct,
                    std::vector<typename FieldType::value_type> &&Ht,
                    const FieldType &Zt) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain), t(t), At(std::move(At)),
                    Bt(std::move(Bt)), Ct(std::move(Ct)), Ht(std::move(Ht)), Zt(Zt) {
                }

                template<typename FieldType>
                std::size_t qap_instance_evaluation<FieldType>::num_variables() const {
                    return num_variables_;
                }

                template<typename FieldType>
                std::size_t qap_instance_evaluation<FieldType>::degree() const {
                    return degree_;
                }

                template<typename FieldType>
                std::size_t qap_instance_evaluation<FieldType>::num_inputs() const {
                    return num_inputs_;
                }

                template<typename FieldType>
                bool qap_instance_evaluation<FieldType>::is_satisfied(const qap_witness<FieldType> &witness) const {

                    if (this->num_variables() != witness.num_variables()) {
                        return false;
                    }

                    if (this->degree() != witness.degree()) {
                        return false;
                    }

                    if (this->num_inputs() != witness.num_inputs()) {
                        return false;
                    }

                    if (this->num_variables() != witness.coefficients_for_ABCs.size()) {
                        return false;
                    }

                    if (this->degree() + 1 != witness.coefficients_for_H.size()) {
                        return false;
                    }

                    if (this->At.size() != this->num_variables() + 1 || this->Bt.size() != this->num_variables() + 1 ||
                        this->Ct.size() != this->num_variables() + 1) {
                        return false;
                    }

                    if (this->Ht.size() != this->degree() + 1) {
                        return false;
                    }

                    if (this->Zt != this->domain->compute_vanishing_polynomial(this->t)) {
                        return false;
                    }

                    FieldType ans_A = this->At[0] + witness.d1 * this->Zt;
                    FieldType ans_B = this->Bt[0] + witness.d2 * this->Zt;
                    FieldType ans_C = this->Ct[0] + witness.d3 * this->Zt;
                    FieldType ans_H = FieldType::zero();

                    ans_A = ans_A + algebra::inner_product<FieldType>(this->At.begin() + 1,
                                                                      this->At.begin() + 1 + this->num_variables(),
                                                                      witness.coefficients_for_ABCs.begin(),
                                                                      witness.coefficients_for_ABCs.begin() +
                                                                          this->num_variables());
                    ans_B = ans_B + algebra::inner_product<FieldType>(this->Bt.begin() + 1,
                                                                      this->Bt.begin() + 1 + this->num_variables(),
                                                                      witness.coefficients_for_ABCs.begin(),
                                                                      witness.coefficients_for_ABCs.begin() +
                                                                          this->num_variables());
                    ans_C = ans_C + algebra::inner_product<FieldType>(this->Ct.begin() + 1,
                                                                      this->Ct.begin() + 1 + this->num_variables(),
                                                                      witness.coefficients_for_ABCs.begin(),
                                                                      witness.coefficients_for_ABCs.begin() +
                                                                          this->num_variables());
                    ans_H = ans_H +
                            algebra::inner_product<FieldType>(this->Ht.begin(),
                                                              this->Ht.begin() + this->degree() + 1,
                                                              witness.coefficients_for_H.begin(),
                                                              witness.coefficients_for_H.begin() + this->degree() + 1);

                    if (ans_A * ans_B - ans_C != ans_H * this->Zt) {
                        return false;
                    }

                    return true;
                }

                template<typename FieldType>
                qap_witness<FieldType>::qap_witness(const std::size_t num_variables,
                                                    const std::size_t degree,
                                                    const std::size_t num_inputs,
                                                    const FieldType &d1,
                                                    const FieldType &d2,
                                                    const FieldType &d3,
                                                    const std::vector<typename FieldType::value_type> &coefficients_for_ABCs,
                                                    const std::vector<typename FieldType::value_type> &coefficients_for_H) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), d1(d1), d2(d2), d3(d3),
                    coefficients_for_ABCs(coefficients_for_ABCs), coefficients_for_H(coefficients_for_H) {
                }

                template<typename FieldType>
                qap_witness<FieldType>::qap_witness(const std::size_t num_variables,
                                                    const std::size_t degree,
                                                    const std::size_t num_inputs,
                                                    const FieldType &d1,
                                                    const FieldType &d2,
                                                    const FieldType &d3,
                                                    const std::vector<typename FieldType::value_type> &coefficients_for_ABCs,
                                                    std::vector<typename FieldType::value_type> &&coefficients_for_H) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), d1(d1), d2(d2), d3(d3),
                    coefficients_for_ABCs(coefficients_for_ABCs), coefficients_for_H(std::move(coefficients_for_H)) {
                }

                template<typename FieldType>
                std::size_t qap_witness<FieldType>::num_variables() const {
                    return num_variables_;
                }

                template<typename FieldType>
                std::size_t qap_witness<FieldType>::degree() const {
                    return degree_;
                }

                template<typename FieldType>
                std::size_t qap_witness<FieldType>::num_inputs() const {
                    return num_inputs_;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // QAP_HPP_
