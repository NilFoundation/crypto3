//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a SSP ("Square Span Program").
//
// SSPs are defined in \[DFGK14].
//
// References:
//
// \[DFGK14]:
// "Square Span Programs with Applications to Succinct NIZK Arguments"
// George Danezis, Cedric Fournet, Jens Groth, Markulf Kohlweiss,
// ASIACRYPT 2014,
// <http://eprint.iacr.org/2014/718>
//---------------------------------------------------------------------------//

#ifndef SSP_HPP_
#define SSP_HPP_

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
                class ssp_witness;

                /**
                 * A SSP instance.
                 *
                 * Specifically, the datastructure stores:
                 * - a choice of domain (corresponding to a certain subset of the field);
                 * - the number of variables, the degree, and the number of inputs; and
                 * - coefficients of the V polynomials in the Lagrange basis.
                 *
                 * There is no need to store the Z polynomial because it is uniquely
                 * determined by the domain (as Z is its vanishing polynomial).
                 */
                template<typename FieldType>
                class ssp_instance {
                private:
                    std::size_t num_variables_;
                    std::size_t degree_;
                    std::size_t num_inputs_;

                public:
                    std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> domain;

                    std::vector<std::map<std::size_t, FieldType>> V_in_Lagrange_basis;

                    ssp_instance(const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                                 const std::size_t num_variables,
                                 const std::size_t degree,
                                 const std::size_t num_inputs,
                                 const std::vector<std::map<std::size_t, FieldType>> &V_in_Lagrange_basis);
                    ssp_instance(const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                                 const std::size_t num_variables,
                                 const std::size_t degree,
                                 const std::size_t num_inputs,
                                 std::vector<std::map<std::size_t, FieldType>> &&V_in_Lagrange_basis);

                    ssp_instance(const ssp_instance<FieldType> &other) = default;
                    ssp_instance(ssp_instance<FieldType> &&other) = default;
                    ssp_instance &operator=(const ssp_instance<FieldType> &other) = default;
                    ssp_instance &operator=(ssp_instance<FieldType> &&other) = default;

                    std::size_t num_variables() const;
                    std::size_t degree() const;
                    std::size_t num_inputs() const;

                    bool is_satisfied(const ssp_witness<FieldType> &witness) const;
                };

                /**
                 * A SSP instance evaluation is a SSP instance that is evaluated at a field element t.
                 *
                 * Specifically, the datastructure stores:
                 * - a choice of domain (corresponding to a certain subset of the field);
                 * - the number of variables, the degree, and the number of inputs;
                 * - a field element t;
                 * - evaluations of the V (and Z) polynomials at t;
                 * - evaluations of all monomials of t.
                 */
                template<typename FieldType>
                class ssp_instance_evaluation {
                private:
                    std::size_t num_variables_;
                    std::size_t degree_;
                    std::size_t num_inputs_;

                public:
                    std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> domain;

                    FieldType t;

                    std::vector<typename FieldType::value_type> Vt, Ht;

                    FieldType Zt;

                    ssp_instance_evaluation(const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                                            const std::size_t num_variables,
                                            const std::size_t degree,
                                            const std::size_t num_inputs,
                                            const FieldType &t,
                                            const std::vector<typename FieldType::value_type> &Vt,
                                            const std::vector<typename FieldType::value_type> &Ht,
                                            const FieldType &Zt);
                    ssp_instance_evaluation(const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                                            const std::size_t num_variables,
                                            const std::size_t degree,
                                            const std::size_t num_inputs,
                                            const FieldType &t,
                                            std::vector<typename FieldType::value_type> &&Vt,
                                            std::vector<typename FieldType::value_type> &&Ht,
                                            const FieldType &Zt);

                    ssp_instance_evaluation(const ssp_instance_evaluation<FieldType> &other) = default;
                    ssp_instance_evaluation(ssp_instance_evaluation<FieldType> &&other) = default;
                    ssp_instance_evaluation &operator=(const ssp_instance_evaluation<FieldType> &other) = default;
                    ssp_instance_evaluation &operator=(ssp_instance_evaluation<FieldType> &&other) = default;

                    std::size_t num_variables() const;
                    std::size_t degree() const;
                    std::size_t num_inputs() const;

                    bool is_satisfied(const ssp_witness<FieldType> &witness) const;
                };

                /**
                 * A SSP witness.
                 */
                template<typename FieldType>
                class ssp_witness {
                private:
                    std::size_t num_variables_;
                    std::size_t degree_;
                    std::size_t num_inputs_;

                public:
                    FieldType d;

                    std::vector<typename FieldType::value_type> coefficients_for_Vs;
                    std::vector<typename FieldType::value_type> coefficients_for_H;

                    ssp_witness(const std::size_t num_variables,
                                const std::size_t degree,
                                const std::size_t num_inputs,
                                const FieldType &d,
                                const std::vector<typename FieldType::value_type> &coefficients_for_Vs,
                                const std::vector<typename FieldType::value_type> &coefficients_for_H);
                    ssp_witness(const std::size_t num_variables,
                                const std::size_t degree,
                                const std::size_t num_inputs,
                                const FieldType &d,
                                const std::vector<typename FieldType::value_type> &coefficients_for_Vs,
                                std::vector<typename FieldType::value_type> &&coefficients_for_H);

                    ssp_witness(const ssp_witness<FieldType> &other) = default;
                    ssp_witness(ssp_witness<FieldType> &&other) = default;
                    ssp_witness &operator=(const ssp_witness<FieldType> &other) = default;
                    ssp_witness &operator=(ssp_witness<FieldType> &&other) = default;

                    std::size_t num_variables() const;
                    std::size_t degree() const;
                    std::size_t num_inputs() const;
                };

                template<typename FieldType>
                ssp_instance<FieldType>::ssp_instance(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    const std::vector<std::map<std::size_t, FieldType>> &V_in_Lagrange_basis) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain), V_in_Lagrange_basis(V_in_Lagrange_basis) {
                }

                template<typename FieldType>
                ssp_instance<FieldType>::ssp_instance(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    std::vector<std::map<std::size_t, FieldType>> &&V_in_Lagrange_basis) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain),
                    V_in_Lagrange_basis(std::move(V_in_Lagrange_basis)) {
                }

                template<typename FieldType>
                std::size_t ssp_instance<FieldType>::num_variables() const {
                    return num_variables_;
                }

                template<typename FieldType>
                std::size_t ssp_instance<FieldType>::degree() const {
                    return degree_;
                }

                template<typename FieldType>
                std::size_t ssp_instance<FieldType>::num_inputs() const {
                    return num_inputs_;
                }

                template<typename FieldType>
                bool ssp_instance<FieldType>::is_satisfied(const ssp_witness<FieldType> &witness) const {
                    const FieldType t = FieldType::random_element();
                    ;
                    std::vector<typename FieldType::value_type> Vt(this->num_variables() + 1, FieldType::zero());
                    std::vector<typename FieldType::value_type> Ht(this->degree() + 1);

                    const FieldType Zt = this->domain->compute_vanishing_polynomial(t);

                    const std::vector<typename FieldType::value_type> u = this->domain->evaluate_all_lagrange_polynomials(t);

                    for (std::size_t i = 0; i < this->num_variables() + 1; ++i) {
                        for (auto &el : V_in_Lagrange_basis[i]) {
                            Vt[i] += u[el.first] * el.second;
                        }
                    }

                    FieldType ti = FieldType::one();
                    for (std::size_t i = 0; i < this->degree() + 1; ++i) {
                        Ht[i] = ti;
                        ti *= t;
                    }

                    const ssp_instance_evaluation<FieldType> eval_ssp_inst(this->domain,
                                                                           this->num_variables(),
                                                                           this->degree(),
                                                                           this->num_inputs(),
                                                                           t,
                                                                           std::move(Vt),
                                                                           std::move(Ht),
                                                                           Zt);
                    return eval_ssp_inst.is_satisfied(witness);
                }

                template<typename FieldType>
                ssp_instance_evaluation<FieldType>::ssp_instance_evaluation(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    const FieldType &t,
                    const std::vector<typename FieldType::value_type> &Vt,
                    const std::vector<typename FieldType::value_type> &Ht,
                    const FieldType &Zt) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain), t(t), Vt(Vt), Ht(Ht), Zt(Zt) {
                }

                template<typename FieldType>
                ssp_instance_evaluation<FieldType>::ssp_instance_evaluation(
                    const std::shared_ptr<algebra::fft::evaluation_domain<FieldType>> &domain,
                    const std::size_t num_variables,
                    const std::size_t degree,
                    const std::size_t num_inputs,
                    const FieldType &t,
                    std::vector<typename FieldType::value_type> &&Vt,
                    std::vector<typename FieldType::value_type> &&Ht,
                    const FieldType &Zt) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), domain(domain), t(t), Vt(std::move(Vt)),
                    Ht(std::move(Ht)), Zt(Zt) {
                }

                template<typename FieldType>
                std::size_t ssp_instance_evaluation<FieldType>::num_variables() const {
                    return num_variables_;
                }

                template<typename FieldType>
                std::size_t ssp_instance_evaluation<FieldType>::degree() const {
                    return degree_;
                }

                template<typename FieldType>
                std::size_t ssp_instance_evaluation<FieldType>::num_inputs() const {
                    return num_inputs_;
                }

                template<typename FieldType>
                bool ssp_instance_evaluation<FieldType>::is_satisfied(const ssp_witness<FieldType> &witness) const {

                    if (this->num_variables() != witness.num_variables()) {
                        return false;
                    }

                    if (this->degree() != witness.degree()) {
                        return false;
                    }

                    if (this->num_inputs() != witness.num_inputs()) {
                        return false;
                    }

                    if (this->num_variables() != witness.coefficients_for_Vs.size()) {
                        return false;
                    }

                    if (this->degree() + 1 != witness.coefficients_for_H.size()) {
                        return false;
                    }

                    if (this->Vt.size() != this->num_variables() + 1) {
                        return false;
                    }

                    if (this->Ht.size() != this->degree() + 1) {
                        return false;
                    }

                    if (this->Zt != this->domain->compute_vanishing_polynomial(this->t)) {
                        return false;
                    }

                    FieldType ans_V = this->Vt[0] + witness.d * this->Zt;
                    FieldType ans_H = FieldType::zero();

                    ans_V = ans_V + algebra::inner_product<FieldType>(this->Vt.begin() + 1,
                                                                      this->Vt.begin() + 1 + this->num_variables(),
                                                                      witness.coefficients_for_Vs.begin(),
                                                                      witness.coefficients_for_Vs.begin() +
                                                                          this->num_variables());
                    ans_H = ans_H +
                            algebra::inner_product<FieldType>(this->Ht.begin(),
                                                              this->Ht.begin() + this->degree() + 1,
                                                              witness.coefficients_for_H.begin(),
                                                              witness.coefficients_for_H.begin() + this->degree() + 1);

                    if (ans_V.squared() - FieldType::one() != ans_H * this->Zt) {
                        return false;
                    }

                    return true;
                }

                template<typename FieldType>
                ssp_witness<FieldType>::ssp_witness(const std::size_t num_variables,
                                                    const std::size_t degree,
                                                    const std::size_t num_inputs,
                                                    const FieldType &d,
                                                    const std::vector<typename FieldType::value_type> &coefficients_for_Vs,
                                                    const std::vector<typename FieldType::value_type> &coefficients_for_H) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), d(d), coefficients_for_Vs(coefficients_for_Vs),
                    coefficients_for_H(coefficients_for_H) {
                }

                template<typename FieldType>
                ssp_witness<FieldType>::ssp_witness(const std::size_t num_variables,
                                                    const std::size_t degree,
                                                    const std::size_t num_inputs,
                                                    const FieldType &d,
                                                    const std::vector<typename FieldType::value_type> &coefficients_for_Vs,
                                                    std::vector<typename FieldType::value_type> &&coefficients_for_H) :
                    num_variables_(num_variables),
                    degree_(degree), num_inputs_(num_inputs), d(d), coefficients_for_Vs(coefficients_for_Vs),
                    coefficients_for_H(std::move(coefficients_for_H)) {
                }

                template<typename FieldType>
                std::size_t ssp_witness<FieldType>::num_variables() const {
                    return num_variables_;
                }

                template<typename FieldType>
                std::size_t ssp_witness<FieldType>::degree() const {
                    return degree_;
                }

                template<typename FieldType>
                std::size_t ssp_witness<FieldType>::num_inputs() const {
                    return num_inputs_;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // SSP_HPP_
