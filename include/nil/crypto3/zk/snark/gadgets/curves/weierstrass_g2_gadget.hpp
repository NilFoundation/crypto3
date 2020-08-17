//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for G2 gadgets.
//
// The gadgets verify curve arithmetic in G2 = E'(F) where E'/F^e: y^2 = x^3 + A' * X + B'
// is an elliptic curve over F^e in short Weierstrass form.
//---------------------------------------------------------------------------//

#ifndef WEIERSTRASS_G2_GADGET_HPP_
#define WEIERSTRASS_G2_GADGET_HPP_

#include <memory>

#include <nil/crypto3/zk/snark/gadget.hpp>
#include <nil/crypto3/zk/snark/gadgets/pairing/pairing_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Gadget that represents a G2 variable.
                 */
                template<typename ppT>
                class G2_variable : public gadget<algebra::Fr<ppT>> {
                public:
                    typedef algebra::Fr<ppT> FieldType;
                    typedef algebra::Fqe<other_curve<ppT>> FqeT;
                    typedef algebra::Fqk<other_curve<ppT>> FqkT;

                    std::shared_ptr<Fqe_variable<ppT>> X;
                    std::shared_ptr<Fqe_variable<ppT>> Y;

                    pb_linear_combination_array<FieldType> all_vars;

                    G2_variable(protoboard<FieldType> &pb);
                    G2_variable(protoboard<FieldType> &pb, const algebra::G2<other_curve<ppT>> &Q);

                    void generate_r1cs_witness(const algebra::G2<other_curve<ppT>> &Q);

                    // (See a comment in r1cs_ppzksnark_verifier_gadget.hpp about why
                    // we mark this function noinline.) TODO: remove later
                    static size_t __attribute__((noinline)) size_in_bits();
                    static size_t num_variables();
                };

                /**
                 * Gadget that creates constraints for the validity of a G2 variable.
                 */
                template<typename ppT>
                class G2_checker_gadget : public gadget<algebra::Fr<ppT>> {
                public:
                    typedef algebra::Fr<ppT> FieldType;
                    typedef algebra::Fqe<other_curve<ppT>> FqeT;
                    typedef algebra::Fqk<other_curve<ppT>> FqkT;

                    G2_variable<ppT> Q;

                    std::shared_ptr<Fqe_variable<ppT>> Xsquared;
                    std::shared_ptr<Fqe_variable<ppT>> Ysquared;
                    std::shared_ptr<Fqe_variable<ppT>> Xsquared_plus_a;
                    std::shared_ptr<Fqe_variable<ppT>> Ysquared_minus_b;

                    std::shared_ptr<Fqe_sqr_gadget<ppT>> compute_Xsquared;
                    std::shared_ptr<Fqe_sqr_gadget<ppT>> compute_Ysquared;
                    std::shared_ptr<Fqe_mul_gadget<ppT>> curve_equation;

                    G2_checker_gadget(protoboard<FieldType> &pb, const G2_variable<ppT> &Q);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename ppT>
                G2_variable<ppT>::G2_variable(protoboard<FieldType> &pb) : gadget<FieldType>(pb) {
                    X.reset(new Fqe_variable<ppT>(pb));
                    Y.reset(new Fqe_variable<ppT>(pb));

                    all_vars.insert(all_vars.end(), X->all_vars.begin(), X->all_vars.end());
                    all_vars.insert(all_vars.end(), Y->all_vars.begin(), Y->all_vars.end());
                }

                template<typename ppT>
                G2_variable<ppT>::G2_variable(protoboard<FieldType> &pb, const algebra::G2<other_curve<ppT>> &Q) :
                    gadget<FieldType>(pb) {
                    algebra::G2<other_curve<ppT>> Q_copy = Q;
                    Q_copy.to_affine_coordinates();

                    X.reset(new Fqe_variable<ppT>(pb, Q_copy.X()));
                    Y.reset(new Fqe_variable<ppT>(pb, Q_copy.Y()));

                    all_vars.insert(all_vars.end(), X->all_vars.begin(), X->all_vars.end());
                    all_vars.insert(all_vars.end(), Y->all_vars.begin(), Y->all_vars.end());
                }

                template<typename ppT>
                void G2_variable<ppT>::generate_r1cs_witness(const algebra::G2<other_curve<ppT>> &Q) {
                    algebra::G2<other_curve<ppT>> Qcopy = Q;
                    Qcopy.to_affine_coordinates();

                    X->generate_r1cs_witness(Qcopy.X());
                    Y->generate_r1cs_witness(Qcopy.Y());
                }

                template<typename ppT>
                size_t G2_variable<ppT>::size_in_bits() {
                    return 2 * Fqe_variable<ppT>::size_in_bits();
                }

                template<typename ppT>
                size_t G2_variable<ppT>::num_variables() {
                    return 2 * Fqe_variable<ppT>::num_variables();
                }

                template<typename ppT>
                G2_checker_gadget<ppT>::G2_checker_gadget(protoboard<FieldType> &pb, const G2_variable<ppT> &Q) :
                    gadget<FieldType>(pb), Q(Q) {
                    Xsquared.reset(new Fqe_variable<ppT>(pb));
                    Ysquared.reset(new Fqe_variable<ppT>(pb));

                    compute_Xsquared.reset(new Fqe_sqr_gadget<ppT>(pb, *(Q.X), *Xsquared));
                    compute_Ysquared.reset(new Fqe_sqr_gadget<ppT>(pb, *(Q.Y), *Ysquared));

                    Xsquared_plus_a.reset(new Fqe_variable<ppT>((*Xsquared) + algebra::G2<other_curve<ppT>>::coeff_a));
                    Ysquared_minus_b.reset(
                        new Fqe_variable<ppT>((*Ysquared) + (-algebra::G2<other_curve<ppT>>::coeff_b)));

                    curve_equation.reset(new Fqe_mul_gadget<ppT>(pb, *(Q.X), *Xsquared_plus_a, *Ysquared_minus_b));
                }

                template<typename ppT>
                void G2_checker_gadget<ppT>::generate_r1cs_constraints() {
                    compute_Xsquared->generate_r1cs_constraints();
                    compute_Ysquared->generate_r1cs_constraints();
                    curve_equation->generate_r1cs_constraints();
                }

                template<typename ppT>
                void G2_checker_gadget<ppT>::generate_r1cs_witness() {
                    compute_Xsquared->generate_r1cs_witness();
                    compute_Ysquared->generate_r1cs_witness();
                    Xsquared_plus_a->evaluate();
                    curve_equation->generate_r1cs_witness();
                }

                template<typename ppT>
                void test_G2_checker_gadget(const std::string &annotation) {
                    protoboard<algebra::Fr<ppT>> pb;
                    G2_variable<ppT> g(pb, "g");
                    G2_checker_gadget<ppT> g_check(pb, g, "g_check");
                    g_check.generate_r1cs_constraints();

                    printf("positive test\n");
                    g.generate_r1cs_witness(algebra::G2<other_curve<ppT>>::one());
                    g_check.generate_r1cs_witness();
                    assert(pb.is_satisfied());

                    printf("negative test\n");
                    g.generate_r1cs_witness(algebra::G2<other_curve<ppT>>::zero());
                    g_check.generate_r1cs_witness();
                    assert(!pb.is_satisfied());

                    printf("number of constraints for G2 checker (Fr is %s)  = %zu\n",
                           annotation.c_str(),
                           pb.num_constraints());
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // WEIERSTRASS_G2_GADGET_HPP_
