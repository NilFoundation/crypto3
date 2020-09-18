//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_WEIERSTRASS_G2_GADGET_HPP_
#define CRYPTO3_ZK_WEIERSTRASS_G2_GADGET_HPP_

#include <memory>

#include <nil/crypto3/zk/snark/component.hpp>
#include <nil/crypto3/zk/snark/components/pairing/pairing_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Gadget that represents a G2 variable.
                 */
                template<typename CurveType>
                class G2_variable : public component<typename CurveType::scalar_field_type> {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;
                    typedef algebra::Fqe<other_curve<CurveType>> fqe_type;
                    typedef algebra::Fqk<other_curve<CurveType>> fqk_type;

                    std::shared_ptr<Fqe_variable<CurveType>> X;
                    std::shared_ptr<Fqe_variable<CurveType>> Y;

                    pb_linear_combination_array<FieldType> all_vars;

                    G2_variable(blueprint<FieldType> &pb);
                    G2_variable(blueprint<FieldType> &pb, const other_curve<CurveType>::g2_type &Q);

                    void generate_r1cs_witness(const other_curve<CurveType>::g2_type &Q);

                    // (See a comment in r1cs_ppzksnark_verifier_gadget.hpp about why
                    // we mark this function noinline.) TODO: remove later
                    static std::size_t __attribute__((noinline)) size_in_bits();
                    static std::size_t num_variables();
                };

                /**
                 * Gadget that creates constraints for the validity of a G2 variable.
                 */
                template<typename CurveType>
                class G2_checker_gadget : public component<typename CurveType::scalar_field_type> {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;
                    typedef algebra::Fqe<other_curve<CurveType>> fqe_type;
                    typedef algebra::Fqk<other_curve<CurveType>> fqk_type;

                    G2_variable<CurveType> Q;

                    std::shared_ptr<Fqe_variable<CurveType>> Xsquared;
                    std::shared_ptr<Fqe_variable<CurveType>> Ysquared;
                    std::shared_ptr<Fqe_variable<CurveType>> Xsquared_plus_a;
                    std::shared_ptr<Fqe_variable<CurveType>> Ysquared_minus_b;

                    std::shared_ptr<Fqe_sqr_gadget<CurveType>> compute_Xsquared;
                    std::shared_ptr<Fqe_sqr_gadget<CurveType>> compute_Ysquared;
                    std::shared_ptr<Fqe_mul_gadget<CurveType>> curve_equation;

                    G2_checker_gadget(blueprint<FieldType> &pb, const G2_variable<CurveType> &Q);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename CurveType>
                G2_variable<CurveType>::G2_variable(blueprint<FieldType> &pb) : component<FieldType>(pb) {
                    X.reset(new Fqe_variable<CurveType>(pb));
                    Y.reset(new Fqe_variable<CurveType>(pb));

                    all_vars.insert(all_vars.end(), X->all_vars.begin(), X->all_vars.end());
                    all_vars.insert(all_vars.end(), Y->all_vars.begin(), Y->all_vars.end());
                }

                template<typename CurveType>
                G2_variable<CurveType>::G2_variable(blueprint<FieldType> &pb, const other_curve<CurveType>::g2_type &Q) :
                    component<FieldType>(pb) {
                    other_curve<CurveType>::g2_type Q_copy = Q;
                    Q_copy.to_affine_coordinates();

                    X.reset(new Fqe_variable<CurveType>(pb, Q_copy.X()));
                    Y.reset(new Fqe_variable<CurveType>(pb, Q_copy.Y()));

                    all_vars.insert(all_vars.end(), X->all_vars.begin(), X->all_vars.end());
                    all_vars.insert(all_vars.end(), Y->all_vars.begin(), Y->all_vars.end());
                }

                template<typename CurveType>
                void G2_variable<CurveType>::generate_r1cs_witness(const other_curve<CurveType>::g2_type &Q) {
                    other_curve<CurveType>::g2_type Qcopy = Q;
                    Qcopy.to_affine_coordinates();

                    X->generate_r1cs_witness(Qcopy.X());
                    Y->generate_r1cs_witness(Qcopy.Y());
                }

                template<typename CurveType>
                std::size_t G2_variable<CurveType>::size_in_bits() {
                    return 2 * Fqe_variable<CurveType>::size_in_bits();
                }

                template<typename CurveType>
                std::size_t G2_variable<CurveType>::num_variables() {
                    return 2 * Fqe_variable<CurveType>::num_variables();
                }

                template<typename CurveType>
                G2_checker_gadget<CurveType>::G2_checker_gadget(blueprint<FieldType> &pb, const G2_variable<CurveType> &Q) :
                    component<FieldType>(pb), Q(Q) {
                    Xsquared.reset(new Fqe_variable<CurveType>(pb));
                    Ysquared.reset(new Fqe_variable<CurveType>(pb));

                    compute_Xsquared.reset(new Fqe_sqr_gadget<CurveType>(pb, *(Q.X), *Xsquared));
                    compute_Ysquared.reset(new Fqe_sqr_gadget<CurveType>(pb, *(Q.Y), *Ysquared));

                    Xsquared_plus_a.reset(new Fqe_variable<CurveType>((*Xsquared) + other_curve<CurveType>::g2_type::a));
                    Ysquared_minus_b.reset(
                        new Fqe_variable<CurveType>((*Ysquared) + (-other_curve<CurveType>::g2_type::b)));

                    curve_equation.reset(new Fqe_mul_gadget<CurveType>(pb, *(Q.X), *Xsquared_plus_a, *Ysquared_minus_b));
                }

                template<typename CurveType>
                void G2_checker_gadget<CurveType>::generate_r1cs_constraints() {
                    compute_Xsquared->generate_r1cs_constraints();
                    compute_Ysquared->generate_r1cs_constraints();
                    curve_equation->generate_r1cs_constraints();
                }

                template<typename CurveType>
                void G2_checker_gadget<CurveType>::generate_r1cs_witness() {
                    compute_Xsquared->generate_r1cs_witness();
                    compute_Ysquared->generate_r1cs_witness();
                    Xsquared_plus_a->evaluate();
                    curve_equation->generate_r1cs_witness();
                }

                template<typename CurveType>
                void test_G2_checker_gadget(const std::string &annotation) {
                    blueprint<typename CurveType::scalar_field_type> pb;
                    G2_variable<CurveType> g(pb);
                    G2_checker_gadget<CurveType> g_check(pb, g);
                    g_check.generate_r1cs_constraints();

                    printf("positive test\n");
                    g.generate_r1cs_witness(other_curve<CurveType>::g2_type::one());
                    g_check.generate_r1cs_witness();
                    assert(pb.is_satisfied());

                    printf("negative test\n");
                    g.generate_r1cs_witness(other_curve<CurveType>::g2_type::zero());
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
