//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for G2 components.
//
// The components verify curve arithmetic in G2 = E'(F) where E'/F^e: y^2 = x^3 + A' * X + B'
// is an elliptic curve over F^e in short Weierstrass form.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_WEIERSTRASS_G2_COMPONENT_HPP
#define CRYPTO3_ZK_WEIERSTRASS_G2_COMPONENT_HPP

#include <memory>

#include <nil/crypto3/algebra/algorithms/pairing.hpp>
#include <nil/crypto3/algebra/pairing/types.hpp>

#include <nil/crypto3/zk/snark/component.hpp>
#include <nil/crypto3/zk/snark/components/curves/detail/mnt4.hpp>
#include <nil/crypto3/zk/snark/components/curves/detail/mnt6.hpp>

#include <nil/crypto3/zk/snark/blueprint_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace components {

                    using namespace nil::crypto3::algebra::pairings;

                    /**
                     * Gadget that represents a G2 variable.
                     */
                    template<typename CurveType>
                    class G2_variable : public component<typename CurveType::scalar_field_type> {
                        using field_type = typename CurveType::pairing_policy::Fp_type;

                        using fqe_type = typename other_curve_type<CurveType>::pairing_policy::Fqe_type;
                        using fqk_type = typename other_curve_type<CurveType>::pairing_policy::Fqk_type;

                        using component_policy = basic_curve_component_policy<CurveType>;

                    public:

                        std::shared_ptr<typename component_policy::Fqe_variable_type> X;
                        std::shared_ptr<typename component_policy::Fqe_variable_type> Y;

                        blueprint_linear_combination_vector<field_type> all_vars;

                        G2_variable(blueprint<field_type> &bp) : component<field_type>(bp) {
                            X.reset(new typename component_policy::Fqe_variable_type(bp));
                            Y.reset(new typename component_policy::Fqe_variable_type(bp));

                            all_vars.insert(all_vars.end(), X->all_vars.begin(), X->all_vars.end());
                            all_vars.insert(all_vars.end(), Y->all_vars.begin(), Y->all_vars.end());
                        }
                        G2_variable(blueprint<field_type> &bp,
                                    const typename other_curve_type<CurveType>::g2_type::value_type &Q) :
                            component<field_type>(bp) {
                            typename other_curve_type<CurveType>::g2_type::value_type Q_copy = Q.to_affine_coordinates();

                            X.reset(new typename component_policy::Fqe_variable_type(bp, Q_copy.X));
                            Y.reset(new typename component_policy::Fqe_variable_type(bp, Q_copy.Y));

                            all_vars.insert(all_vars.end(), X->all_vars.begin(), X->all_vars.end());
                            all_vars.insert(all_vars.end(), Y->all_vars.begin(), Y->all_vars.end());
                        }

                        void generate_r1cs_witness(const typename other_curve_type<CurveType>::g2_type::value_type &Q) {
                            typename other_curve_type<CurveType>::g2_type::value_type Qcopy = Q.to_affine_coordinates();

                            X->generate_r1cs_witness(Qcopy.X);
                            Y->generate_r1cs_witness(Qcopy.Y);
                        }

                        // (See a comment in r1cs_ppzksnark_verifier_component.hpp about why
                        // we mark this function noinline.) TODO: remove later
                        static std::size_t __attribute__((noinline)) size_in_bits() {
                            return 2 * typename component_policy::Fqe_variable_type::size_in_bits();
                        }
                        static std::size_t num_variables() {
                            return 2 * typename component_policy::Fqe_variable_type::num_variables();
                        }
                    };

                    /**
                     * Gadget that creates constraints for the validity of a G2 variable.
                     */
                    template<typename CurveType>
                    class G2_checker_component : public component<typename CurveType::scalar_field_type> {
                        typedef typename CurveType::pairing_policy::Fp_type field_type;
                        using fqe_type = typename other_curve_type<CurveType>::pairing_policy::Fqe_type;
                        using fqk_type = typename other_curve_type<CurveType>::pairing_policy::Fqk_type;

                        using component_policy = basic_curve_component_policy<CurveType>;

                    public:

                        G2_variable<CurveType> Q;

                        std::shared_ptr<typename component_policy::Fqe_variable_type> Xsquared;
                        std::shared_ptr<typename component_policy::Fqe_variable_type> Ysquared;
                        std::shared_ptr<typename component_policy::Fqe_variable_type> Xsquared_plus_a;
                        std::shared_ptr<typename component_policy::Fqe_variable_type> Ysquared_minus_b;

                        std::shared_ptr<typename component_policy::Fqe_sqr_component_type> compute_Xsquared;
                        std::shared_ptr<typename component_policy::Fqe_sqr_component_type> compute_Ysquared;
                        std::shared_ptr<typename component_policy::Fqe_mul_component_type> curve_equation;

                        G2_checker_component(blueprint<field_type> &bp, const G2_variable<CurveType> &Q) :
                            component<field_type>(bp), Q(Q) {
                            Xsquared.reset(new typename component_policy::Fqe_variable_type(bp));
                            Ysquared.reset(new typename component_policy::Fqe_variable_type(bp));

                            compute_Xsquared.reset(new typename component_policy::Fqe_sqr_component_type(bp, *(Q.X), *Xsquared));
                            compute_Ysquared.reset(new typename component_policy::Fqe_sqr_component_type(bp, *(Q.Y), *Ysquared));

                            Xsquared_plus_a.reset(
                                new typename component_policy::Fqe_variable_type((*Xsquared) + other_curve_type<CurveType>::a));
                            Ysquared_minus_b.reset(
                                new typename component_policy::Fqe_variable_type((*Ysquared) + (-other_curve_type<CurveType>::b)));

                            curve_equation.reset(
                                new typename component_policy::Fqe_mul_component_type(bp, *(Q.X), *Xsquared_plus_a, *Ysquared_minus_b));
                        }

                        void generate_r1cs_constraints() {
                            compute_Xsquared->generate_r1cs_constraints();
                            compute_Ysquared->generate_r1cs_constraints();
                            curve_equation->generate_r1cs_constraints();
                        }
                        void generate_r1cs_witness() {
                            compute_Xsquared->generate_r1cs_witness();
                            compute_Ysquared->generate_r1cs_witness();
                            Xsquared_plus_a->evaluate();
                            curve_equation->generate_r1cs_witness();
                        }
                    };
                }    // namespace components
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_WEIERSTRASS_G2_COMPONENT_HPP
