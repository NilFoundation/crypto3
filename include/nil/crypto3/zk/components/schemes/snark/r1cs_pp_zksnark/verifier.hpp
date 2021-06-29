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
// @file Declaration of interfaces for the the R1CS ppzkSNARK verifier component.
//
// The component r1cs_ppzksnark_verifier_component verifiers correct computation of
// r1cs_ppzksnark::verifier_strong_input_consistency. The component is built from two main sub-components:
// - r1cs_ppzksnark_verifier_process_vk_component, which verifies correct computation of
// r1cs_ppzksnark_verifier_process_vk, and
// - r1cs_ppzksnark_online_verifier_component, which verifies correct computation of
// r1cs_ppzksnark_online_verifier_strong_input_consistency. See r1cs_ppzksnark.hpp for description of the aforementioned
// functions.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_R1CS_PPZKSNARK_VERIFIER_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_R1CS_PPZKSNARK_VERIFIER_COMPONENT_HPP

#include <nil/crypto3/algebra/algorithms/pair.hpp>

#include <nil/crypto3/zk/components/packing.hpp>
#include <nil/crypto3/zk/components/conjunction.hpp>
#include <nil/crypto3/zk/components/algebra/curves/weierstrass/element_g1.hpp>
#include <nil/crypto3/zk/components/algebra/curves/weierstrass/element_g2.hpp>
#include <nil/crypto3/zk/components/algebra/pairing/pairing_checks.hpp>
//#include <nil/crypto3/zk/components/algebra/pairing/pairing_params.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_ppzksnark.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace components {

                    using namespace nil::crypto3::algebra::pairing;

                    template<typename CurveType>
                    class r1cs_ppzksnark_proof_variable : public component<typename CurveType::scalar_field_type> {
                    public:
                        typedef typename CurveType::scalar_field_type FieldType;

                        std::shared_ptr<element_g1<CurveType>> g_A_g;
                        std::shared_ptr<element_g1<CurveType>> g_A_h;
                        std::shared_ptr<element_g2<CurveType>> g_B_g;
                        std::shared_ptr<element_g1<CurveType>> g_B_h;
                        std::shared_ptr<element_g1<CurveType>> g_C_g;
                        std::shared_ptr<element_g1<CurveType>> g_C_h;
                        std::shared_ptr<element_g1<CurveType>> g_H;
                        std::shared_ptr<element_g1<CurveType>> g_K;

                        std::vector<std::shared_ptr<element_g1<CurveType>>> all_G1_vars;
                        std::vector<std::shared_ptr<element_g2<CurveType>>> all_G2_vars;

                        std::vector<std::shared_ptr<element_g1_is_well_formed<CurveType>>> all_G1_checkers;
                        std::shared_ptr<element_g2_is_well_formed<CurveType>> G2_checker;

                        blueprint_variable_vector<FieldType> proof_contents;

                        r1cs_ppzksnark_proof_variable(blueprint<FieldType> &bp) : component<FieldType>(bp) {
                            const std::size_t num_G1 = 7;
                            const std::size_t num_G2 = 1;

                            g_A_g.reset(new element_g1<CurveType>(bp));
                            g_A_h.reset(new element_g1<CurveType>(bp));
                            g_B_g.reset(new element_g2<CurveType>(bp));
                            g_B_h.reset(new element_g1<CurveType>(bp));
                            g_C_g.reset(new element_g1<CurveType>(bp));
                            g_C_h.reset(new element_g1<CurveType>(bp));
                            g_H.reset(new element_g1<CurveType>(bp));
                            g_K.reset(new element_g1<CurveType>(bp));

                            all_G1_vars = {g_A_g, g_A_h, g_B_h, g_C_g, g_C_h, g_H, g_K};
                            all_G2_vars = {g_B_g};

                            all_G1_checkers.resize(all_G1_vars.size());

                            for (std::size_t i = 0; i < all_G1_vars.size(); ++i) {
                                all_G1_checkers[i].reset(new element_g1_is_well_formed<CurveType>(bp, *all_G1_vars[i]));
                            }
                            G2_checker.reset(new element_g2_is_well_formed<CurveType>(bp, *g_B_g));

                            assert(all_G1_vars.size() == num_G1);
                            assert(all_G2_vars.size() == num_G2);
                        }
                        void generate_r1cs_constraints() {
                            for (auto &G1_checker : all_G1_checkers) {
                                G1_checker->generate_r1cs_constraints();
                            }

                            G2_checker->generate_r1cs_constraints();
                        }
                        void generate_r1cs_witness(
                            const typename r1cs_ppzksnark<typename CurveType::pairing::pair_curve_type>::proof_type
                                &proof) {
                            std::vector<typename CurveType::pairing::pair_curve_type::g1_type> G1_elems;
                            std::vector<typename CurveType::pairing::pair_curve_type::g2_type> G2_elems;

                            G1_elems = {proof.g_A.g, proof.g_A.h, proof.g_B.h, proof.g_C.g,
                                        proof.g_C.h, proof.g_H,   proof.g_K};
                            G2_elems = {proof.g_B.g};

                            assert(G1_elems.size() == all_G1_vars.size());
                            assert(G2_elems.size() == all_G2_vars.size());

                            for (std::size_t i = 0; i < G1_elems.size(); ++i) {
                                all_G1_vars[i]->generate_r1cs_witness(G1_elems[i]);
                            }

                            for (std::size_t i = 0; i < G2_elems.size(); ++i) {
                                all_G2_vars[i]->generate_r1cs_witness(G2_elems[i]);
                            }

                            for (auto &G1_checker : all_G1_checkers) {
                                G1_checker->generate_r1cs_witness();
                            }

                            G2_checker->generate_r1cs_witness();
                        }
                        static std::size_t size() {
                            const std::size_t num_G1 = 7;
                            const std::size_t num_G2 = 1;
                            return (num_G1 * element_g1<CurveType>::num_field_elems +
                                    num_G2 * element_g2<CurveType>::num_field_elems);
                        }
                    };

                    template<typename CurveType>
                    class r1cs_ppzksnark_verification_key_variable
                        : public component<typename CurveType::scalar_field_type> {
                    public:
                        typedef typename CurveType::scalar_field_type FieldType;

                        std::shared_ptr<element_g2<CurveType>> alphaA_g2;
                        std::shared_ptr<element_g1<CurveType>> alphaB_g1;
                        std::shared_ptr<element_g2<CurveType>> alphaC_g2;
                        std::shared_ptr<element_g2<CurveType>> gamma_g2;
                        std::shared_ptr<element_g1<CurveType>> gamma_beta_g1;
                        std::shared_ptr<element_g2<CurveType>> gamma_beta_g2;
                        std::shared_ptr<element_g2<CurveType>> rC_Z_g2;
                        std::shared_ptr<element_g1<CurveType>> encoded_IC_base;
                        std::vector<std::shared_ptr<element_g1<CurveType>>> encoded_IC_query;

                        blueprint_variable_vector<FieldType> all_bits;
                        blueprint_linear_combination_vector<FieldType> all_vars;
                        std::size_t input_size;

                        std::vector<std::shared_ptr<element_g1<CurveType>>> all_G1_vars;
                        std::vector<std::shared_ptr<element_g2<CurveType>>> all_G2_vars;

                        std::shared_ptr<multipacking_component<FieldType>> packer;

                        // Unfortunately, g++ 4.9 and g++ 5.0 have a bug related to
                        // incorrect inlining of small functions:
                        // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=65307, which
                        // produces wrong assembly even at -O1. The test case at the bug
                        // report is directly derived from this code here. As a temporary
                        // work-around we mark the key functions noinline to hint compiler
                        // that inlining should not be performed.

                        // TODO: remove later, when g++ developers fix the bug.

                        __attribute__((noinline))
                        r1cs_ppzksnark_verification_key_variable(blueprint<FieldType> &bp,
                                                                 const blueprint_variable_vector<FieldType> &all_bits,
                                                                 const std::size_t input_size) :
                            component<FieldType>(bp),
                            all_bits(all_bits), input_size(input_size) {
                            const std::size_t num_G1 = 2 + (input_size + 1);
                            const std::size_t num_G2 = 5;

                            assert(all_bits.size() == (element_g1<CurveType>::size_in_bits() * num_G1 +
                                                       element_g2<CurveType>::size_in_bits() * num_G2));

                            this->alphaA_g2.reset(new element_g2<CurveType>(bp));
                            this->alphaB_g1.reset(new element_g1<CurveType>(bp));
                            this->alphaC_g2.reset(new element_g2<CurveType>(bp));
                            this->gamma_g2.reset(new element_g2<CurveType>(bp));
                            this->gamma_beta_g1.reset(new element_g1<CurveType>(bp));
                            this->gamma_beta_g2.reset(new element_g2<CurveType>(bp));
                            this->rC_Z_g2.reset(new element_g2<CurveType>(bp));

                            all_G1_vars = {this->alphaB_g1, this->gamma_beta_g1};
                            all_G2_vars = {this->alphaA_g2, this->alphaC_g2, this->gamma_g2, this->gamma_beta_g2,
                                           this->rC_Z_g2};

                            this->encoded_IC_query.resize(input_size);
                            this->encoded_IC_base.reset(new element_g1<CurveType>(bp));
                            this->all_G1_vars.emplace_back(this->encoded_IC_base);

                            for (std::size_t i = 0; i < input_size; ++i) {
                                this->encoded_IC_query[i].reset(new element_g1<CurveType>(bp));
                                all_G1_vars.emplace_back(this->encoded_IC_query[i]);
                            }

                            for (auto &G1_var : all_G1_vars) {
                                all_vars.insert(all_vars.end(), G1_var->all_vars.begin(), G1_var->all_vars.end());
                            }

                            for (auto &G2_var : all_G2_vars) {
                                all_vars.insert(all_vars.end(), G2_var->all_vars.begin(), G2_var->all_vars.end());
                            }

                            assert(all_G1_vars.size() == num_G1);
                            assert(all_G2_vars.size() == num_G2);
                            assert(all_vars.size() == (num_G1 * element_g1<CurveType>::num_variables() +
                                                       num_G2 * element_g2<CurveType>::num_variables()));

                            packer.reset(new multipacking_component<FieldType>(
                                bp, all_bits, all_vars, FieldType::size_in_bits()));
                        }
                        void generate_r1cs_constraints(const bool enforce_bitness) {
                            packer->generate_r1cs_constraints(enforce_bitness);
                        }
                        void generate_r1cs_witness(
                            const typename r1cs_ppzksnark<
                                typename CurveType::pairing::pair_curve_type>::verification_key_type &vk) {
                            std::vector<typename CurveType::pairing::pair_curve_type::g1_type> G1_elems;
                            std::vector<typename CurveType::pairing::pair_curve_type::g2_type> G2_elems;

                            G1_elems = {vk.alphaB_g1, vk.gamma_beta_g1};
                            G2_elems = {vk.alphaA_g2, vk.alphaC_g2, vk.gamma_g2, vk.gamma_beta_g2, vk.rC_Z_g2};

                            assert(vk.encoded_IC_query.rest.indices.size() == input_size);
                            G1_elems.emplace_back(vk.encoded_IC_query.first);
                            for (std::size_t i = 0; i < input_size; ++i) {
                                assert(vk.encoded_IC_query.rest.indices[i] == i);
                                G1_elems.emplace_back(vk.encoded_IC_query.rest.values[i]);
                            }

                            assert(G1_elems.size() == all_G1_vars.size());
                            assert(G2_elems.size() == all_G2_vars.size());

                            for (std::size_t i = 0; i < G1_elems.size(); ++i) {
                                all_G1_vars[i]->generate_r1cs_witness(G1_elems[i]);
                            }

                            for (std::size_t i = 0; i < G2_elems.size(); ++i) {
                                all_G2_vars[i]->generate_r1cs_witness(G2_elems[i]);
                            }

                            packer->generate_r1cs_witness_from_packed();
                        }
                        void generate_r1cs_witness(const std::vector<bool> &vk_bits) {
                            all_bits.fill_with_bits(this->bp, vk_bits);
                            packer->generate_r1cs_witness_from_bits();
                        }

                        std::vector<bool> get_bits() const {
                            return all_bits.get_bits(this->bp);
                        }

                        static std::size_t __attribute__((noinline)) size_in_bits(const std::size_t input_size) {
                            const std::size_t num_G1 = 2 + (input_size + 1);
                            const std::size_t num_G2 = 5;
                            const std::size_t result = element_g1<CurveType>::size_in_bits() * num_G1 +
                                                       element_g2<CurveType>::size_in_bits() * num_G2;
                            return result;
                        }

                        static std::vector<bool> get_verification_key_bits(
                            const typename r1cs_ppzksnark<
                                typename CurveType::pairing::pair_curve_type>::verification_key_type &r1cs_vk) {

                            typedef typename CurveType::scalar_field_type FieldType;

                            const std::size_t input_size_in_elts =
                                r1cs_vk.encoded_IC_query.rest.indices
                                    .size();    // this might be approximate for bound verification keys, however they
                                                // are not
                            // supported by r1cs_ppzksnark_verification_key_variable
                            const std::size_t vk_size_in_bits =
                                r1cs_ppzksnark_verification_key_variable<CurveType>::size_in_bits(input_size_in_elts);

                            blueprint<FieldType> bp;
                            blueprint_variable_vector<FieldType> vk_bits;
                            vk_bits.allocate(bp, vk_size_in_bits);
                            r1cs_ppzksnark_verification_key_variable<CurveType> vk(bp, vk_bits, input_size_in_elts);
                            vk.generate_r1cs_witness(r1cs_vk);

                            return vk.get_bits();
                        }
                    };

                    template<typename CurveType>
                    class r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable {
                    public:
                        typedef typename CurveType::scalar_field_type FieldType;

                        std::shared_ptr<element_g1<CurveType>> encoded_IC_base;
                        std::vector<std::shared_ptr<element_g1<CurveType>>> encoded_IC_query;

                        std::shared_ptr<g1_precomputation<CurveType>> vk_alphaB_g1_precomp;
                        std::shared_ptr<g1_precomputation<CurveType>> vk_gamma_beta_g1_precomp;

                        std::shared_ptr<g2_precomputation<CurveType>> pp_G2_one_precomp;
                        std::shared_ptr<g2_precomputation<CurveType>> vk_alphaA_g2_precomp;
                        std::shared_ptr<g2_precomputation<CurveType>> vk_alphaC_g2_precomp;
                        std::shared_ptr<g2_precomputation<CurveType>> vk_gamma_beta_g2_precomp;
                        std::shared_ptr<g2_precomputation<CurveType>> vk_gamma_g2_precomp;
                        std::shared_ptr<g2_precomputation<CurveType>> vk_rC_Z_g2_precomp;

                        r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable() {
                            // will be allocated outside
                        }

                        r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable(
                            blueprint<FieldType> &bp,
                            const typename r1cs_ppzksnark<
                                typename CurveType::pairing::pair_curve_type>::verification_key &r1cs_vk) {

                            encoded_IC_base.reset(new element_g1<CurveType>(bp, r1cs_vk.encoded_IC_query.first));
                            encoded_IC_query.resize(r1cs_vk.encoded_IC_query.rest.indices.size());
                            for (std::size_t i = 0; i < r1cs_vk.encoded_IC_query.rest.indices.size(); ++i) {
                                assert(r1cs_vk.encoded_IC_query.rest.indices[i] == i);
                                encoded_IC_query[i].reset(
                                    new element_g1<CurveType>(bp, r1cs_vk.encoded_IC_query.rest.values[i]));
                            }

                            vk_alphaB_g1_precomp.reset(new g1_precomputation<CurveType>(bp, r1cs_vk.alphaB_g1));
                            vk_gamma_beta_g1_precomp.reset(new g1_precomputation<CurveType>(bp, r1cs_vk.gamma_beta_g1));

                            pp_G2_one_precomp.reset(new g2_precomputation<CurveType>(
                                bp, CurveType::pairing::pair_curve_type::g2_type::value_type::one()));
                            vk_alphaA_g2_precomp.reset(new g2_precomputation<CurveType>(bp, r1cs_vk.alphaA_g2));
                            vk_alphaC_g2_precomp.reset(new g2_precomputation<CurveType>(bp, r1cs_vk.alphaC_g2));
                            vk_gamma_beta_g2_precomp.reset(new g2_precomputation<CurveType>(bp, r1cs_vk.gamma_beta_g2));
                            vk_gamma_g2_precomp.reset(new g2_precomputation<CurveType>(bp, r1cs_vk.gamma_g2));
                            vk_rC_Z_g2_precomp.reset(new g2_precomputation<CurveType>(bp, r1cs_vk.rC_Z_g2));
                        }
                    };

                    template<typename CurveType>
                    class r1cs_ppzksnark_verifier_process_vk_component
                        : public component<typename CurveType::scalar_field_type> {
                    public:
                        typedef typename CurveType::scalar_field_type FieldType;

                        std::shared_ptr<precompute_G1_component<CurveType>> compute_vk_alphaB_g1_precomp;
                        std::shared_ptr<precompute_G1_component<CurveType>> compute_vk_gamma_beta_g1_precomp;

                        std::shared_ptr<precompute_G2_component<CurveType>> compute_vk_alphaA_g2_precomp;
                        std::shared_ptr<precompute_G2_component<CurveType>> compute_vk_alphaC_g2_precomp;
                        std::shared_ptr<precompute_G2_component<CurveType>> compute_vk_gamma_beta_g2_precomp;
                        std::shared_ptr<precompute_G2_component<CurveType>> compute_vk_gamma_g2_precomp;
                        std::shared_ptr<precompute_G2_component<CurveType>> compute_vk_rC_Z_g2_precomp;

                        r1cs_ppzksnark_verification_key_variable<CurveType> vk;
                        r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<CurveType>
                            &pvk;    // important to have a reference here

                        r1cs_ppzksnark_verifier_process_vk_component(
                            blueprint<FieldType> &bp,
                            const r1cs_ppzksnark_verification_key_variable<CurveType> &vk,
                            r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<CurveType> &pvk) :
                            component<FieldType>(bp),
                            vk(vk), pvk(pvk) {
                            pvk.encoded_IC_base = vk.encoded_IC_base;
                            pvk.encoded_IC_query = vk.encoded_IC_query;

                            pvk.vk_alphaB_g1_precomp.reset(new g1_precomputation<CurveType>());
                            pvk.vk_gamma_beta_g1_precomp.reset(new g1_precomputation<CurveType>());

                            pvk.pp_G2_one_precomp.reset(new g2_precomputation<CurveType>());
                            pvk.vk_alphaA_g2_precomp.reset(new g2_precomputation<CurveType>());
                            pvk.vk_alphaC_g2_precomp.reset(new g2_precomputation<CurveType>());
                            pvk.vk_gamma_beta_g2_precomp.reset(new g2_precomputation<CurveType>());
                            pvk.vk_gamma_g2_precomp.reset(new g2_precomputation<CurveType>());
                            pvk.vk_rC_Z_g2_precomp.reset(new g2_precomputation<CurveType>());

                            compute_vk_alphaB_g1_precomp.reset(
                                new precompute_G1_component<CurveType>(bp, *vk.alphaB_g1, *pvk.vk_alphaB_g1_precomp));
                            compute_vk_gamma_beta_g1_precomp.reset(new precompute_G1_component<CurveType>(
                                bp, *vk.gamma_beta_g1, *pvk.vk_gamma_beta_g1_precomp));

                            pvk.pp_G2_one_precomp.reset(new g2_precomputation<CurveType>(
                                bp, CurveType::pairing::pair_curve_type::g2_type::value_type::one()));
                            compute_vk_alphaA_g2_precomp.reset(
                                new precompute_G2_component<CurveType>(bp, *vk.alphaA_g2, *pvk.vk_alphaA_g2_precomp));
                            compute_vk_alphaC_g2_precomp.reset(
                                new precompute_G2_component<CurveType>(bp, *vk.alphaC_g2, *pvk.vk_alphaC_g2_precomp));
                            compute_vk_gamma_beta_g2_precomp.reset(new precompute_G2_component<CurveType>(
                                bp, *vk.gamma_beta_g2, *pvk.vk_gamma_beta_g2_precomp));
                            compute_vk_gamma_g2_precomp.reset(
                                new precompute_G2_component<CurveType>(bp, *vk.gamma_g2, *pvk.vk_gamma_g2_precomp));
                            compute_vk_rC_Z_g2_precomp.reset(
                                new precompute_G2_component<CurveType>(bp, *vk.rC_Z_g2, *pvk.vk_rC_Z_g2_precomp));
                        }

                        void generate_r1cs_constraints() {
                            compute_vk_alphaB_g1_precomp->generate_r1cs_constraints();
                            compute_vk_gamma_beta_g1_precomp->generate_r1cs_constraints();

                            compute_vk_alphaA_g2_precomp->generate_r1cs_constraints();
                            compute_vk_alphaC_g2_precomp->generate_r1cs_constraints();
                            compute_vk_gamma_beta_g2_precomp->generate_r1cs_constraints();
                            compute_vk_gamma_g2_precomp->generate_r1cs_constraints();
                            compute_vk_rC_Z_g2_precomp->generate_r1cs_constraints();
                        }

                        void generate_r1cs_witness() {
                            compute_vk_alphaB_g1_precomp->generate_r1cs_witness();
                            compute_vk_gamma_beta_g1_precomp->generate_r1cs_witness();

                            compute_vk_alphaA_g2_precomp->generate_r1cs_witness();
                            compute_vk_alphaC_g2_precomp->generate_r1cs_witness();
                            compute_vk_gamma_beta_g2_precomp->generate_r1cs_witness();
                            compute_vk_gamma_g2_precomp->generate_r1cs_witness();
                            compute_vk_rC_Z_g2_precomp->generate_r1cs_witness();
                        }
                    };

                    template<typename CurveType>
                    class r1cs_ppzksnark_online_verifier_component
                        : public component<typename CurveType::scalar_field_type> {
                    public:
                        typedef typename CurveType::scalar_field_type FieldType;

                        r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<CurveType> pvk;

                        blueprint_variable_vector<FieldType> input;
                        std::size_t elt_size;
                        r1cs_ppzksnark_proof_variable<CurveType> proof;
                        blueprint_variable<FieldType> result;
                        const std::size_t input_len;

                        std::shared_ptr<element_g1<CurveType>> acc;
                        std::shared_ptr<G1_multiscalar_mul_component<CurveType>> accumulate_input;

                        std::shared_ptr<element_g1<CurveType>> proof_g_A_g_acc;
                        std::shared_ptr<element_g1_add<CurveType>> compute_proof_g_A_g_acc;
                        std::shared_ptr<element_g1<CurveType>> proof_g_A_g_acc_C;
                        std::shared_ptr<element_g1_add<CurveType>> compute_proof_g_A_g_acc_C;

                        std::shared_ptr<g1_precomputation<CurveType>> proof_g_A_h_precomp;
                        std::shared_ptr<g1_precomputation<CurveType>> proof_g_A_g_acc_C_precomp;
                        std::shared_ptr<g1_precomputation<CurveType>> proof_g_A_g_acc_precomp;
                        std::shared_ptr<g1_precomputation<CurveType>> proof_g_A_g_precomp;
                        std::shared_ptr<g1_precomputation<CurveType>> proof_g_B_h_precomp;
                        std::shared_ptr<g1_precomputation<CurveType>> proof_g_C_h_precomp;
                        std::shared_ptr<g1_precomputation<CurveType>> proof_g_C_g_precomp;
                        std::shared_ptr<g1_precomputation<CurveType>> proof_g_K_precomp;
                        std::shared_ptr<g1_precomputation<CurveType>> proof_g_H_precomp;

                        std::shared_ptr<g2_precomputation<CurveType>> proof_g_B_g_precomp;

                        std::shared_ptr<precompute_G1_component<CurveType>> compute_proof_g_A_h_precomp;
                        std::shared_ptr<precompute_G1_component<CurveType>> compute_proof_g_A_g_acc_C_precomp;
                        std::shared_ptr<precompute_G1_component<CurveType>> compute_proof_g_A_g_acc_precomp;
                        std::shared_ptr<precompute_G1_component<CurveType>> compute_proof_g_A_g_precomp;
                        std::shared_ptr<precompute_G1_component<CurveType>> compute_proof_g_B_h_precomp;
                        std::shared_ptr<precompute_G1_component<CurveType>> compute_proof_g_C_h_precomp;
                        std::shared_ptr<precompute_G1_component<CurveType>> compute_proof_g_C_g_precomp;
                        std::shared_ptr<precompute_G1_component<CurveType>> compute_proof_g_K_precomp;
                        std::shared_ptr<precompute_G1_component<CurveType>> compute_proof_g_H_precomp;

                        std::shared_ptr<precompute_G2_component<CurveType>> compute_proof_g_B_g_precomp;

                        std::shared_ptr<check_e_equals_e_component<CurveType>> check_kc_A_valid;
                        std::shared_ptr<check_e_equals_e_component<CurveType>> check_kc_B_valid;
                        std::shared_ptr<check_e_equals_e_component<CurveType>> check_kc_C_valid;
                        std::shared_ptr<check_e_equals_ee_component<CurveType>> check_QAP_valid;
                        std::shared_ptr<check_e_equals_ee_component<CurveType>> check_CC_valid;

                        blueprint_variable<FieldType> kc_A_valid;
                        blueprint_variable<FieldType> kc_B_valid;
                        blueprint_variable<FieldType> kc_C_valid;
                        blueprint_variable<FieldType> QAP_valid;
                        blueprint_variable<FieldType> CC_valid;

                        blueprint_variable_vector<FieldType> all_test_results;
                        std::shared_ptr<conjunction<FieldType>> all_tests_pass;

                        r1cs_ppzksnark_online_verifier_component(
                            blueprint<FieldType> &bp,
                            const r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<CurveType> &pvk,
                            const blueprint_variable_vector<FieldType> &input,
                            const std::size_t elt_size,
                            const r1cs_ppzksnark_proof_variable<CurveType> &proof,
                            const blueprint_variable<FieldType> &result) :
                            component<FieldType>(bp),
                            pvk(pvk), input(input), elt_size(elt_size), proof(proof), result(result),
                            input_len(input.size()) {
                            // accumulate input and store base in acc
                            acc.reset(new element_g1<CurveType>(bp));
                            std::vector<element_g1<CurveType>> IC_terms;
                            for (std::size_t i = 0; i < pvk.encoded_IC_query.size(); ++i) {
                                IC_terms.emplace_back(*(pvk.encoded_IC_query[i]));
                            }
                            accumulate_input.reset(new G1_multiscalar_mul_component<CurveType>(
                                bp, *(pvk.encoded_IC_base), input, elt_size, IC_terms, *acc));

                            // allocate results for precomputation
                            proof_g_A_h_precomp.reset(new g1_precomputation<CurveType>());
                            proof_g_A_g_acc_C_precomp.reset(new g1_precomputation<CurveType>());
                            proof_g_A_g_acc_precomp.reset(new g1_precomputation<CurveType>());
                            proof_g_A_g_precomp.reset(new g1_precomputation<CurveType>());
                            proof_g_B_h_precomp.reset(new g1_precomputation<CurveType>());
                            proof_g_C_h_precomp.reset(new g1_precomputation<CurveType>());
                            proof_g_C_g_precomp.reset(new g1_precomputation<CurveType>());
                            proof_g_K_precomp.reset(new g1_precomputation<CurveType>());
                            proof_g_H_precomp.reset(new g1_precomputation<CurveType>());

                            proof_g_B_g_precomp.reset(new g2_precomputation<CurveType>());

                            // do the necessary precomputations
                            // compute things not available in plain from proof/vk
                            proof_g_A_g_acc.reset(new element_g1<CurveType>(bp));
                            compute_proof_g_A_g_acc.reset(
                                new element_g1_add<CurveType>(bp, *(proof.g_A_g), *acc, *proof_g_A_g_acc));
                            proof_g_A_g_acc_C.reset(new element_g1<CurveType>(bp));
                            compute_proof_g_A_g_acc_C.reset(new element_g1_add<CurveType>(
                                bp, *proof_g_A_g_acc, *(proof.g_C_g), *proof_g_A_g_acc_C));

                            compute_proof_g_A_g_acc_precomp.reset(
                                new precompute_G1_component<CurveType>(bp, *proof_g_A_g_acc, *proof_g_A_g_acc_precomp));
                            compute_proof_g_A_g_acc_C_precomp.reset(new precompute_G1_component<CurveType>(
                                bp, *proof_g_A_g_acc_C, *proof_g_A_g_acc_C_precomp));

                            // do other precomputations
                            compute_proof_g_A_h_precomp.reset(
                                new precompute_G1_component<CurveType>(bp, *(proof.g_A_h), *proof_g_A_h_precomp));
                            compute_proof_g_A_g_precomp.reset(
                                new precompute_G1_component<CurveType>(bp, *(proof.g_A_g), *proof_g_A_g_precomp));
                            compute_proof_g_B_h_precomp.reset(
                                new precompute_G1_component<CurveType>(bp, *(proof.g_B_h), *proof_g_B_h_precomp));
                            compute_proof_g_C_h_precomp.reset(
                                new precompute_G1_component<CurveType>(bp, *(proof.g_C_h), *proof_g_C_h_precomp));
                            compute_proof_g_C_g_precomp.reset(
                                new precompute_G1_component<CurveType>(bp, *(proof.g_C_g), *proof_g_C_g_precomp));
                            compute_proof_g_H_precomp.reset(
                                new precompute_G1_component<CurveType>(bp, *(proof.g_H), *proof_g_H_precomp));
                            compute_proof_g_K_precomp.reset(
                                new precompute_G1_component<CurveType>(bp, *(proof.g_K), *proof_g_K_precomp));
                            compute_proof_g_B_g_precomp.reset(
                                new precompute_G2_component<CurveType>(bp, *(proof.g_B_g), *proof_g_B_g_precomp));

                            // check validity of A knowledge commitment
                            kc_A_valid.allocate(bp);
                            check_kc_A_valid.reset(
                                new check_e_equals_e_component<CurveType>(bp,
                                                                          *proof_g_A_g_precomp,
                                                                          *(pvk.vk_alphaA_g2_precomp),
                                                                          *proof_g_A_h_precomp,
                                                                          *(pvk.pp_G2_one_precomp),
                                                                          kc_A_valid));

                            // check validity of B knowledge commitment
                            kc_B_valid.allocate(bp);
                            check_kc_B_valid.reset(
                                new check_e_equals_e_component<CurveType>(bp,
                                                                          *(pvk.vk_alphaB_g1_precomp),
                                                                          *proof_g_B_g_precomp,
                                                                          *proof_g_B_h_precomp,
                                                                          *(pvk.pp_G2_one_precomp),
                                                                          kc_B_valid));

                            // check validity of C knowledge commitment
                            kc_C_valid.allocate(bp);
                            check_kc_C_valid.reset(
                                new check_e_equals_e_component<CurveType>(bp,
                                                                          *proof_g_C_g_precomp,
                                                                          *(pvk.vk_alphaC_g2_precomp),
                                                                          *proof_g_C_h_precomp,
                                                                          *(pvk.pp_G2_one_precomp),
                                                                          kc_C_valid));

                            // check QAP divisibility
                            QAP_valid.allocate(bp);
                            check_QAP_valid.reset(new check_e_equals_ee_component<CurveType>(bp,
                                                                                             *proof_g_A_g_acc_precomp,
                                                                                             *proof_g_B_g_precomp,
                                                                                             *proof_g_H_precomp,
                                                                                             *(pvk.vk_rC_Z_g2_precomp),
                                                                                             *proof_g_C_g_precomp,
                                                                                             *(pvk.pp_G2_one_precomp),
                                                                                             QAP_valid));

                            // check coefficients
                            CC_valid.allocate(bp);
                            check_CC_valid.reset(
                                new check_e_equals_ee_component<CurveType>(bp,
                                                                           *proof_g_K_precomp,
                                                                           *(pvk.vk_gamma_g2_precomp),
                                                                           *proof_g_A_g_acc_C_precomp,
                                                                           *(pvk.vk_gamma_beta_g2_precomp),
                                                                           *(pvk.vk_gamma_beta_g1_precomp),
                                                                           *proof_g_B_g_precomp,
                                                                           CC_valid));

                            // final constraint
                            all_test_results.emplace_back(kc_A_valid);
                            all_test_results.emplace_back(kc_B_valid);
                            all_test_results.emplace_back(kc_C_valid);
                            all_test_results.emplace_back(QAP_valid);
                            all_test_results.emplace_back(CC_valid);

                            all_tests_pass.reset(new conjunction<FieldType>(bp, all_test_results, result));
                        }

                        void generate_r1cs_constraints() {
                            accumulate_input->generate_r1cs_constraints();

                            compute_proof_g_A_g_acc->generate_r1cs_constraints();
                            compute_proof_g_A_g_acc_C->generate_r1cs_constraints();

                            compute_proof_g_A_g_acc_precomp->generate_r1cs_constraints();
                            compute_proof_g_A_g_acc_C_precomp->generate_r1cs_constraints();

                            compute_proof_g_A_h_precomp->generate_r1cs_constraints();
                            compute_proof_g_A_g_precomp->generate_r1cs_constraints();
                            compute_proof_g_B_h_precomp->generate_r1cs_constraints();
                            compute_proof_g_C_h_precomp->generate_r1cs_constraints();
                            compute_proof_g_C_g_precomp->generate_r1cs_constraints();
                            compute_proof_g_H_precomp->generate_r1cs_constraints();
                            compute_proof_g_K_precomp->generate_r1cs_constraints();
                            compute_proof_g_B_g_precomp->generate_r1cs_constraints();

                            check_kc_A_valid->generate_r1cs_constraints();
                            check_kc_B_valid->generate_r1cs_constraints();
                            check_kc_C_valid->generate_r1cs_constraints();
                            check_QAP_valid->generate_r1cs_constraints();
                            check_CC_valid->generate_r1cs_constraints();

                            all_tests_pass->generate_r1cs_constraints();
                        }

                        void generate_r1cs_witness() {
                            accumulate_input->generate_r1cs_witness();

                            compute_proof_g_A_g_acc->generate_r1cs_witness();
                            compute_proof_g_A_g_acc_C->generate_r1cs_witness();

                            compute_proof_g_A_g_acc_precomp->generate_r1cs_witness();
                            compute_proof_g_A_g_acc_C_precomp->generate_r1cs_witness();

                            compute_proof_g_A_h_precomp->generate_r1cs_witness();
                            compute_proof_g_A_g_precomp->generate_r1cs_witness();
                            compute_proof_g_B_h_precomp->generate_r1cs_witness();
                            compute_proof_g_C_h_precomp->generate_r1cs_witness();
                            compute_proof_g_C_g_precomp->generate_r1cs_witness();
                            compute_proof_g_H_precomp->generate_r1cs_witness();
                            compute_proof_g_K_precomp->generate_r1cs_witness();
                            compute_proof_g_B_g_precomp->generate_r1cs_witness();

                            check_kc_A_valid->generate_r1cs_witness();
                            check_kc_B_valid->generate_r1cs_witness();
                            check_kc_C_valid->generate_r1cs_witness();
                            check_QAP_valid->generate_r1cs_witness();
                            check_CC_valid->generate_r1cs_witness();

                            all_tests_pass->generate_r1cs_witness();
                        }
                    };

                    template<typename CurveType>
                    class r1cs_ppzksnark_verifier_component : public component<typename CurveType::scalar_field_type> {
                    public:
                        typedef typename CurveType::scalar_field_type FieldType;

                        std::shared_ptr<r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<CurveType>>
                            pvk;
                        std::shared_ptr<r1cs_ppzksnark_verifier_process_vk_component<CurveType>> compute_pvk;
                        std::shared_ptr<r1cs_ppzksnark_online_verifier_component<CurveType>> online_verifier;

                        r1cs_ppzksnark_verifier_component(blueprint<FieldType> &bp,
                                                          const r1cs_ppzksnark_verification_key_variable<CurveType> &vk,
                                                          const blueprint_variable_vector<FieldType> &input,
                                                          const std::size_t elt_size,
                                                          const r1cs_ppzksnark_proof_variable<CurveType> &proof,
                                                          const blueprint_variable<FieldType> &result) :
                            component<FieldType>(bp) {
                            pvk.reset(
                                new r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<CurveType>());
                            compute_pvk.reset(
                                new r1cs_ppzksnark_verifier_process_vk_component<CurveType>(bp, vk, *pvk));
                            online_verifier.reset(new r1cs_ppzksnark_online_verifier_component<CurveType>(
                                bp, *pvk, input, elt_size, proof, result));
                        }

                        void generate_r1cs_constraints() {
                            compute_pvk->generate_r1cs_constraints();

                            online_verifier->generate_r1cs_constraints();
                        }

                        void generate_r1cs_witness() {
                            compute_pvk->generate_r1cs_witness();
                            online_verifier->generate_r1cs_witness();
                        }
                    };
                }    // namespace components
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_R1CS_PPZKSNARK_VERIFIER_COMPONENT_HPP
