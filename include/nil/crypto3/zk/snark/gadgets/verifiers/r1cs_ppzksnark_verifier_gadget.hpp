//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the the R1CS ppzkSNARK verifier gadget.
//
// The gadget r1cs_ppzksnark_verifier_gadget verifiers correct computation of r1cs_ppzksnark_verifier_strong_IC.
// The gadget is built from two main sub-gadgets:
// - r1cs_ppzksnark_verifier_process_vk_gadget, which verifies correct computation of
// r1cs_ppzksnark_verifier_process_vk, and
// - r1cs_ppzksnark_online_verifier_gadget, which verifies correct computation of
// r1cs_ppzksnark_online_verifier_strong_IC. See r1cs_ppzksnark.hpp for description of the aforementioned functions.
//---------------------------------------------------------------------------//

#ifndef R1CS_PPZKSNARK_VERIFIER_GADGET_HPP_
#define R1CS_PPZKSNARK_VERIFIER_GADGET_HPP_

#include <nil/crypto3/zk/snark/gadgets/basic_gadgets.hpp>
#include <nil/crypto3/zk/snark/gadgets/curves/weierstrass_g1_gadget.hpp>
#include <nil/crypto3/zk/snark/gadgets/curves/weierstrass_g2_gadget.hpp>
#include <nil/crypto3/zk/snark/gadgets/pairing/pairing_checks.hpp>
#include <nil/crypto3/zk/snark/gadgets/pairing/pairing_params.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename ppT>
                class r1cs_ppzksnark_proof_variable : public gadget<algebra::Fr<ppT>> {
                public:
                    typedef algebra::Fr<ppT> FieldType;

                    std::shared_ptr<G1_variable<ppT>> g_A_g;
                    std::shared_ptr<G1_variable<ppT>> g_A_h;
                    std::shared_ptr<G2_variable<ppT>> g_B_g;
                    std::shared_ptr<G1_variable<ppT>> g_B_h;
                    std::shared_ptr<G1_variable<ppT>> g_C_g;
                    std::shared_ptr<G1_variable<ppT>> g_C_h;
                    std::shared_ptr<G1_variable<ppT>> g_H;
                    std::shared_ptr<G1_variable<ppT>> g_K;

                    std::vector<std::shared_ptr<G1_variable<ppT>>> all_G1_vars;
                    std::vector<std::shared_ptr<G2_variable<ppT>>> all_G2_vars;

                    std::vector<std::shared_ptr<G1_checker_gadget<ppT>>> all_G1_checkers;
                    std::shared_ptr<G2_checker_gadget<ppT>> G2_checker;

                    pb_variable_array<FieldType> proof_contents;

                    r1cs_ppzksnark_proof_variable(protoboard<FieldType> &pb);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness(const r1cs_ppzksnark_proof<other_curve<ppT>> &proof);
                    static size_t size();
                };

                template<typename ppT>
                class r1cs_ppzksnark_verification_key_variable : public gadget<algebra::Fr<ppT>> {
                public:
                    typedef algebra::Fr<ppT> FieldType;

                    std::shared_ptr<G2_variable<ppT>> alphaA_g2;
                    std::shared_ptr<G1_variable<ppT>> alphaB_g1;
                    std::shared_ptr<G2_variable<ppT>> alphaC_g2;
                    std::shared_ptr<G2_variable<ppT>> gamma_g2;
                    std::shared_ptr<G1_variable<ppT>> gamma_beta_g1;
                    std::shared_ptr<G2_variable<ppT>> gamma_beta_g2;
                    std::shared_ptr<G2_variable<ppT>> rC_Z_g2;
                    std::shared_ptr<G1_variable<ppT>> encoded_IC_base;
                    std::vector<std::shared_ptr<G1_variable<ppT>>> encoded_IC_query;

                    pb_variable_array<FieldType> all_bits;
                    pb_linear_combination_array<FieldType> all_vars;
                    size_t input_size;

                    std::vector<std::shared_ptr<G1_variable<ppT>>> all_G1_vars;
                    std::vector<std::shared_ptr<G2_variable<ppT>>> all_G2_vars;

                    std::shared_ptr<multipacking_gadget<FieldType>> packer;

                    // Unfortunately, g++ 4.9 and g++ 5.0 have a bug related to
                    // incorrect inlining of small functions:
                    // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=65307, which
                    // produces wrong assembly even at -O1. The test case at the bug
                    // report is directly derived from this code here. As a temporary
                    // work-around we mark the key functions noinline to hint compiler
                    // that inlining should not be performed.

                    // TODO: remove later, when g++ developers fix the bug.

                    __attribute__((noinline))
                    r1cs_ppzksnark_verification_key_variable(protoboard<FieldType> &pb,
                                                             const pb_variable_array<FieldType> &all_bits,
                                                             const size_t input_size);
                    void generate_r1cs_constraints(const bool enforce_bitness);
                    void generate_r1cs_witness(const r1cs_ppzksnark_verification_key<other_curve<ppT>> &vk);
                    void generate_r1cs_witness(const std::vector<bool> &vk_bits);
                    std::vector<bool> get_bits() const;
                    static size_t __attribute__((noinline)) size_in_bits(const size_t input_size);
                    static std::vector<bool>
                        get_verification_key_bits(const r1cs_ppzksnark_verification_key<other_curve<ppT>> &r1cs_vk);
                };

                template<typename ppT>
                class r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable {
                public:
                    typedef algebra::Fr<ppT> FieldType;

                    std::shared_ptr<G1_variable<ppT>> encoded_IC_base;
                    std::vector<std::shared_ptr<G1_variable<ppT>>> encoded_IC_query;

                    std::shared_ptr<G1_precomputation<ppT>> vk_alphaB_g1_precomp;
                    std::shared_ptr<G1_precomputation<ppT>> vk_gamma_beta_g1_precomp;

                    std::shared_ptr<G2_precomputation<ppT>> pp_G2_one_precomp;
                    std::shared_ptr<G2_precomputation<ppT>> vk_alphaA_g2_precomp;
                    std::shared_ptr<G2_precomputation<ppT>> vk_alphaC_g2_precomp;
                    std::shared_ptr<G2_precomputation<ppT>> vk_gamma_beta_g2_precomp;
                    std::shared_ptr<G2_precomputation<ppT>> vk_gamma_g2_precomp;
                    std::shared_ptr<G2_precomputation<ppT>> vk_rC_Z_g2_precomp;

                    r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable();
                    r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable(
                        protoboard<FieldType> &pb,
                        const r1cs_ppzksnark_verification_key<other_curve<ppT>> &r1cs_vk);
                };

                template<typename ppT>
                class r1cs_ppzksnark_verifier_process_vk_gadget : public gadget<algebra::Fr<ppT>> {
                public:
                    typedef algebra::Fr<ppT> FieldType;

                    std::shared_ptr<precompute_G1_gadget<ppT>> compute_vk_alphaB_g1_precomp;
                    std::shared_ptr<precompute_G1_gadget<ppT>> compute_vk_gamma_beta_g1_precomp;

                    std::shared_ptr<precompute_G2_gadget<ppT>> compute_vk_alphaA_g2_precomp;
                    std::shared_ptr<precompute_G2_gadget<ppT>> compute_vk_alphaC_g2_precomp;
                    std::shared_ptr<precompute_G2_gadget<ppT>> compute_vk_gamma_beta_g2_precomp;
                    std::shared_ptr<precompute_G2_gadget<ppT>> compute_vk_gamma_g2_precomp;
                    std::shared_ptr<precompute_G2_gadget<ppT>> compute_vk_rC_Z_g2_precomp;

                    r1cs_ppzksnark_verification_key_variable<ppT> vk;
                    r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<ppT>
                        &pvk;    // important to have a reference here

                    r1cs_ppzksnark_verifier_process_vk_gadget(
                        protoboard<FieldType> &pb,
                        const r1cs_ppzksnark_verification_key_variable<ppT> &vk,
                        r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<ppT> &pvk);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename ppT>
                class r1cs_ppzksnark_online_verifier_gadget : public gadget<algebra::Fr<ppT>> {
                public:
                    typedef algebra::Fr<ppT> FieldType;

                    r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<ppT> pvk;

                    pb_variable_array<FieldType> input;
                    size_t elt_size;
                    r1cs_ppzksnark_proof_variable<ppT> proof;
                    pb_variable<FieldType> result;
                    const size_t input_len;

                    std::shared_ptr<G1_variable<ppT>> acc;
                    std::shared_ptr<G1_multiscalar_mul_gadget<ppT>> accumulate_input;

                    std::shared_ptr<G1_variable<ppT>> proof_g_A_g_acc;
                    std::shared_ptr<G1_add_gadget<ppT>> compute_proof_g_A_g_acc;
                    std::shared_ptr<G1_variable<ppT>> proof_g_A_g_acc_C;
                    std::shared_ptr<G1_add_gadget<ppT>> compute_proof_g_A_g_acc_C;

                    std::shared_ptr<G1_precomputation<ppT>> proof_g_A_h_precomp;
                    std::shared_ptr<G1_precomputation<ppT>> proof_g_A_g_acc_C_precomp;
                    std::shared_ptr<G1_precomputation<ppT>> proof_g_A_g_acc_precomp;
                    std::shared_ptr<G1_precomputation<ppT>> proof_g_A_g_precomp;
                    std::shared_ptr<G1_precomputation<ppT>> proof_g_B_h_precomp;
                    std::shared_ptr<G1_precomputation<ppT>> proof_g_C_h_precomp;
                    std::shared_ptr<G1_precomputation<ppT>> proof_g_C_g_precomp;
                    std::shared_ptr<G1_precomputation<ppT>> proof_g_K_precomp;
                    std::shared_ptr<G1_precomputation<ppT>> proof_g_H_precomp;

                    std::shared_ptr<G2_precomputation<ppT>> proof_g_B_g_precomp;

                    std::shared_ptr<precompute_G1_gadget<ppT>> compute_proof_g_A_h_precomp;
                    std::shared_ptr<precompute_G1_gadget<ppT>> compute_proof_g_A_g_acc_C_precomp;
                    std::shared_ptr<precompute_G1_gadget<ppT>> compute_proof_g_A_g_acc_precomp;
                    std::shared_ptr<precompute_G1_gadget<ppT>> compute_proof_g_A_g_precomp;
                    std::shared_ptr<precompute_G1_gadget<ppT>> compute_proof_g_B_h_precomp;
                    std::shared_ptr<precompute_G1_gadget<ppT>> compute_proof_g_C_h_precomp;
                    std::shared_ptr<precompute_G1_gadget<ppT>> compute_proof_g_C_g_precomp;
                    std::shared_ptr<precompute_G1_gadget<ppT>> compute_proof_g_K_precomp;
                    std::shared_ptr<precompute_G1_gadget<ppT>> compute_proof_g_H_precomp;

                    std::shared_ptr<precompute_G2_gadget<ppT>> compute_proof_g_B_g_precomp;

                    std::shared_ptr<check_e_equals_e_gadget<ppT>> check_kc_A_valid;
                    std::shared_ptr<check_e_equals_e_gadget<ppT>> check_kc_B_valid;
                    std::shared_ptr<check_e_equals_e_gadget<ppT>> check_kc_C_valid;
                    std::shared_ptr<check_e_equals_ee_gadget<ppT>> check_QAP_valid;
                    std::shared_ptr<check_e_equals_ee_gadget<ppT>> check_CC_valid;

                    pb_variable<FieldType> kc_A_valid;
                    pb_variable<FieldType> kc_B_valid;
                    pb_variable<FieldType> kc_C_valid;
                    pb_variable<FieldType> QAP_valid;
                    pb_variable<FieldType> CC_valid;

                    pb_variable_array<FieldType> all_test_results;
                    std::shared_ptr<conjunction_gadget<FieldType>> all_tests_pass;

                    r1cs_ppzksnark_online_verifier_gadget(
                        protoboard<FieldType> &pb,
                        const r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<ppT> &pvk,
                        const pb_variable_array<FieldType> &input,
                        const size_t elt_size,
                        const r1cs_ppzksnark_proof_variable<ppT> &proof,
                        const pb_variable<FieldType> &result);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename ppT>
                class r1cs_ppzksnark_verifier_gadget : public gadget<algebra::Fr<ppT>> {
                public:
                    typedef algebra::Fr<ppT> FieldType;

                    std::shared_ptr<r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<ppT>> pvk;
                    std::shared_ptr<r1cs_ppzksnark_verifier_process_vk_gadget<ppT>> compute_pvk;
                    std::shared_ptr<r1cs_ppzksnark_online_verifier_gadget<ppT>> online_verifier;

                    r1cs_ppzksnark_verifier_gadget(protoboard<FieldType> &pb,
                                                   const r1cs_ppzksnark_verification_key_variable<ppT> &vk,
                                                   const pb_variable_array<FieldType> &input,
                                                   const size_t elt_size,
                                                   const r1cs_ppzksnark_proof_variable<ppT> &proof,
                                                   const pb_variable<FieldType> &result);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename ppT>
                r1cs_ppzksnark_proof_variable<ppT>::r1cs_ppzksnark_proof_variable(protoboard<FieldType> &pb) :
                    gadget<FieldType>(pb) {
                    const size_t num_G1 = 7;
                    const size_t num_G2 = 1;

                    g_A_g.reset(new G1_variable<ppT>(pb));
                    g_A_h.reset(new G1_variable<ppT>(pb));
                    g_B_g.reset(new G2_variable<ppT>(pb));
                    g_B_h.reset(new G1_variable<ppT>(pb));
                    g_C_g.reset(new G1_variable<ppT>(pb));
                    g_C_h.reset(new G1_variable<ppT>(pb));
                    g_H.reset(new G1_variable<ppT>(pb));
                    g_K.reset(new G1_variable<ppT>(pb));

                    all_G1_vars = {g_A_g, g_A_h, g_B_h, g_C_g, g_C_h, g_H, g_K};
                    all_G2_vars = {g_B_g};

                    all_G1_checkers.resize(all_G1_vars.size());

                    for (size_t i = 0; i < all_G1_vars.size(); ++i) {
                        all_G1_checkers[i].reset(new G1_checker_gadget<ppT>(pb, *all_G1_vars[i]));
                    }
                    G2_checker.reset(new G2_checker_gadget<ppT>(pb, *g_B_g));

                    assert(all_G1_vars.size() == num_G1);
                    assert(all_G2_vars.size() == num_G2);
                }

                template<typename ppT>
                void r1cs_ppzksnark_proof_variable<ppT>::generate_r1cs_constraints() {
                    for (auto &G1_checker : all_G1_checkers) {
                        G1_checker->generate_r1cs_constraints();
                    }

                    G2_checker->generate_r1cs_constraints();
                }

                template<typename ppT>
                void r1cs_ppzksnark_proof_variable<ppT>::generate_r1cs_witness(
                    const r1cs_ppzksnark_proof<other_curve<ppT>> &proof) {
                    std::vector<algebra::G1<other_curve<ppT>>> G1_elems;
                    std::vector<algebra::G2<other_curve<ppT>>> G2_elems;

                    G1_elems = {proof.g_A.g, proof.g_A.h, proof.g_B.h, proof.g_C.g, proof.g_C.h, proof.g_H, proof.g_K};
                    G2_elems = {proof.g_B.g};

                    assert(G1_elems.size() == all_G1_vars.size());
                    assert(G2_elems.size() == all_G2_vars.size());

                    for (size_t i = 0; i < G1_elems.size(); ++i) {
                        all_G1_vars[i]->generate_r1cs_witness(G1_elems[i]);
                    }

                    for (size_t i = 0; i < G2_elems.size(); ++i) {
                        all_G2_vars[i]->generate_r1cs_witness(G2_elems[i]);
                    }

                    for (auto &G1_checker : all_G1_checkers) {
                        G1_checker->generate_r1cs_witness();
                    }

                    G2_checker->generate_r1cs_witness();
                }

                template<typename ppT>
                size_t r1cs_ppzksnark_proof_variable<ppT>::size() {
                    const size_t num_G1 = 7;
                    const size_t num_G2 = 1;
                    return (num_G1 * G1_variable<ppT>::num_field_elems + num_G2 * G2_variable<ppT>::num_field_elems);
                }

                template<typename ppT>
                r1cs_ppzksnark_verification_key_variable<ppT>::r1cs_ppzksnark_verification_key_variable(
                    protoboard<FieldType> &pb,
                    const pb_variable_array<FieldType> &all_bits,
                    const size_t input_size) :
                    gadget<FieldType>(pb),
                    all_bits(all_bits), input_size(input_size) {
                    const size_t num_G1 = 2 + (input_size + 1);
                    const size_t num_G2 = 5;

                    assert(all_bits.size() ==
                           (G1_variable<ppT>::size_in_bits() * num_G1 + G2_variable<ppT>::size_in_bits() * num_G2));

                    this->alphaA_g2.reset(new G2_variable<ppT>(pb));
                    this->alphaB_g1.reset(new G1_variable<ppT>(pb));
                    this->alphaC_g2.reset(new G2_variable<ppT>(pb));
                    this->gamma_g2.reset(new G2_variable<ppT>(pb));
                    this->gamma_beta_g1.reset(new G1_variable<ppT>(pb));
                    this->gamma_beta_g2.reset(new G2_variable<ppT>(pb));
                    this->rC_Z_g2.reset(new G2_variable<ppT>(pb));

                    all_G1_vars = {this->alphaB_g1, this->gamma_beta_g1};
                    all_G2_vars = {this->alphaA_g2, this->alphaC_g2, this->gamma_g2, this->gamma_beta_g2,
                                   this->rC_Z_g2};

                    this->encoded_IC_query.resize(input_size);
                    this->encoded_IC_base.reset(new G1_variable<ppT>(pb));
                    this->all_G1_vars.emplace_back(this->encoded_IC_base);

                    for (size_t i = 0; i < input_size; ++i) {
                        this->encoded_IC_query[i].reset(new G1_variable<ppT>(pb));
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
                    assert(all_vars.size() ==
                           (num_G1 * G1_variable<ppT>::num_variables() + num_G2 * G2_variable<ppT>::num_variables()));

                    packer.reset(new multipacking_gadget<FieldType>(pb, all_bits, all_vars, FieldType::size_in_bits()));
                }

                template<typename ppT>
                void r1cs_ppzksnark_verification_key_variable<ppT>::generate_r1cs_constraints(
                    const bool enforce_bitness) {
                    packer->generate_r1cs_constraints(enforce_bitness);
                }

                template<typename ppT>
                void r1cs_ppzksnark_verification_key_variable<ppT>::generate_r1cs_witness(
                    const r1cs_ppzksnark_verification_key<other_curve<ppT>> &vk) {
                    std::vector<algebra::G1<other_curve<ppT>>> G1_elems;
                    std::vector<algebra::G2<other_curve<ppT>>> G2_elems;

                    G1_elems = {vk.alphaB_g1, vk.gamma_beta_g1};
                    G2_elems = {vk.alphaA_g2, vk.alphaC_g2, vk.gamma_g2, vk.gamma_beta_g2, vk.rC_Z_g2};

                    assert(vk.encoded_IC_query.rest.indices.size() == input_size);
                    G1_elems.emplace_back(vk.encoded_IC_query.first);
                    for (size_t i = 0; i < input_size; ++i) {
                        assert(vk.encoded_IC_query.rest.indices[i] == i);
                        G1_elems.emplace_back(vk.encoded_IC_query.rest.values[i]);
                    }

                    assert(G1_elems.size() == all_G1_vars.size());
                    assert(G2_elems.size() == all_G2_vars.size());

                    for (size_t i = 0; i < G1_elems.size(); ++i) {
                        all_G1_vars[i]->generate_r1cs_witness(G1_elems[i]);
                    }

                    for (size_t i = 0; i < G2_elems.size(); ++i) {
                        all_G2_vars[i]->generate_r1cs_witness(G2_elems[i]);
                    }

                    packer->generate_r1cs_witness_from_packed();
                }

                template<typename ppT>
                void r1cs_ppzksnark_verification_key_variable<ppT>::generate_r1cs_witness(
                    const std::vector<bool> &vk_bits) {
                    all_bits.fill_with_bits(this->pb, vk_bits);
                    packer->generate_r1cs_witness_from_bits();
                }

                template<typename ppT>
                std::vector<bool> r1cs_ppzksnark_verification_key_variable<ppT>::get_bits() const {
                    return all_bits.get_bits(this->pb);
                }

                template<typename ppT>
                size_t r1cs_ppzksnark_verification_key_variable<ppT>::size_in_bits(const size_t input_size) {
                    const size_t num_G1 = 2 + (input_size + 1);
                    const size_t num_G2 = 5;
                    const size_t result =
                        G1_variable<ppT>::size_in_bits() * num_G1 + G2_variable<ppT>::size_in_bits() * num_G2;
                    return result;
                }

                template<typename ppT>
                std::vector<bool> r1cs_ppzksnark_verification_key_variable<ppT>::get_verification_key_bits(
                    const r1cs_ppzksnark_verification_key<other_curve<ppT>> &r1cs_vk) {
                    typedef algebra::Fr<ppT> FieldType;

                    const size_t input_size_in_elts =
                        r1cs_vk.encoded_IC_query.rest.indices
                            .size();    // this might be approximate for bound verification keys, however they are not
                    // supported by r1cs_ppzksnark_verification_key_variable
                    const size_t vk_size_in_bits =
                        r1cs_ppzksnark_verification_key_variable<ppT>::size_in_bits(input_size_in_elts);

                    protoboard<FieldType> pb;
                    pb_variable_array<FieldType> vk_bits;
                    vk_bits.allocate(pb, vk_size_in_bits);
                    r1cs_ppzksnark_verification_key_variable<ppT> vk(pb, vk_bits, input_size_in_elts);
                    vk.generate_r1cs_witness(r1cs_vk);

                    return vk.get_bits();
                }

                template<typename ppT>
                r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<
                    ppT>::r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable() {
                    // will be allocated outside
                }

                template<typename ppT>
                r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<ppT>::
                    r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable(
                        protoboard<FieldType> &pb,
                        const r1cs_ppzksnark_verification_key<other_curve<ppT>> &r1cs_vk) {
                    encoded_IC_base.reset(new G1_variable<ppT>(pb, r1cs_vk.encoded_IC_query.first));
                    encoded_IC_query.resize(r1cs_vk.encoded_IC_query.rest.indices.size());
                    for (size_t i = 0; i < r1cs_vk.encoded_IC_query.rest.indices.size(); ++i) {
                        assert(r1cs_vk.encoded_IC_query.rest.indices[i] == i);
                        encoded_IC_query[i].reset(new G1_variable<ppT>(pb, r1cs_vk.encoded_IC_query.rest.values[i]));
                    }

                    vk_alphaB_g1_precomp.reset(new G1_precomputation<ppT>(pb, r1cs_vk.alphaB_g1));
                    vk_gamma_beta_g1_precomp.reset(new G1_precomputation<ppT>(pb, r1cs_vk.gamma_beta_g1));

                    pp_G2_one_precomp.reset(new G2_precomputation<ppT>(pb, algebra::G2<other_curve<ppT>>::one()));
                    vk_alphaA_g2_precomp.reset(new G2_precomputation<ppT>(pb, r1cs_vk.alphaA_g2));
                    vk_alphaC_g2_precomp.reset(new G2_precomputation<ppT>(pb, r1cs_vk.alphaC_g2));
                    vk_gamma_beta_g2_precomp.reset(new G2_precomputation<ppT>(pb, r1cs_vk.gamma_beta_g2));
                    vk_gamma_g2_precomp.reset(new G2_precomputation<ppT>(pb, r1cs_vk.gamma_g2));
                    vk_rC_Z_g2_precomp.reset(new G2_precomputation<ppT>(pb, r1cs_vk.rC_Z_g2));
                }

                template<typename ppT>
                r1cs_ppzksnark_verifier_process_vk_gadget<ppT>::r1cs_ppzksnark_verifier_process_vk_gadget(
                    protoboard<FieldType> &pb,
                    const r1cs_ppzksnark_verification_key_variable<ppT> &vk,
                    r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<ppT> &pvk) :
                    gadget<FieldType>(pb),
                    vk(vk), pvk(pvk) {
                    pvk.encoded_IC_base = vk.encoded_IC_base;
                    pvk.encoded_IC_query = vk.encoded_IC_query;

                    pvk.vk_alphaB_g1_precomp.reset(new G1_precomputation<ppT>());
                    pvk.vk_gamma_beta_g1_precomp.reset(new G1_precomputation<ppT>());

                    pvk.pp_G2_one_precomp.reset(new G2_precomputation<ppT>());
                    pvk.vk_alphaA_g2_precomp.reset(new G2_precomputation<ppT>());
                    pvk.vk_alphaC_g2_precomp.reset(new G2_precomputation<ppT>());
                    pvk.vk_gamma_beta_g2_precomp.reset(new G2_precomputation<ppT>());
                    pvk.vk_gamma_g2_precomp.reset(new G2_precomputation<ppT>());
                    pvk.vk_rC_Z_g2_precomp.reset(new G2_precomputation<ppT>());

                    compute_vk_alphaB_g1_precomp.reset(
                        new precompute_G1_gadget<ppT>(pb, *vk.alphaB_g1, *pvk.vk_alphaB_g1_precomp));
                    compute_vk_gamma_beta_g1_precomp.reset(
                        new precompute_G1_gadget<ppT>(pb, *vk.gamma_beta_g1, *pvk.vk_gamma_beta_g1_precomp));

                    pvk.pp_G2_one_precomp.reset(new G2_precomputation<ppT>(pb, algebra::G2<other_curve<ppT>>::one()));
                    compute_vk_alphaA_g2_precomp.reset(
                        new precompute_G2_gadget<ppT>(pb, *vk.alphaA_g2, *pvk.vk_alphaA_g2_precomp));
                    compute_vk_alphaC_g2_precomp.reset(
                        new precompute_G2_gadget<ppT>(pb, *vk.alphaC_g2, *pvk.vk_alphaC_g2_precomp));
                    compute_vk_gamma_beta_g2_precomp.reset(
                        new precompute_G2_gadget<ppT>(pb, *vk.gamma_beta_g2, *pvk.vk_gamma_beta_g2_precomp));
                    compute_vk_gamma_g2_precomp.reset(
                        new precompute_G2_gadget<ppT>(pb, *vk.gamma_g2, *pvk.vk_gamma_g2_precomp));
                    compute_vk_rC_Z_g2_precomp.reset(
                        new precompute_G2_gadget<ppT>(pb, *vk.rC_Z_g2, *pvk.vk_rC_Z_g2_precomp));
                }

                template<typename ppT>
                void r1cs_ppzksnark_verifier_process_vk_gadget<ppT>::generate_r1cs_constraints() {
                    compute_vk_alphaB_g1_precomp->generate_r1cs_constraints();
                    compute_vk_gamma_beta_g1_precomp->generate_r1cs_constraints();

                    compute_vk_alphaA_g2_precomp->generate_r1cs_constraints();
                    compute_vk_alphaC_g2_precomp->generate_r1cs_constraints();
                    compute_vk_gamma_beta_g2_precomp->generate_r1cs_constraints();
                    compute_vk_gamma_g2_precomp->generate_r1cs_constraints();
                    compute_vk_rC_Z_g2_precomp->generate_r1cs_constraints();
                }

                template<typename ppT>
                void r1cs_ppzksnark_verifier_process_vk_gadget<ppT>::generate_r1cs_witness() {
                    compute_vk_alphaB_g1_precomp->generate_r1cs_witness();
                    compute_vk_gamma_beta_g1_precomp->generate_r1cs_witness();

                    compute_vk_alphaA_g2_precomp->generate_r1cs_witness();
                    compute_vk_alphaC_g2_precomp->generate_r1cs_witness();
                    compute_vk_gamma_beta_g2_precomp->generate_r1cs_witness();
                    compute_vk_gamma_g2_precomp->generate_r1cs_witness();
                    compute_vk_rC_Z_g2_precomp->generate_r1cs_witness();
                }

                template<typename ppT>
                r1cs_ppzksnark_online_verifier_gadget<ppT>::r1cs_ppzksnark_online_verifier_gadget(
                    protoboard<FieldType> &pb,
                    const r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<ppT> &pvk,
                    const pb_variable_array<FieldType> &input,
                    const size_t elt_size,
                    const r1cs_ppzksnark_proof_variable<ppT> &proof,
                    const pb_variable<FieldType> &result) :
                    gadget<FieldType>(pb),
                    pvk(pvk), input(input), elt_size(elt_size), proof(proof), result(result), input_len(input.size()) {
                    // accumulate input and store base in acc
                    acc.reset(new G1_variable<ppT>(pb));
                    std::vector<G1_variable<ppT>> IC_terms;
                    for (size_t i = 0; i < pvk.encoded_IC_query.size(); ++i) {
                        IC_terms.emplace_back(*(pvk.encoded_IC_query[i]));
                    }
                    accumulate_input.reset(new G1_multiscalar_mul_gadget<ppT>(
                        pb, *(pvk.encoded_IC_base), input, elt_size, IC_terms, *acc));

                    // allocate results for precomputation
                    proof_g_A_h_precomp.reset(new G1_precomputation<ppT>());
                    proof_g_A_g_acc_C_precomp.reset(new G1_precomputation<ppT>());
                    proof_g_A_g_acc_precomp.reset(new G1_precomputation<ppT>());
                    proof_g_A_g_precomp.reset(new G1_precomputation<ppT>());
                    proof_g_B_h_precomp.reset(new G1_precomputation<ppT>());
                    proof_g_C_h_precomp.reset(new G1_precomputation<ppT>());
                    proof_g_C_g_precomp.reset(new G1_precomputation<ppT>());
                    proof_g_K_precomp.reset(new G1_precomputation<ppT>());
                    proof_g_H_precomp.reset(new G1_precomputation<ppT>());

                    proof_g_B_g_precomp.reset(new G2_precomputation<ppT>());

                    // do the necessary precomputations
                    // compute things not available in plain from proof/vk
                    proof_g_A_g_acc.reset(new G1_variable<ppT>(pb));
                    compute_proof_g_A_g_acc.reset(new G1_add_gadget<ppT>(pb, *(proof.g_A_g), *acc, *proof_g_A_g_acc));
                    proof_g_A_g_acc_C.reset(new G1_variable<ppT>(pb));
                    compute_proof_g_A_g_acc_C.reset(
                        new G1_add_gadget<ppT>(pb, *proof_g_A_g_acc, *(proof.g_C_g), *proof_g_A_g_acc_C));

                    compute_proof_g_A_g_acc_precomp.reset(
                        new precompute_G1_gadget<ppT>(pb, *proof_g_A_g_acc, *proof_g_A_g_acc_precomp));
                    compute_proof_g_A_g_acc_C_precomp.reset(
                        new precompute_G1_gadget<ppT>(pb, *proof_g_A_g_acc_C, *proof_g_A_g_acc_C_precomp));

                    // do other precomputations
                    compute_proof_g_A_h_precomp.reset(
                        new precompute_G1_gadget<ppT>(pb, *(proof.g_A_h), *proof_g_A_h_precomp));
                    compute_proof_g_A_g_precomp.reset(
                        new precompute_G1_gadget<ppT>(pb, *(proof.g_A_g), *proof_g_A_g_precomp));
                    compute_proof_g_B_h_precomp.reset(
                        new precompute_G1_gadget<ppT>(pb, *(proof.g_B_h), *proof_g_B_h_precomp));
                    compute_proof_g_C_h_precomp.reset(
                        new precompute_G1_gadget<ppT>(pb, *(proof.g_C_h), *proof_g_C_h_precomp));
                    compute_proof_g_C_g_precomp.reset(
                        new precompute_G1_gadget<ppT>(pb, *(proof.g_C_g), *proof_g_C_g_precomp));
                    compute_proof_g_H_precomp.reset(
                        new precompute_G1_gadget<ppT>(pb, *(proof.g_H), *proof_g_H_precomp));
                    compute_proof_g_K_precomp.reset(
                        new precompute_G1_gadget<ppT>(pb, *(proof.g_K), *proof_g_K_precomp));
                    compute_proof_g_B_g_precomp.reset(
                        new precompute_G2_gadget<ppT>(pb, *(proof.g_B_g), *proof_g_B_g_precomp));

                    // check validity of A knowledge commitment
                    kc_A_valid.allocate(pb);
                    check_kc_A_valid.reset(new check_e_equals_e_gadget<ppT>(pb,
                                                                            *proof_g_A_g_precomp,
                                                                            *(pvk.vk_alphaA_g2_precomp),
                                                                            *proof_g_A_h_precomp,
                                                                            *(pvk.pp_G2_one_precomp),
                                                                            kc_A_valid));

                    // check validity of B knowledge commitment
                    kc_B_valid.allocate(pb);
                    check_kc_B_valid.reset(new check_e_equals_e_gadget<ppT>(pb,
                                                                            *(pvk.vk_alphaB_g1_precomp),
                                                                            *proof_g_B_g_precomp,
                                                                            *proof_g_B_h_precomp,
                                                                            *(pvk.pp_G2_one_precomp),
                                                                            kc_B_valid));

                    // check validity of C knowledge commitment
                    kc_C_valid.allocate(pb);
                    check_kc_C_valid.reset(new check_e_equals_e_gadget<ppT>(pb,
                                                                            *proof_g_C_g_precomp,
                                                                            *(pvk.vk_alphaC_g2_precomp),
                                                                            *proof_g_C_h_precomp,
                                                                            *(pvk.pp_G2_one_precomp),
                                                                            kc_C_valid));

                    // check QAP divisibility
                    QAP_valid.allocate(pb);
                    check_QAP_valid.reset(new check_e_equals_ee_gadget<ppT>(pb,
                                                                            *proof_g_A_g_acc_precomp,
                                                                            *proof_g_B_g_precomp,
                                                                            *proof_g_H_precomp,
                                                                            *(pvk.vk_rC_Z_g2_precomp),
                                                                            *proof_g_C_g_precomp,
                                                                            *(pvk.pp_G2_one_precomp),
                                                                            QAP_valid));

                    // check coefficients
                    CC_valid.allocate(pb);
                    check_CC_valid.reset(new check_e_equals_ee_gadget<ppT>(pb,
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

                    all_tests_pass.reset(new conjunction_gadget<FieldType>(pb, all_test_results, result));
                }

                template<typename ppT>
                void r1cs_ppzksnark_online_verifier_gadget<ppT>::generate_r1cs_constraints() {
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

                template<typename ppT>
                void r1cs_ppzksnark_online_verifier_gadget<ppT>::generate_r1cs_witness() {
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

                template<typename ppT>
                r1cs_ppzksnark_verifier_gadget<ppT>::r1cs_ppzksnark_verifier_gadget(
                    protoboard<FieldType> &pb,
                    const r1cs_ppzksnark_verification_key_variable<ppT> &vk,
                    const pb_variable_array<FieldType> &input,
                    const size_t elt_size,
                    const r1cs_ppzksnark_proof_variable<ppT> &proof,
                    const pb_variable<FieldType> &result) :
                    gadget<FieldType>(pb) {
                    pvk.reset(new r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<ppT>());
                    compute_pvk.reset(new r1cs_ppzksnark_verifier_process_vk_gadget<ppT>(pb, vk, *pvk));
                    online_verifier.reset(
                        new r1cs_ppzksnark_online_verifier_gadget<ppT>(pb, *pvk, input, elt_size, proof, result));
                }

                template<typename ppT>
                void r1cs_ppzksnark_verifier_gadget<ppT>::generate_r1cs_constraints() {
                    compute_pvk->generate_r1cs_constraints();

                    online_verifier->generate_r1cs_constraints();
                }

                template<typename ppT>
                void r1cs_ppzksnark_verifier_gadget<ppT>::generate_r1cs_witness() {
                    compute_pvk->generate_r1cs_witness();
                    online_verifier->generate_r1cs_witness();
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // R1CS_PPZKSNARK_VERIFIER_GADGET_HPP_
