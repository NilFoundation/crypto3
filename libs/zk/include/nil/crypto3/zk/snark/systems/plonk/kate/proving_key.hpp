//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_PLONK_BATCHED_KATE_PROVING_KEY_HPP
#define CRYPTO3_PLONK_BATCHED_KATE_PROVING_KEY_HPP

#include <nil/crypto3/zk/snark/commitments/batched_kate_commitment.hpp>
#include <nil/crypto3/zk/snark/arithmetization/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename TCurve, typename TCommitment>
                struct plonk_proving_key_data;

                template<typename TCurve>
                struct plonk_proving_key_data<TCurve, batched_kate_commitment_scheme<...>> {
                    std::uint32_t n;
                    std::uint32_t num_public_inputs;
                    bool contains_recursive_proof;
                    std::vector<std::uint32_t> recursive_proof_public_input_indices;
                    std::map<std::string, math::polynomial> constraint_selectors;
                    std::map<std::string, math::polynomial> constraint_selector_ffts;
                    std::map<std::string, math::polynomial> permutation_selectors;
                    std::map<std::string, math::polynomial> permutation_selectors_lagrange_base;
                    std::map<std::string, math::polynomial> permutation_selector_ffts;
                };

                inline bool operator==(plonk_proving_key_data const &lhs, plonk_proving_key_data const &rhs) {
                    return lhs.n == rhs.n && lhs.num_public_inputs == rhs.num_public_inputs &&
                           lhs.constraint_selectors == rhs.constraint_selectors &&
                           lhs.constraint_selector_ffts == rhs.constraint_selector_ffts &&
                           lhs.permutation_selectors == rhs.permutation_selectors &&
                           lhs.permutation_selectors_lagrange_base == rhs.permutation_selectors_lagrange_base &&
                           lhs.permutation_selector_ffts == rhs.permutation_selector_ffts &&
                           lhs.contains_recursive_proof == rhs.contains_recursive_proof &&
                           lhs.recursive_proof_public_input_indices == rhs.recursive_proof_public_input_indices;
                }

                template<typename TCurve, typename TCommitment>
                class plonk_proving_key;

                template<typename TCurve>
                class plonk_proving_key<TCurve, batched_kate_commitment_scheme<...>> {
                    constexpr static const std::size_t scalar_bytes = TCurve::scalar_field_type::value_bits / BYTE_BITS;

                    std::size_t n;
                    std::size_t num_public_inputs;

                    std::map<std::string, math::polynomial> constraint_selectors;
                    std::map<std::string, math::polynomial> constraint_selectors_lagrange_base;
                    std::map<std::string, math::polynomial> constraint_selector_ffts;

                    std::map<std::string, math::polynomial> permutation_selectors;
                    std::map<std::string, math::polynomial> permutation_selectors_lagrange_base;
                    std::map<std::string, math::polynomial> permutation_selector_ffts;

                    std::map<std::string, math::polynomial> wire_ffts;

                    math::evaluation_domain small_domain;
                    math::evaluation_domain mid_domain;
                    math::evaluation_domain large_domain;

                    std::shared_ptr<ProverReferenceString> reference_string;

                    math::polynomial lagrange_1;
                    math::polynomial opening_poly;
                    math::polynomial shifted_opening_poly;
                    math::polynomial linear_poly;

                    math::polynomial quotient_mid;
                    math::polynomial quotient_large;

                    algebra::scalar_multiplication::pippenger_runtime_state pippenger_runtime_state;

                    std::vector<PolynomialDescriptor> polynomial_manifest;

                    bool contains_recursive_proof = false;
                    std::vector<std::uint32_t> recursive_proof_public_input_indices;
                    static constexpr std::size_t min_thread_block = 4UL;

                public:
                    enum LookupType {
                        NONE,
                        ABSOLUTE_LOOKUP,
                        RELATIVE_LOOKUP,
                    };

                    plonk_proving_key(const std::size_t num_gates,
                                      const std::size_t num_inputs,
                                      std::shared_ptr<ProverReferenceString> const &crs) :
                        n(num_gates),
                        num_public_inputs(num_inputs), small_domain(n, n),
                        mid_domain(2 * n, n > min_thread_block ? n : 2 * n),
                        large_domain(4 * n, n > min_thread_block ? n : 4 * n), reference_string(crs),
                        pippenger_runtime_state(n + 1) {
                        init();
                    }

                    plonk_proving_key(plonk_proving_key_data<TCurve, TConstraintSystem> &&data,
                                      std::shared_ptr<ProverReferenceString> const &crs) :
                        n(data.n),
                        num_public_inputs(data.num_public_inputs),
                        constraint_selectors(std::move(data.constraint_selectors)),
                        constraint_selector_ffts(std::move(data.constraint_selector_ffts)),
                        permutation_selectors(std::move(data.permutation_selectors)),
                        permutation_selectors_lagrange_base(std::move(data.permutation_selectors_lagrange_base)),
                        permutation_selector_ffts(std::move(data.permutation_selector_ffts)), small_domain(n, n),
                        mid_domain(2 * n, n > min_thread_block ? n : 2 * n),
                        large_domain(4 * n, n > min_thread_block ? n : 4 * n), reference_string(crs),
                        pippenger_runtime_state(n + 1), contains_recursive_proof(data.contains_recursive_proof),
                        recursive_proof_public_input_indices(std::move(data.recursive_proof_public_input_indices)) {
                        init();
                        // TODO: Currently only supporting TurboComposer in serialization!
                        std::copy(turbo_polynomial_manifest,
                                  turbo_polynomial_manifest + 20,
                                  std::back_inserter(polynomial_manifest));
                    }

                    void init() {
                        if (n != 0) {
                            small_domain.compute_lookup_table();
                            mid_domain.compute_lookup_table();
                            large_domain.compute_lookup_table();
                        }

                        reset();

                        lagrange_1 = math::polynomial(4 * n, 4 * n + 8);
                        math::polynomial_arithmetic::compute_lagrange_polynomial_fft(
                            lagrange_1.get_coefficients(), small_domain, large_domain);
                        lagrange_1.add_lagrange_base_coefficient(lagrange_1[0]);
                        lagrange_1.add_lagrange_base_coefficient(lagrange_1[1]);
                        lagrange_1.add_lagrange_base_coefficient(lagrange_1[2]);
                        lagrange_1.add_lagrange_base_coefficient(lagrange_1[3]);
                        lagrange_1.add_lagrange_base_coefficient(lagrange_1[4]);
                        lagrange_1.add_lagrange_base_coefficient(lagrange_1[5]);
                        lagrange_1.add_lagrange_base_coefficient(lagrange_1[6]);
                        lagrange_1.add_lagrange_base_coefficient(lagrange_1[7]);

                        // The opening polynomial W_{\script{z}}(X) in round 5 of prover's algorithm has degree n.
                        // However, as explained in
                        // (./src/aztec/plonk/proof_system/prover/prover.cpp/ProverBase::compute_quotient_pre_commitment),
                        // for standard plonk (program_width = 3) and number of roots cut out of the vanishing
                        // polynomial is 4, the degree of the quotient polynomial t(X) is 3n. Thus, the number of
                        // coefficients in t_{high} is (n + 1). But our prover algorithm assumes that each of t_{low},
                        // t_{mid}, t_{high} is of degree (n - 1) (i.e. n coefficients in each). Note that:
                        // deg(W_{\script{z}}) = max{ deg(t_{low}), deg(t_{mid}), deg(t_{high}), deg(a), deg(b), ... }
                        // => deg(W_{\script{z}}) = n + 1 when program_width is 3!
                        // Therefore, when program_width is 3, we need to allow the degree of the opening polynomial to
                        // be (n + 1) and NOT n.
                        //
                        opening_poly = math::polynomial(n, n);
                        shifted_opening_poly = math::polynomial(n, n);
                        linear_poly = math::polynomial(n, n);

                        quotient_mid = math::polynomial(2 * n, 2 * n);
                        quotient_large = math::polynomial(4 * n, 4 * n);

                        memset((void *)&opening_poly[0], 0x00, scalar_bytes * n);
                        memset((void *)&shifted_opening_poly[0], 0x00, scalar_bytes * n);
                        memset((void *)&linear_poly[0], 0x00, scalar_bytes * n);
                        memset((void *)&quotient_mid[0], 0x00, scalar_bytes * 2 * n);
                        memset((void *)&quotient_large[0], 0x00, scalar_bytes * 4 * n);
                    }

                    void reset() {
                        wire_ffts.clear();

                        opening_poly = math::polynomial(n, n);

                        math::polynomial w_1_fft = math::polynomial(4 * n + 4, 4 * n + 4);
                        math::polynomial w_2_fft = math::polynomial(4 * n + 4, 4 * n + 4);
                        math::polynomial w_3_fft = math::polynomial(4 * n + 4, 4 * n + 4);
                        math::polynomial w_4_fft = math::polynomial(4 * n + 4, 4 * n + 4);
                        math::polynomial z_fft = math::polynomial(4 * n + 4, 4 * n + 4);

                        memset((void *)&w_1_fft[0], 0x00, sizeof(scalar_bytes) * (4 * n + 4));
                        memset((void *)&w_2_fft[0], 0x00, sizeof(scalar_bytes) * (4 * n + 4));
                        memset((void *)&w_3_fft[0], 0x00, sizeof(scalar_bytes) * (4 * n + 4));
                        memset((void *)&w_4_fft[0], 0x00, sizeof(scalar_bytes) * (4 * n + 4));
                        memset((void *)&z_fft[0], 0x00, sizeof(scalar_bytes) * (4 * n + 4));

                        wire_ffts.insert({"w_1_fft", std::move(w_1_fft)});
                        wire_ffts.insert({"w_2_fft", std::move(w_2_fft)});
                        wire_ffts.insert({"w_3_fft", std::move(w_3_fft)});
                        wire_ffts.insert({"w_4_fft", std::move(w_4_fft)});
                        wire_ffts.insert({"z_fft", std::move(z_fft)});
                    }

                    plonk_proving_key &operator=(const plonk_proving_key &other) {
                        n = other.n;
                        num_public_inputs = other.num_public_inputs;
                        constraint_selectors = std::move(other.constraint_selectors);
                        constraint_selectors_lagrange_base = std::move(other.constraint_selectors_lagrange_base);
                        constraint_selector_ffts = std::move(other.constraint_selector_ffts);
                        permutation_selectors = std::move(other.permutation_selectors);
                        permutation_selectors_lagrange_base = std::move(other.permutation_selectors_lagrange_base);
                        permutation_selector_ffts = std::move(other.permutation_selector_ffts);
                        wire_ffts = std::move(other.wire_ffts);
                        small_domain = std::move(other.small_domain);
                        mid_domain = std::move(other.mid_domain);
                        large_domain = std::move(other.large_domain);
                        reference_string = std::move(other.reference_string);
                        lagrange_1 = std::move(other.lagrange_1);
                        opening_poly = std::move(other.opening_poly);
                        shifted_opening_poly = std::move(other.shifted_opening_poly);
                        linear_poly = std::move(other.linear_poly);
                        pippenger_runtime_state = std::move(other.pippenger_runtime_state);
                        polynomial_manifest = std::move(other.polynomial_manifest);
                        contains_recursive_proof = other.contains_recursive_proof;
                        recursive_proof_public_input_indices = std::move(other.recursive_proof_public_input_indices);

                        return *this;
                    }

                    plonk_proving_key(const plonk_proving_key &other) :
                        n(other.n), num_public_inputs(other.num_public_inputs),
                        constraint_selectors(other.constraint_selectors),
                        constraint_selectors_lagrange_base(other.constraint_selectors_lagrange_base),
                        constraint_selector_ffts(other.constraint_selector_ffts),
                        permutation_selectors(other.permutation_selectors),
                        permutation_selectors_lagrange_base(other.permutation_selectors_lagrange_base),
                        permutation_selector_ffts(other.permutation_selector_ffts), wire_ffts(other.wire_ffts),
                        small_domain(other.small_domain), mid_domain(other.mid_domain),
                        large_domain(other.large_domain), reference_string(other.reference_string),
                        lagrange_1(other.lagrange_1), opening_poly(other.opening_poly),
                        shifted_opening_poly(other.shifted_opening_poly), linear_poly(other.linear_poly),
                        quotient_mid(other.quotient_mid), quotient_large(other.quotient_large),
                        pippenger_runtime_state(n + 1), polynomial_manifest(other.polynomial_manifest),
                        contains_recursive_proof(other.contains_recursive_proof),
                        recursive_proof_public_input_indices(other.recursive_proof_public_input_indices) {
                    }

                    plonk_proving_key(plonk_proving_key &&other) :
                        n(other.n), num_public_inputs(other.num_public_inputs),
                        constraint_selectors(other.constraint_selectors),
                        constraint_selectors_lagrange_base(other.constraint_selectors_lagrange_base),
                        constraint_selector_ffts(other.constraint_selector_ffts),
                        permutation_selectors(other.permutation_selectors),
                        permutation_selectors_lagrange_base(other.permutation_selectors_lagrange_base),
                        permutation_selector_ffts(other.permutation_selector_ffts), wire_ffts(other.wire_ffts),
                        small_domain(std::move(other.small_domain)), mid_domain(std::move(other.mid_domain)),
                        large_domain(std::move(other.large_domain)),
                        reference_string(std::move(other.reference_string)), lagrange_1(std::move(other.lagrange_1)),
                        opening_poly(std::move(other.opening_poly)),
                        shifted_opening_poly(std::move(other.shifted_opening_poly)),
                        linear_poly(std::move(other.linear_poly)),
                        pippenger_runtime_state(std::move(other.pippenger_runtime_state)),
                        polynomial_manifest(std::move(other.polynomial_manifest)),
                        contains_recursive_proof(other.contains_recursive_proof),
                        recursive_proof_public_input_indices(std::move(other.recursive_proof_public_input_indices)) {
                    }

                    std::size_t size_in_bits() const {
                        ? ? ? ;
                    }

                    bool operator==(const plonk_proving_key &other) const {
                        return this->n == other.n && this->num_public_inputs == other.num_public_inputs &&
                               this->constraint_selectors == other.constraint_selectors &&
                               this->constraint_selector_ffts == other.constraint_selector_ffts &&
                               this->permutation_selectors == other.permutation_selectors &&
                               this->permutation_selectors_lagrange_base == other.permutation_selectors_lagrange_base &&
                               this->permutation_selector_ffts == other.permutation_selector_ffts &&
                               this->contains_recursive_proof == other.contains_recursive_proof &&
                               this->recursive_proof_public_input_indices == other.recursive_proof_public_input_indices;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PLONK_BATCHED_KATE_PROVING_KEY_HPP
