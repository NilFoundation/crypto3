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

#ifndef CRYPTO3_PLONK_BATCHED_KATE_VERIFICATION_KEY_HPP
#define CRYPTO3_PLONK_BATCHED_KATE_VERIFICATION_KEY_HPP

#include <nil/crypto3/zk/snark/commitments/batched_kate_commitment.hpp>
#include <nil/crypto3/zk/snark/arithmetization/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename TCurve, typename TCommitment>
                struct plonk_verification_key_data;

                template<typename TCurve>
                struct plonk_verification_key_data<TCurve, batched_kate_commitment_scheme<...>> {
                    std::uint32_t n;
                    std::uint32_t num_public_inputs;
                    std::map<std::string, typename TCurve::template g1_type<>::value_type> constraint_selectors;
                    std::map<std::string, typename TCurve::template g1_type<>::value_type> permutation_selectors;
                    bool contains_recursive_proof = false;
                    std::vector<std::uint32_t> recursive_proof_public_input_indices;
                };

                inline bool operator==(plonk_verification_key_data const &lhs, plonk_verification_key_data const &rhs) {
                    return lhs.n == rhs.n && lhs.num_public_inputs == rhs.num_public_inputs &&
                           lhs.constraint_selectors == rhs.constraint_selectors &&
                           lhs.permutation_selectors == rhs.permutation_selectors;
                }

                template<typename TCurve, typename TCommitment>
                class plonk_verification_key;

                template<typename TCurve>
                class plonk_verification_key<TCurve, batched_kate_commitment_scheme<...>> {
                    using commitment_scheme_type = batched_kate_commitment_scheme<...>;

                    constexpr static const std::size_t scalar_bytes = TCurve::scalar_field_type::value_bits / BYTE_BITS;

                    std::size_t n;
                    std::size_t num_public_inputs;

                    math::evaluation_domain domain;

                    std::shared_ptr<VerifierReferenceString> reference_string;

                    std::map<std::string, typename TCurve::template g1_type<>::value_type> constraint_selectors;

                    std::map<std::string, typename TCurve::template g1_type<>::value_type> permutation_selectors;

                    std::vector<PolynomialDescriptor> polynomial_manifest;

                    // this is a member variable because stdlib::field has no `pow` method, we
                    // have to compute this differently for the normal and recursive settings respectively
                    typename TCurve::scalar_field_type::value_type z_pow_n;

                    bool contains_recursive_proof = false;
                    std::vector<std::uint32_t> recursive_proof_public_input_indices;
                    std::size_t program_width = 3;

                public:
                    plonk_verification_key(const std::size_t num_gates,
                                           const std::size_t num_inputs,
                                           std::shared_ptr<VerifierReferenceString> const &crs) :
                        n(num_gates),
                        num_public_inputs(num_inputs), domain(n), reference_string(crs) {
                    }

                    plonk_verification_key(plonk_verification_key_data<TCurve, commitment_scheme_type> &&data,
                                           std::shared_ptr<VerifierReferenceString> const &crs) :
                        n(data.n),
                        num_public_inputs(data.num_public_inputs), domain(n), reference_string(crs),
                        constraint_selectors(std::move(data.constraint_selectors)),
                        permutation_selectors(std::move(data.permutation_selectors)),
                        contains_recursive_proof(data.contains_recursive_proof),
                        recursive_proof_public_input_indices(std::move(data.recursive_proof_public_input_indices)) {
                        // TODO: Currently only supporting TurboComposer in serialization!
                        std::copy(turbo_polynomial_manifest,
                                  turbo_polynomial_manifest + 20,
                                  std::back_inserter(polynomial_manifest));
                    }

                    plonk_verification_key &operator=(plonk_verification_key &&other) {
                        n = other.n;
                        num_public_inputs = other.num_public_inputs;
                        reference_string = std::move(other.reference_string);
                        constraint_selectors = std::move(other.constraint_selectors);
                        permutation_selectors = std::move(other.permutation_selectors);
                        polynomial_manifest = std::move(other.polynomial_manifest);
                        domain = std::move(other.domain);
                        contains_recursive_proof = (other.contains_recursive_proof);
                        recursive_proof_public_input_indices = std::move(other.recursive_proof_public_input_indices);
                        return *this;
                    }

                    plonk_verification_key(const plonk_verification_key &other) :
                        n(other.n), num_public_inputs(other.num_public_inputs), domain(other.domain),
                        reference_string(other.reference_string), constraint_selectors(other.constraint_selectors),
                        permutation_selectors(other.permutation_selectors),
                        polynomial_manifest(other.polynomial_manifest),
                        contains_recursive_proof(other.contains_recursive_proof),
                        recursive_proof_public_input_indices(other.recursive_proof_public_input_indices) {
                    }

                    plonk_verification_key(plonk_verification_key &&other) :
                        n(other.n), num_public_inputs(other.num_public_inputs), domain(other.domain),
                        reference_string(other.reference_string), constraint_selectors(other.constraint_selectors),
                        permutation_selectors(other.permutation_selectors),
                        polynomial_manifest(other.polynomial_manifest),
                        contains_recursive_proof(other.contains_recursive_proof),
                        recursive_proof_public_input_indices(other.recursive_proof_public_input_indices) {
                    }

                    std::size_t size_in_bits() const {
                        ? ? ? ;
                    }

                    bool operator==(const plonk_verification_key &other) const {
                        return this->n == rhs.n && this->num_public_inputs == rhs.num_public_inputs &&
                               this->constraint_selectors == rhs.constraint_selectors &&
                               this->permutation_selectors == rhs.permutation_selectors;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PLONK_BATCHED_KATE_VERIFICATION_KEY_HPP
