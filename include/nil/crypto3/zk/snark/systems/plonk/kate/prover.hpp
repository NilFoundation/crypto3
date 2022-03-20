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

#ifndef CRYPTO3_ZK_PLONK_BATCHED_KATE_PROVER_HPP
#define CRYPTO3_ZK_PLONK_BATCHED_KATE_PROVER_HPP

#include <nil/crypto3/zk/snark/commitments/batched_kate_commitment.hpp>
#include <nil/crypto3/zk/snark/arithmetization/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename TCurve, typename TCommitment>
                class plonk_prover;

                template<typename TCurve>
                class plonk_prover<TCurve, batched_kate_commitment_scheme<...>> {
                    using commitment_scheme_type = batched_kate_commitment_scheme<...>;
                    using constraint_system_type = plonk_constraint_system<typename TCurve::scalar_field_type>;

                    size_t n;

                    std::vector<uint32_t> sigma_1_mapping;
                    std::vector<uint32_t> sigma_2_mapping;
                    std::vector<uint32_t> sigma_3_mapping;

                    std::vector<std::unique_ptr<ProverRandomWidget>> random_widgets;
                    std::vector<std::unique_ptr<widget::TransitionWidgetBase<typename TCurve::scalar_field_type>>>
                        transition_widgets;
                    transcript::StandardTranscript transcript;

                    std::shared_ptr<plonk_proving_key<TCurve, commitment_scheme_type>> key;
                    std::shared_ptr<program_witness> witness;
                    std::unique_ptr<commitment_scheme_type> commitment;

                    work_queue queue;
                    bool uses_quotient_mid;

                    plonk_proof proof;

                public:
                    plonk_prover(std::shared_ptr<plonk_proving_key<TCurve, commitment_scheme_type>> input_key,
                                 std::shared_ptr<program_witness>
                                     input_witness,
                                 const transcript::Manifest &input_manifest) :
                        n(input_key == nullptr ? 0 : input_key->n),
                        transcript(input_manifest, hash_type, num_challenge_bytes), key(input_key),
                        witness(input_witness), queue(key.get(), witness.get(), &transcript) {
                        if (input_witness && witness->wires.count("z") == 0) {
                            witness->wires.insert({"z", math::polynomial(n, n)});
                        }
                    }

                    plonk_prover &operator=(plonk_prover &&other) {
                        n = other.n;

                        random_widgets.resize(0);
                        transition_widgets.resize(0);
                        for (size_t i = 0; i < other.random_widgets.size(); ++i) {
                            random_widgets.emplace_back(std::move(other.random_widgets[i]));
                        }
                        for (size_t i = 0; i < other.transition_widgets.size(); ++i) {
                            transition_widgets.emplace_back(std::move(other.transition_widgets[i]));
                        }
                        transcript = other.transcript;
                        key = std::move(other.key);
                        witness = std::move(other.witness);
                        commitment = std::move(other.commitment);

                        queue = work_queue(key.get(), witness.get(), &transcript);
                        return *this;
                    }

                    plonk_prover(plonk_prover &&other) :
                        n(other.n), transcript(other.transcript), key(std::move(other.key)),
                        witness(std::move(other.witness)), commitment(std::move(other.commitment)),
                        queue(key.get(), witness.get(), &transcript) {
                        for (size_t i = 0; i < other.random_widgets.size(); ++i) {
                            random_widgets.emplace_back(std::move(other.random_widgets[i]));
                        }
                        for (size_t i = 0; i < other.transition_widgets.size(); ++i) {
                            transition_widgets.emplace_back(std::move(other.transition_widgets[i]));
                        }
                    }

                    void compute_wire_pre_commitments() {
                        for (size_t i = 0; i < settings::program_width; ++i) {
                            std::string wire_tag = "w_" + std::to_string(i + 1);
                            std::string commit_tag = "W_" + std::to_string(i + 1);
                            typename TCurve::scalar_field_type::value_type *coefficients =
                                witness->wires.at(wire_tag).get_coefficients();
                            commitment->commit(coefficients, commit_tag,
                                               typename TCurve::scalar_field_type::value_type::zero(), queue);
                        }

                        // add public inputs
                        const math::polynomial &public_wires_source = key->wire_ffts.at("w_2_fft");
                        std::vector<typename TCurve::scalar_field_type::value_type> public_wires;
                        for (size_t i = 0; i < key->num_public_inputs; ++i) {
                            public_wires.push_back(public_wires_source[i]);
                        }
                        transcript.add_element("public_inputs", ::to_buffer(public_wires));
                    }

                    void compute_quotient_pre_commitment() {
                        // In this method, we compute the commitments to polynomials t_{low}(X), t_{mid}(X) and
                        // t_{high}(X). Recall, the quotient polynomial t(X) = t_{low}(X) + t_{mid}(X).X^n +
                        // t_{high}(X).X^{2n}
                        //
                        // The reason we split t(X) into three degree-n polynomials is because:
                        //  (i) We want the opening proof polynomials bounded by degree n as the opening algorithm of
                        //  the
                        //      polynomial commitment scheme results in O(n) prover computation.
                        // (ii) The size of the srs restricts us to compute commitments to polynomials of degree n
                        //      (and disallows for degree 2n and 3n for large n).
                        //
                        // The degree of t(X) is determined by the term:
                        // ((a(X) + βX + γ) (b(X) + βk_1X + γ) (c(X) + βk_2X + γ)z(X)) / Z*_H(X).
                        //
                        // Let k = num_roots_cut_out_of_vanishing_polynomial, we have
                        // deg(t) = (n - 1) * (program_width + 1) - (n - k)
                        //        = n * program_width - program_width - 1 + k
                        //
                        // Since we must cut atleast 4 roots from the vanishing polynomial
                        // (refer to
                        // ./src/aztec/plonk/proof_system/widgets/random_widgets/permutation_widget_impl.hpp/L247), k =
                        // 4 => deg(t) = n * program_width - program_width + 3
                        //
                        // For standard plonk, program_width = 3 and thus, deg(t) = 3n. This implies that there would be
                        // (3n + 1) coefficients of t(X). Now, splitting them into t_{low}(X), t_{mid}(X) and
                        // t_{high}(X), t_{high} will have (n+1) coefficients while t_{low} and t_{mid} will have n
                        // coefficients. This means that to commit t_{high}, we need a multi-scalar multiplication of
                        // size (n+1). Thus, we first compute the commitments to t_{low}(X), t_{mid}(X) using n
                        // multi-scalar multiplications each and separately compute commitment to t_{high} which is of
                        // size (n + 1). Note that this must be done only when program_width = 3.
                        //
                        //
                        // NOTE: If in future there is a need to cut off more zeros off the vanishing polynomial, the
                        // degree of the quotient polynomial t(X) will increase, so the degrees of t_{high}, t_{mid},
                        // t_{low} could also increase according to the type of the composer type we are using.
                        // Currently, for TurboPLONK and Ultra- PLONK, the degree of t(X) is (4n - 1) and hence each
                        // t_{low}, t_{mid}, t_{high}, t_{higher} each is of degree (n - 1) (and thus contains n
                        // coefficients). Therefore, we are on the brink! If we need to cut out more zeros off the
                        // vanishing polynomial, sizes of coefficients of individual t_{i} would change and so we will
                        // have to ensure the correct size of multi-scalar multiplication in computing the commitments
                        // to these polynomials.
                        //
                        for (size_t i = 0; i < program_width - 1; ++i) {
                            const size_t offset = n * i;
                            typename TCurve::scalar_field_type::value_type *coefficients =
                                &key->quotient_large.get_coefficients()[offset];
                            std::string quotient_tag = "T_" + std::to_string(i + 1);
                            commitment->commit(coefficients, quotient_tag,
                                               typename TCurve::scalar_field_type::value_type::zero(), queue);
                        }

                        typename TCurve::scalar_field_type::value_type *coefficients =
                            &key->quotient_large.get_coefficients()[(program_width - 1) * n];
                        std::string quotient_tag = "T_" + std::to_string(program_width);
                        typename TCurve::scalar_field_type::value_type program_flag =
                            program_width == 3 ? typename TCurve::scalar_field_type::value_type::one() :
                                                 typename TCurve::scalar_field_type::value_type::zero();
                        commitment->commit(coefficients, quotient_tag, program_flag, queue);
                    }

                    void execute_preamble_round() {
                        queue.flush_queue();
                        transcript.add_element("circuit_size",
                                               {static_cast<std::uint8_t>(n >> 24), static_cast<std::uint8_t>(n >> 16),
                                                static_cast<std::uint8_t>(n >> 8), static_cast<std::uint8_t>(n)});
                        transcript.add_element("public_input_size",
                                               {static_cast<std::uint8_t>(key->num_public_inputs >> 24),
                                                static_cast<std::uint8_t>(key->num_public_inputs >> 16),
                                                static_cast<std::uint8_t>(key->num_public_inputs >> 8),
                                                static_cast<std::uint8_t>(key->num_public_inputs)});
                        transcript.apply_fiat_shamir("init");

                        for (size_t i = 0; i < settings::program_width; ++i) {
                            // fetch witness wire w_i
                            std::string wire_tag = "w_" + std::to_string(i + 1);
                            math::polynomial &wire = witness->wires.at(wire_tag);

                            /*
                            Adding zero knowledge to the witness polynomials.
                            */
                            // To ensure that PLONK is honest-verifier zero-knowledge, we need to ensure that the
                            // witness polynomials and the permutation polynomial look uniformly random to an adversary.
                            // To make the witness polynomials a(X), b(X) and c(X) uniformly random, we need to add 2
                            // random blinding factors into each of them. i.e. a'(X) = a(X) + (r_1X + r_2) where r_1 and
                            // r_2 are uniformly random scalar field elements. A natural question is: Why do we need 2
                            // random scalars in witness polynomials? The reason is: our witness polynomials are
                            // evaluated at only 1 point (\scripted{z}), so adding a random degree-1 polynomial
                            // suffices.
                            //
                            // NOTE: In TurboPlonk and UltraPlonk, the witness polynomials are evaluated at 2 points and
                            // thus we need to add 3 random scalars in them.
                            //
                            // We start adding random scalars in `wire` polynomials from index (n - k) upto (n - k + 2).
                            // For simplicity, we add 3 random scalars even for standard plonk (recall, just 2 of them
                            // are required) since an additional random scalar would not affect things.
                            //
                            // NOTE: If in future there is a need to cut off more zeros off the vanishing polynomial,
                            // this method will not change. This must be changed only if the number of evaluations of
                            // witness polynomials change.
                            //
                            const size_t w_randomness = 3;
                            ASSERT(w_randomness < settings::num_roots_cut_out_of_vanishing_polynomial);
                            for (size_t k = 0; k < w_randomness; ++k) {
                                wire.at(n - settings::num_roots_cut_out_of_vanishing_polynomial + k) =
                                    algebra::random_element(typename TCurve::scalar_field_type);
                            }

                            math::polynomial &wire_fft = key->wire_ffts.at(wire_tag + "_fft");
                            math::polynomial_arithmetic::copy_polynomial(&wire[0], &wire_fft[0], n, n);
                            queue.add_to_queue({
                                work_queue::WorkType::IFFT,
                                nullptr,
                                wire_tag,
                                typename TCurve::scalar_field_type::value_type::zero(),
                                0,
                            });
                        }
                    }

                    void execute_first_round() {
                        queue.flush_queue();
                        compute_wire_pre_commitments();
                        for (auto &widget : random_widgets) {
                            widget->compute_round_commitments(transcript, 1, queue);
                        }
                    }

                    void execute_second_round() {
                        queue.flush_queue();
                        transcript.apply_fiat_shamir("eta");
                        for (auto &widget : random_widgets) {
                            widget->compute_round_commitments(transcript, 2, queue);
                        }
                    }

                    void execute_third_round() {
                        queue.flush_queue();
                        transcript.apply_fiat_shamir("beta");
                        for (auto &widget : random_widgets) {
                            widget->compute_round_commitments(transcript, 3, queue);
                        }

                        for (size_t i = 0; i < settings::program_width; ++i) {
                            std::string wire_tag = "w_" + std::to_string(i + 1);
                            queue.add_to_queue({
                                work_queue::WorkType::FFT,
                                nullptr,
                                wire_tag,
                                typename TCurve::scalar_field_type::value_type::zero(),
                                0,
                            });
                        }
                    }

                    void execute_fourth_round() {
                        queue.flush_queue();
                        transcript.apply_fiat_shamir("alpha");

                        typename TCurve::scalar_field_type::value_type alpha_base =
                            typename TCurve::scalar_field_type::value_type::serialize_from_buffer(
                                transcript.get_challenge("alpha").begin());

                        for (auto &widget : random_widgets) {
                            alpha_base = widget->compute_quotient_contribution(alpha_base, transcript);
                        }
                        for (auto &widget : transition_widgets) {
                            alpha_base = widget->compute_quotient_contribution(alpha_base, transcript);
                        }
                        typename TCurve::scalar_field_type::value_type *q_mid = &key->quotient_mid[0];
                        typename TCurve::scalar_field_type::value_type *q_large = &key->quotient_large[0];

                        if constexpr (settings::uses_quotient_mid) {
                            math::polynomial_arithmetic::divide_by_pseudo_vanishing_polynomial(
                                key->quotient_mid.get_coefficients(), key->small_domain, key->mid_domain);
                        }
                        math::polynomial_arithmetic::divide_by_pseudo_vanishing_polynomial(
                            key->quotient_large.get_coefficients(), key->small_domain, key->large_domain);
                        if (settings::uses_quotient_mid) {
                            key->quotient_mid.coset_ifft(key->mid_domain);
                        }
                        key->quotient_large.coset_ifft(key->large_domain);
                        if (settings::uses_quotient_mid) {
                            ITERATE_OVER_DOMAIN_START(key->mid_domain);
                            q_large[i] += q_mid[i];
                            ITERATE_OVER_DOMAIN_END;
                        }
                        compute_quotient_pre_commitment();
                    }

                    void execute_fifth_round() {
                        queue.flush_queue();
                        transcript.apply_fiat_shamir("z");    // end of 4th round
                        compute_linearisation_coefficients();
                    }

                    void execute_sixth_round() {
                        queue.flush_queue();
                        transcript.apply_fiat_shamir("nu");

                        commitment->batch_open(transcript, queue, key, witness);
                    }

                    typename TCurve::scalar_field_type::value_type compute_linearisation_coefficients() {

                        typename TCurve::scalar_field_type::value_type zeta = crypto3::marshalling::algebra <
                                                                              typename TCurve::scalar_field_type >>
                                                                              (transcript.get_challenge("z").begin());

                        math::polynomial &r = key->linear_poly;

                        commitment->add_opening_evaluations_to_transcript(transcript, key, witness, false);
                        typename TCurve::scalar_field_type::value_type t_eval =
                            key->quotient_large.evaluate(zeta, 4 * n);

                        if constexpr (use_linearisation) {
                            typename TCurve::scalar_field_type::value_type alpha_base =
                                typename TCurve::scalar_field_type::value_type::serialize_from_buffer(
                                    transcript.get_challenge("alpha").begin());

                            for (auto &widget : random_widgets) {
                                alpha_base = widget->compute_linear_contribution(alpha_base, transcript, r);
                            }
                            for (auto &widget : transition_widgets) {
                                alpha_base = widget->compute_linear_contribution(alpha_base, transcript, &r[0]);
                            }
                            typename TCurve::scalar_field_type::value_type linear_eval = r.evaluate(zeta, n);
                            transcript.add_element("r", linear_eval.to_buffer());
                        }
                        transcript.add_element("t", t_eval.to_buffer());
                        return t_eval;
                    }

                    plonk_proof &export_proof() {
                        proof.proof_data = transcript.export_transcript();
                        return proof;
                    }

                    plonk_proof &construct_proof() {
                        execute_preamble_round();
                        queue.process_queue();
                        execute_first_round();
                        queue.process_queue();
                        execute_second_round();
                        queue.process_queue();
                        execute_third_round();
                        queue.process_queue();
                        execute_fourth_round();
                        queue.process_queue();
                        execute_fifth_round();
                        execute_sixth_round();
                        queue.process_queue();
                        return export_proof();
                    }

                    void reset() {
                        transcript::Manifest manifest = transcript.get_manifest();
                        transcript = transcript::StandardTranscript(manifest, settings::hash_type,
                                                                    settings::num_challenge_bytes);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_KATE_PROVER_HPP
