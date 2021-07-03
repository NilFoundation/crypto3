//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_HPP

#include <type_traits>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/detail/basic_policy.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/modes.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/generator.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/prover.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/verifier.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/generator.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/prover.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/verifier.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType, typename Generator, typename Prover, typename Verifier>
                using is_basic_mode = typename std::integral_constant<
                    bool,
                    std::is_same<r1cs_gg_ppzksnark_generator<CurveType>, Generator>::value &&
                        std::is_same<r1cs_gg_ppzksnark_prover<CurveType>, Prover>::value &&
                        (std::is_same<r1cs_gg_ppzksnark_verifier_weak_input_consistency<CurveType>, Verifier>::value ||
                         std::is_same<r1cs_gg_ppzksnark_verifier_strong_input_consistency<CurveType>,
                                      Verifier>::value ||
                         std::is_same<r1cs_gg_ppzksnark_affine_verifier_weak_input_consistency<CurveType>,
                                      Verifier>::value)>;

                template<typename CurveType, typename Generator, typename Prover, typename Verifier>
                using is_aggregate_mode = typename std::integral_constant<
                    bool,
                    std::is_same<r1cs_gg_ppzksnark_aggregate_generator<CurveType>, Generator>::value &&
                        std::is_same<r1cs_gg_ppzksnark_aggregate_prover<CurveType, typename Prover::basic_prover>,
                                     Prover>::value &&
                        std::is_same<r1cs_gg_ppzksnark_aggregate_verifier<CurveType, typename Verifier::basic_verifier>,
                                     Verifier>::value>;
                /*!
                 * @brief ppzkSNARK for R1CS with a security proof in the generic group (GG) model
                 * @tparam CurveType
                 * @tparam Generator
                 * @tparam Prover
                 * @tparam Verifier
                 *
                 * The implementation instantiates the protocol of \[Gro16] and aggregation scheme \[BMM+19] for the
                 * protocol of \[Gro16].
                 *
                 * Acronyms:
                 * - R1CS = "Rank-1 Constraint Systems"
                 * - ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
                 * - SRS = "Structured Reference String"
                 *
                 * References:
                 * \[Gro16]:
                 * "On the Size of Pairing-based Non-interactive Arguments",
                 * Jens Groth,
                 * EUROCRYPT 2016,
                 * <https://eprint.iacr.org/2016/260>
                 *
                 * \[BMM+19]:
                 * "Proofs for inner pairing products and applications",
                 * Benedikt Bünz, Mary Maller, Pratyush Mishra, Nirvan Tyagi, Psi Vesely,
                 * Cryptology ePrint Archive, Report 2019/1177, 2019
                 * <https://eprint.iacr.org/2019/1177.pdf>
                 */
                template<typename CurveType, typename Generator = r1cs_gg_ppzksnark_generator<CurveType>,
                         typename Prover = r1cs_gg_ppzksnark_prover<CurveType>,
                         typename Verifier = r1cs_gg_ppzksnark_verifier_strong_input_consistency<CurveType>,
                         ProvingMode mode = ProvingMode::Basic, typename = void>
                class r1cs_gg_ppzksnark;

                template<typename CurveType, typename Generator, typename Prover, typename Verifier>
                class r1cs_gg_ppzksnark<
                    CurveType, Generator, Prover, Verifier, ProvingMode::Basic,
                    typename std::enable_if<is_basic_mode<CurveType, Generator, Prover, Verifier>::value>::type> {
                    typedef detail::r1cs_gg_ppzksnark_basic_policy<CurveType, ProvingMode::Basic> policy_type;

                public:
                    typedef typename policy_type::constraint_system_type constraint_system_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    static inline keypair_type generate(const constraint_system_type &constraint_system) {
                        return Generator::process(constraint_system);
                    }

                    static inline proof_type prove(const proving_key_type &pk,
                                                   const primary_input_type &primary_input,
                                                   const auxiliary_input_type &auxiliary_input) {

                        return Prover::process(pk, primary_input, auxiliary_input);
                    }

                    template<typename VerificationKey>
                    static inline bool verify(const VerificationKey &vk,
                                              const primary_input_type &primary_input,
                                              const proof_type &proof) {
                        return Verifier::process(vk, primary_input, proof);
                    }
                };

                template<typename CurveType, typename Generator, typename Prover, typename Verifier>
                class r1cs_gg_ppzksnark<
                    CurveType, Generator, Prover, Verifier, ProvingMode::Aggregate,
                    typename std::enable_if<is_aggregate_mode<CurveType, Generator, Prover, Verifier>::value>::type> {
                    typedef detail::r1cs_gg_ppzksnark_basic_policy<CurveType, ProvingMode::Aggregate> policy_type;

                public:
                    typedef typename policy_type::constraint_system_type constraint_system_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;

                    typedef typename policy_type::srs_type srs_type;
                    typedef typename policy_type::proving_srs_type proving_srs_type;
                    typedef typename policy_type::verification_srs_type verification_srs_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::srs_pair_type srs_pair_type;

                    typedef typename policy_type::proof_type proof_type;
                    typedef typename policy_type::aggregate_proof_type aggregate_proof_type;

                    // Generate key pair
                    template<typename DistributionType = boost::random::uniform_int_distribution<
                                 typename CurveType::scalar_field_type::modulus_type>,
                             typename GeneratorType = boost::random::mt19937>
                    static inline keypair_type generate(const constraint_system_type &constraint_system) {
                        return Generator::template process<DistributionType, GeneratorType>(constraint_system);
                    }

                    // Generate SRS pair
                    template<typename DistributionType = boost::random::uniform_int_distribution<
                                 typename CurveType::scalar_field_type::modulus_type>,
                             typename GeneratorType = boost::random::mt19937>
                    static inline srs_pair_type generate(std::size_t num_proofs) {
                        return Generator::template process<DistributionType, GeneratorType>(num_proofs);
                    }

                    // Basic proove
                    static inline proof_type prove(const proving_key_type &pk,
                                                   const primary_input_type &primary_input,
                                                   const auxiliary_input_type &auxiliary_input) {

                        return Prover::process(pk, primary_input, auxiliary_input);
                    }

                    // Aggregate prove
                    template<typename Hash, typename InputTranscriptIncludeIterator, typename InputProofIterator>
                    static inline aggregate_proof_type prove(const proving_srs_type &srs,
                                                             InputTranscriptIncludeIterator transcript_include_first,
                                                             InputTranscriptIncludeIterator transcript_include_last,
                                                             InputProofIterator proofs_first,
                                                             InputProofIterator proofs_last) {

                        return Prover::template process<Hash>(srs, transcript_include_first, transcript_include_last,
                                                              proofs_first, proofs_last);
                    }

                    // Basic verify
                    template<typename VerificationKey>
                    static inline bool verify(const VerificationKey &vk,
                                              const primary_input_type &primary_input,
                                              const proof_type &proof) {
                        return Verifier::process(vk, primary_input, proof);
                    }

                    // Aggregate verify
                    template<typename DistributionType = boost::random::uniform_int_distribution<
                                 typename CurveType::scalar_field_type::modulus_type>,
                             typename GeneratorType = boost::random::mt19937, typename Hash = hashes::sha2<256>,
                             typename InputPrimaryInputRange, typename InputIterator>
                    static inline bool verify(const verification_srs_type &ip_verifier_srs,
                                              const verification_key_type &pvk,
                                              const InputPrimaryInputRange &public_inputs,
                                              const aggregate_proof_type &proof,
                                              InputIterator transcript_include_first,
                                              InputIterator transcript_include_last) {
                        return Verifier::template process<DistributionType, GeneratorType, Hash>(
                            ip_verifier_srs, pvk, public_inputs, proof, transcript_include_first,
                            transcript_include_last);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_HPP
