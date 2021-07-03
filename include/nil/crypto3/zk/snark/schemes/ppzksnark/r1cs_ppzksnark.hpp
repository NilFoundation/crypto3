//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ZK_R1CS_PPZKSNARK_HPP
#define CRYPTO3_ZK_R1CS_PPZKSNARK_HPP

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_ppzksnark/detail/basic_policy.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_ppzksnark/generator.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_ppzksnark/prover.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_ppzksnark/verifier.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /*!
                 * @brief ppzkSNARK for R1CS
                 * @tparam CurveType
                 * @tparam Generator
                 * @tparam Prover
                 * @tparam Verifier
                 *
                 * The implementation instantiates (a modification of) the protocol of \[PGHR13],
                 * by following extending, and optimizing the approach described in \[BCTV14].
                 *
                 * Acronyms:
                 * - R1CS = "Rank-1 Constraint Systems"
                 * - ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
                 *
                 * References:
                 * \[BCTV14]:
                 * "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture",
                 * Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
                 * USENIX Security 2014,
                 * <http://eprint.iacr.org/2013/879>
                 *
                 * \[PGHR13]:
                 * "Pinocchio: Nearly practical verifiable computation",
                 * Bryan Parno, Craig Gentry, Jon Howell, Mariana Raykova,
                 * IEEE S&P 2013,
                 * <https://eprint.iacr.org/2013/279>
                 */
                template<typename CurveType,
                         typename Generator = r1cs_ppzksnark_generator<CurveType>,
                         typename Prover = r1cs_ppzksnark_prover<CurveType>,
                         typename Verifier = r1cs_ppzksnark_verifier_strong_input_consistency<CurveType>>
                class r1cs_ppzksnark {
                    typedef detail::r1cs_ppzksnark_policy<CurveType> policy_type;

                public:
                    typedef Generator generator_type;
                    typedef Prover prover_type;
                    typedef Verifier verifier_type;

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

                    static inline bool verify(const typename Verifier::verification_key_type &vk,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {
                        return Verifier::process(vk, primary_input, proof);
                    }

                    static inline bool verify(const typename Verifier::processed_verification_key_type &pvk,
                                              const primary_input_type &primary_input,
                                              const proof_type &proof) {
                        return Verifier::process(pvk, primary_input, proof);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_PPZKSNARK_HPP
