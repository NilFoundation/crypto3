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
// @file Declaration of functionality that runs the R1CS GG-ppzkSNARK for
// a given R1CS example.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_RUN_R1CS_GG_PPZKSNARK_TVM_MARSHALLING_HPP
#define CRYPTO3_RUN_R1CS_GG_PPZKSNARK_TVM_MARSHALLING_HPP

#include <tuple>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/algorithms/generate.hpp>
#include <nil/crypto3/zk/snark/algorithms/verify.hpp>
#include <nil/crypto3/zk/snark/algorithms/prove.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>

#include <nil/marshalling/status_type.hpp>
#include "../r1cs_examples.hpp"

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename ProofSystem>
                bool run_verifier_with_byte_input(std::vector<std::uint8_t> data) {
                    using proof_system_policy = ProofSystem;

                    typename nil::marshalling::verifier_data_from_bits<proof_system_policy>::verifier_data vd =
                        nil::marshalling::verifier_data_from_bits<proof_system_policy>::process(data);

                    std::cout << "Data converted from byte blob" << std::endl;

                    return verify<proof_system_policy>(vd.vk, vd.pi, vd.pr);
                }

                /**
                 * The code below provides an example of all stages of running a R1CS GG-ppzkSNARK.
                 *
                 * Of course, in a real-life scenario, we would have three distinct entities,
                 * mangled into one in the demonstration below. The three entities are as follows.
                 * (1) The "generator", which runs the ppzkSNARK generator on input a given
                 *     constraint system CS to create a proving and a verification key for CS.
                 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
                 *     a primary input for CS, and an auxiliary input for CS.
                 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
                 *     a primary input for CS, and a proof.
                 */
                template<typename CurveType>
                bool run_r1cs_gg_ppzksnark_tvm_marshalling(const r1cs_example<typename CurveType::scalar_field_type> &example);

                template<>
                bool run_r1cs_gg_ppzksnark_tvm_marshalling<nil::crypto3::algebra::curves::bls12<381>>(
                    const r1cs_example<typename nil::crypto3::algebra::curves::bls12<381>::scalar_field_type> &example) {

                    using CurveType = typename nil::crypto3::algebra::curves::bls12<381>;

                    using scheme_type = r1cs_gg_ppzksnark<CurveType>;

                    std::cout << "Starting generator" << std::endl;

                    typename scheme_type::keypair_type keypair =
                        generate<scheme_type>(example.constraint_system);

                    std::cout << "Starting prover" << std::endl;

                    typename scheme_type::proof_type proof =
                        prove<scheme_type>(keypair.first, example.primary_input, example.auxiliary_input);

                    std::cout << std::hex << "Obtained proof: " << proof.g_A.to_affine().X.data << " " << proof.g_A.to_affine().Y.data << " " << proof.g_A.to_affine().Z.data << std::endl
                                                                << proof.g_B.to_affine().X.data[0].data << " " << proof.g_B.to_affine().X.data[1].data << " " << proof.g_B.to_affine().Y.data[0].data << std::endl
                                                                << proof.g_B.to_affine().Y.data[1].data << " " << proof.g_B.to_affine().Z.data[0].data << " " << proof.g_B.to_affine().Z.data[1].data << std::endl
                                                                << proof.g_C.to_affine().X.data << " " << proof.g_C.to_affine().Y.data << " " << proof.g_C.to_affine().Z.data << std::endl;

                    std::cout << std::hex << "Obtained verification key: " << "gamma_g2: " 
                                                                << keypair.second.gamma_g2.to_affine().X.data[0].data << " " << keypair.second.gamma_g2.to_affine().Y.data[0].data << " " << keypair.second.gamma_g2.to_affine().Z.data[0].data << std::endl
                                                                << keypair.second.gamma_g2.to_affine().X.data[1].data << " " << keypair.second.gamma_g2.to_affine().Y.data[1].data << " " << keypair.second.gamma_g2.to_affine().Z.data[1].data << std::endl
                                                                << "delta_g2: " 
                                                                << keypair.second.delta_g2.to_affine().X.data[0].data << " " << keypair.second.delta_g2.to_affine().Y.data[0].data << " " << keypair.second.delta_g2.to_affine().Z.data[0].data << std::endl
                                                                << keypair.second.delta_g2.to_affine().X.data[1].data << " " << keypair.second.delta_g2.to_affine().Y.data[1].data << " " << keypair.second.delta_g2.to_affine().Z.data[1].data << std::endl;

                    std::cout << std::hex << "Obtained primary input: " << std::endl;

                    for (auto it = example.primary_input.begin(); it != example.primary_input.end(); it++){
                        std::cout << std::hex << it->data << " " ;
                    }
                    std::cout << std::endl;


                    std::vector<std::uint8_t> verification_key_byteblob = nil::marshalling::verifier_input_serializer_tvm<scheme_type>::process(
                        keypair.second);
                    std::vector<std::uint8_t> primary_input_byteblob = nil::marshalling::verifier_input_serializer_tvm<scheme_type>::process(
                        example.primary_input);
                    std::vector<std::uint8_t> proof_byteblob = nil::marshalling::verifier_input_serializer_tvm<scheme_type>::process(
                        proof);

                    std::cout << "Verification key byteblob, size " << std::dec << verification_key_byteblob.size() << std::endl;

                    for (auto it = verification_key_byteblob.begin(); it != verification_key_byteblob.end(); ++it){
                        std::cout << std::hex << std::size_t(*it) << " " ;
                    }

                    std::cout << std::endl;

                    std::cout << "Primary input byteblob, size " << std::dec << primary_input_byteblob.size() << std::endl;

                    for (auto it = primary_input_byteblob.begin(); it != primary_input_byteblob.end(); ++it){
                        std::cout << std::hex << std::size_t(*it) << " " ;
                    }

                    std::cout << std::endl;

                    std::cout << "Proof byteblob, size " << std::dec << proof_byteblob.size() << std::endl;

                    for (auto it = proof_byteblob.begin(); it != proof_byteblob.end(); ++it){
                        std::cout << std::hex << std::size_t(*it) << " " ;
                    }

                    std::cout << std::endl;

                    std::vector<std::uint8_t> byteblob;

                    byteblob.insert (byteblob.end(), proof_byteblob.begin(), proof_byteblob.end());
                    byteblob.insert (byteblob.end(), primary_input_byteblob.begin(), primary_input_byteblob.end());
                    byteblob.insert (byteblob.end(), verification_key_byteblob.begin(), verification_key_byteblob.end());

                    std::cout << "Data converted to byte blob" << std::endl;

                    for (auto it = byteblob.begin(); it != byteblob.end(); ++it){
                        std::cout << std::hex << std::size_t(*it) << " " ;
                    }

                    std::cout << std::endl;

                    std::cout << "Starting verifier with plain input" << std::endl;

                    bool ans = verify<scheme_type>(keypair.second, example.primary_input, proof);

                    std::cout << "Verifier with plain input finished, result: " << ans << std::endl;

                    marshalling::status_type processingStatus = marshalling::status_type::success;
                    
                    auto tup = nil::marshalling::verifier_input_deserializer_tvm<scheme_type>::verifier_input_process(byteblob.cbegin(), 
                            byteblob.cend(),
                            processingStatus);

                    if (processingStatus != marshalling::status_type::success){
                        std::cout << "Incorrect datablob!" << std::endl;

                        return false;
                    }

                    BOOST_CHECK(processingStatus == marshalling::status_type::success);

                    typename scheme_type::proof_type de_prf = std::get<2>(tup);
                    typename scheme_type::primary_input_type de_pi = std::get<1>(tup);
                    typename scheme_type::verification_key_type de_vk = std::get<0>(tup);

                    // typename scheme_type::proof_type de_prf = nil::marshalling::verifier_input_deserializer_tvm<scheme_type>::proof_process(proof_byteblob.cbegin(), proof_byteblob.cend());
                    // typename scheme_type::primary_input_type de_pi = nil::marshalling::verifier_input_deserializer_tvm<scheme_type>::primary_input_process(primary_input_byteblob.cbegin(), primary_input_byteblob.cend());
                    // typename scheme_type::verification_key_type de_vk = nil::marshalling::verifier_input_deserializer_tvm<scheme_type>::verification_key_process(verification_key_byteblob.cbegin(), verification_key_byteblob.cend());

                    std::cout << std::hex << "Decoded proof: " << de_prf.g_A.to_affine().X.data << " " << de_prf.g_A.to_affine().Y.data << " " << de_prf.g_A.to_affine().Z.data << std::endl
                                                                << de_prf.g_B.to_affine().X.data[0].data << " " << de_prf.g_B.to_affine().X.data[1].data << " " << de_prf.g_B.to_affine().Y.data[0].data << std::endl
                                                                << de_prf.g_B.to_affine().Y.data[1].data << " " << de_prf.g_B.to_affine().Z.data[0].data << " " << de_prf.g_B.to_affine().Z.data[1].data << std::endl
                                                                << de_prf.g_C.to_affine().X.data << " " << de_prf.g_C.to_affine().Y.data << " " << de_prf.g_C.to_affine().Z.data << std::endl;

                    assert (de_prf == proof);

                    std::cout << std::hex << "Decoded primary input: " << std::endl;

                    for (auto it = de_pi.begin(); it != de_pi.end(); it++){
                        std::cout << std::hex << it->data << " " ;
                    }
                    std::cout << std::endl;

                    // assert (de_pi == example.primary_input);

                    std::cout << std::hex << "Decoded verification key: " << "gamma_g2: " 
                                                                << de_vk.gamma_g2.to_affine().X.data[0].data << " " << de_vk.gamma_g2.to_affine().Y.data[0].data << " " << de_vk.gamma_g2.to_affine().Z.data[0].data << std::endl
                                                                << de_vk.gamma_g2.to_affine().X.data[1].data << " " << de_vk.gamma_g2.to_affine().Y.data[1].data << " " << de_vk.gamma_g2.to_affine().Z.data[1].data << std::endl
                                                                << "delta_g2: " 
                                                                << de_vk.delta_g2.to_affine().X.data[0].data << " " << de_vk.delta_g2.to_affine().Y.data[0].data << " " << de_vk.delta_g2.to_affine().Z.data[0].data << std::endl
                                                                << de_vk.delta_g2.to_affine().X.data[1].data << " " << de_vk.delta_g2.to_affine().Y.data[1].data << " " << de_vk.delta_g2.to_affine().Z.data[1].data << std::endl;

                    assert (de_vk == keypair.second);

                    std::cout << "Starting verifier with decoded input" << std::endl;

                    ans = verify<scheme_type>(de_vk, de_pi, de_prf);

                    std::cout << "Verifier with decoded input finished, result: " << ans << std::endl;

                    return ans;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RUN_R1CS_GG_PPZKSNARK_TVM_MARSHALLING_HPP
