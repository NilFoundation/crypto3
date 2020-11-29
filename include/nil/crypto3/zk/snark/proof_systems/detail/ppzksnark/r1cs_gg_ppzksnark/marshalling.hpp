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
// @file Declaration of interfaces for a ppzkSNARK for R1CS with a security proof
// in the generic group (GG) model.
//
// This includes:
//- class for proving key
//- class for verification key
//- class for processed verification key
//- class for key pair (proving key & verification key)
//- class for proof
//- generator algorithm
//- prover algorithm
//- verifier algorithm (with strong or weak input consistency)
//- online verifier algorithm (with strong or weak input consistency)
//
// The implementation instantiates the protocol of \[Gro16].
//
//
// Acronyms:
//
//- R1CS = "Rank-1 Constraint Systems"
//- ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
//
// References:
//
//\[Gro16]:
// "On the Size of Pairing-based Non-interactive Arguments",
// Jens Groth,
// EUROCRYPT 2016,
// <https://eprint.iacr.org/2016/260>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_PSEUDO_MARSHALLING_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_PSEUDO_MARSHALLING_HPP

#include <vector>

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/modular/modular_adaptor.hpp>

#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/r1cs_gg_ppzksnark/types_policy.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template <typename ProofSystem>
                    struct verifier_data_from_bits;

                    template <typename CurveType>
                    class verifier_data_from_bits<r1cs_gg_ppzksnark<CurveType>> {
                        using proof_system = r1cs_gg_ppzksnark<CurveType>;

                        using modulus_type = typename CurveType::base_field_type::modulus_type;
                        using number_type = typename CurveType::base_field_type::number_type;

                        constexpr static const std::size_t modulus_bits = CurveType::base_field_type::modulus_bits;

                        using chunk_type = std::uint8_t;
                        
                        constexpr static const std::size_t chunk_size = 8;
                        constexpr static const std::size_t modulus_chunks = modulus_bits/chunk_size + 
                                                                            modulus_bits%chunk_size;

                        static inline typename CurveType::g1_type::value_type 
                            g1_type_process (std::vector<chunk_type>::iterator read_iter){

                            using g1_field_value_type = 
                                typename CurveType::g1_type::underlying_field_type::value_type;

                            modulus_type g1_out_X, g1_out_Y, g1_out_Z;

                            boost::multiprecision::import_bits(g1_out_X, read_iter, read_iter + modulus_chunks, 
                                                               chunk_size, false);

                            std::cout << "processed X value: " << g1_out_X << std::endl;

                            read_iter += modulus_chunks;
                            boost::multiprecision::import_bits(g1_out_Y, read_iter, read_iter + modulus_chunks, 
                                                               chunk_size, false);

                            std::cout << "processed Y value: " << g1_out_Y << std::endl;

                            read_iter += modulus_chunks;
                            boost::multiprecision::import_bits(g1_out_Z, read_iter, read_iter + modulus_chunks, 
                                                               chunk_size, false);

                            std::cout << "processed Z value: " << g1_out_Z << std::endl;
                            
                            number_type g1_X_n (g1_out_X);
                            //g1_field_value_type g1_X (g1_out_X);

                            exit(0);
                            /*g1_field_value_type g1_Y(g1_out_Y);
                            g1_field_value_type g1_Z = 
                                g1_field_value_type(g1_out_Z);

                            std::cout << "processed value: " << g1_X.data << std::endl 
                                                             << g1_Y.data << std::endl
                                                             << g1_Z.data << std::endl;
                                                             */

                            typename CurveType::g1_type::value_type g1_out;/*= 
                                typename CurveType::g1_type::value_type(g1_X, g1_Y, g1_Z);*/

                            return g1_out;
                        }
                    public:

                        struct verifier_data {
                            typename proof_system::verification_key_type vk;
                            typename proof_system::primary_input_type pi;
                            typename proof_system::proof_type pr;

                            verifier_data(){};

                            verifier_data(typename proof_system::verification_key_type vk,
                                          typename proof_system::primary_input_type pi,
                                          typename proof_system::proof_type pr):
                                          vk(vk), pi(pi), pr(pr){};
                        };

                        template <typename DataType>
                        static inline verifier_data process (DataType data){
                            return verifier_data();
                        }

                        static inline verifier_data process (std::vector<chunk_type> data){

                            //typename CurveType::g1_type::value_type g1_out = g1_type_process(data.begin());

                            using g1_field_value_type = 
                                typename CurveType::g1_type::underlying_field_type::value_type;

                            modulus_type g1_out_X, g1_out_Y, g1_out_Z;

                            auto read_iter = data.begin();

                            boost::multiprecision::import_bits(g1_out_X, read_iter, read_iter + modulus_chunks, 
                                                               chunk_size, false);

                            std::cout << "processed X value: " << g1_out_X << std::endl;

                            read_iter += modulus_chunks;
                            boost::multiprecision::import_bits(g1_out_Y, read_iter, read_iter + modulus_chunks, 
                                                               chunk_size, false);

                            std::cout << "processed Y value: " << g1_out_Y << std::endl;

                            read_iter += modulus_chunks;
                            boost::multiprecision::import_bits(g1_out_Z, read_iter, read_iter + modulus_chunks, 
                                                               chunk_size, false);

                            std::cout << "processed Z value: " << g1_out_Z << std::endl;
                            
                            number_type g1_X_n (g1_out_X);

                            std::cout << "processed value: " << g1_X_n << std::endl;

                            return verifier_data();
                        }
                    };

                    template <typename ProofSystem>
                    class verifier_data_to_bits;

                    template <typename CurveType>
                    class verifier_data_to_bits<r1cs_gg_ppzksnark<CurveType>> {
                        using proof_system = r1cs_gg_ppzksnark<CurveType>;

                        constexpr static const std::size_t modulus_bits = CurveType::base_field_type::modulus_bits;

                        typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_int_backend<>>
                            modulus_type;

                        using chunk_type = std::uint8_t;

                        constexpr static const std::size_t chunk_size = 8;
                        constexpr static const std::size_t modulus_chunks = modulus_bits/chunk_size + 
                                                                            modulus_bits%chunk_size;


                        static inline std::vector<chunk_type> g1_type_process (
                            typename CurveType::g1_type::value_type input_g1){

                            std::vector<chunk_type> output_data (modulus_chunks * 3, 0);

                            auto write_iter = output_data.begin();

                            boost::multiprecision::export_bits(modulus_type(input_g1.X.data), 
                                write_iter, chunk_size, false);

                            write_iter += modulus_chunks;
                            boost::multiprecision::export_bits(modulus_type(input_g1.Y.data), 
                                write_iter, chunk_size, false);

                            write_iter += modulus_chunks;
                            boost::multiprecision::export_bits(modulus_type(input_g1.Z.data), 
                                write_iter, chunk_size, false);

                            write_iter += modulus_chunks;
                            /*for (int i = 0; i < modulus_chunks * 3; ++i){
                                std::cout << i % modulus_chunks << ": 0x" << std::hex << 
                                    int(output_data[i]) << std::endl;
                            }

                            std::cout << std::endl;*/

                            return output_data;
                        }

                    public:

                        struct verifier_data {
                            typename proof_system::verification_key_type vk;
                            typename proof_system::primary_input_type pi;
                            typename proof_system::proof_type pr;

                            verifier_data(){};

                            verifier_data(typename proof_system::verification_key_type vk,
                                          typename proof_system::primary_input_type pi,
                                          typename proof_system::proof_type pr):
                                          vk(vk), pi(pi), pr(pr){};
                        };

                        static inline std::vector<chunk_type> process (){

                            std::vector<chunk_type> output;

                            std::vector<chunk_type> g1_out = g1_type_process (
                                typename CurveType::g1_type::value_type (16*99 + 13, 17, 10*16 + 7));

                            output.reserve(output.size() + distance(g1_out.begin(),g1_out.end()));
                            output.insert(output.end(),g1_out.begin(),g1_out.end());

                            for (int i = 0; i < modulus_chunks * 3; ++i){
                                std::cout << i % modulus_chunks << ": 0x" << std::hex << 
                                    int(output[i]) << std::endl;
                            }
                            
                            std::cout << std::endl;

                            return output;
                        }
                    };

                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_PSEUDO_MARSHALLING_HPP
