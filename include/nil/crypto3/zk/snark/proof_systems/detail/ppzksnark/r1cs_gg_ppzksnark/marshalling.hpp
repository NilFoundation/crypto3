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

                    template<typename ProofSystem>
                    struct verifier_data_from_bits;

                    template<typename CurveType>
                    class verifier_data_from_bits<r1cs_gg_ppzksnark<CurveType>> {
                        using proof_system = r1cs_gg_ppzksnark<CurveType>;

                        using modulus_type = typename CurveType::base_field_type::modulus_type;
                        using number_type = typename CurveType::base_field_type::number_type;

                        constexpr static const std::size_t modulus_bits = CurveType::base_field_type::modulus_bits;

                        using chunk_type = std::uint8_t;

                        constexpr static const std::size_t chunk_size = 8;
                        constexpr static const std::size_t modulus_chunks =
                            modulus_bits / chunk_size + modulus_bits % chunk_size;

                        template<typename FieldType>
                        static inline
                            typename std::enable_if<!::nil::crypto3::detail::is_extended_field<FieldType>::value,
                                                    typename FieldType::value_type>::type
                            field_process(std::vector<chunk_type>::iterator &read_iter) {

                            using field_type = FieldType;

                            modulus_type fp_out;

                            boost::multiprecision::import_bits(fp_out, read_iter, read_iter + modulus_chunks,
                                                               chunk_size, false);

                            read_iter += modulus_chunks;

                            return typename field_type::value_type(fp_out);
                        }

                        template<typename FieldType>
                        static inline
                            typename std::enable_if<::nil::crypto3::detail::is_extended_field<FieldType>::value,
                                                    typename FieldType::value_type>::type
                            field_process(std::vector<chunk_type>::iterator &read_iter) {

                            using field_type = FieldType;

                            typename field_type::value_type::data_type data;
                            const std::size_t data_dimension =
                                field_type::arity / field_type::underlying_field_type::arity;

                            for (int n = 0; n < data_dimension; ++n) {
                                data[n] = field_process<typename field_type::underlying_field_type>(read_iter);
                            }

                            return typename field_type::value_type(data);
                        }

                        template<typename GroupType>
                        static inline typename GroupType::value_type
                            group_type_process(std::vector<chunk_type>::iterator &read_iter) {

                            typename GroupType::underlying_field_type::value_type X =
                                field_process<typename GroupType::underlying_field_type>(read_iter);

                            typename GroupType::underlying_field_type::value_type Y =
                                field_process<typename GroupType::underlying_field_type>(read_iter);

                            typename GroupType::underlying_field_type::value_type Z =
                                field_process<typename GroupType::underlying_field_type>(read_iter);

                            return typename GroupType::value_type(X, Y, Z);
                        }

                    public:
                        struct verifier_data {
                            typename proof_system::verification_key_type vk;
                            typename proof_system::primary_input_type pi;
                            typename proof_system::proof_type pr;

                            verifier_data() {};

                            verifier_data(typename proof_system::verification_key_type vk,
                                          typename proof_system::primary_input_type pi,
                                          typename proof_system::proof_type pr) :
                                vk(vk),
                                pi(pi), pr(pr) {};
                        };

                        template<typename DataType>
                        static inline verifier_data process(DataType data) {
                            return verifier_data();
                        }

                        static inline verifier_data process(std::vector<chunk_type> data) {

                            std::vector<chunk_type>::iterator read_iter = data.begin();

                            typename CurveType::g1_type::value_type g1_out =
                                group_type_process<typename CurveType::g1_type>(read_iter);

                            std::cout << "processed g1: " << g1_out.X.data << std::endl
                                      << g1_out.Y.data << std::endl
                                      << g1_out.Z.data << std::endl;

                            typename CurveType::g2_type::value_type g2_out =
                                group_type_process<typename CurveType::g2_type>(read_iter);

                            std::cout << "processed g2: " << g2_out.X.data[0].data << std::endl
                                      << g2_out.X.data[1].data << std::endl
                                      << g2_out.Y.data[0].data << std::endl
                                      << g2_out.Y.data[1].data << std::endl
                                      << g2_out.Z.data[0].data << std::endl
                                      << g2_out.Z.data[1].data << std::endl;

                            return verifier_data();
                        }
                    };

                    template<typename ProofSystem>
                    class verifier_data_to_bits;

                    // TODO: reimplement private functions using field value type trait
                    template<typename CurveType>
                    class verifier_data_to_bits<r1cs_gg_ppzksnark<CurveType>> {
                        using proof_system = r1cs_gg_ppzksnark<CurveType>;

                        constexpr static const std::size_t modulus_bits = CurveType::base_field_type::modulus_bits;

                        typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_int_backend<>>
                            modulus_type;

                        using chunk_type = std::uint8_t;

                        constexpr static const std::size_t chunk_size = 8;
                        constexpr static const std::size_t modulus_chunks =
                            modulus_bits / chunk_size + modulus_bits % chunk_size;

                        template<typename FieldType>
                        static inline
                            typename std::enable_if<!::nil::crypto3::detail::is_extended_field<FieldType>::value,
                                                    void>::type
                            field_process(typename FieldType::value_type input_fp,
                                          std::vector<chunk_type>::iterator &write_iter) {

                            boost::multiprecision::export_bits(modulus_type(input_fp.data), write_iter, chunk_size,
                                                               false);
                            write_iter += modulus_chunks;
                        }

                        template<typename FieldType>
                        static inline
                            typename std::enable_if<::nil::crypto3::detail::is_extended_field<FieldType>::value,
                                                    void>::type
                            field_process(typename FieldType::value_type input_fp,
                                          std::vector<chunk_type>::iterator &write_iter) {

                            using field_type = FieldType;

                            const std::size_t data_dimension =
                                field_type::arity / field_type::underlying_field_type::arity;

                            for (int n = 0; n < data_dimension; ++n) {
                                field_process<typename field_type::underlying_field_type>(input_fp.data[n], write_iter);
                            }
                        }

                        template<typename GroupType>
                        static inline void group_type_process(typename GroupType::value_type input_g,
                                                              std::vector<chunk_type>::iterator &write_iter) {

                            field_process<typename GroupType::underlying_field_type>(input_g.X, write_iter);
                            field_process<typename GroupType::underlying_field_type>(input_g.Y, write_iter);
                            field_process<typename GroupType::underlying_field_type>(input_g.Z, write_iter);
                        }

                    public:
                        struct verifier_data {
                            typename proof_system::verification_key_type vk;
                            typename proof_system::primary_input_type pi;
                            typename proof_system::proof_type pr;

                            verifier_data() {};

                            verifier_data(typename proof_system::verification_key_type vk,
                                          typename proof_system::primary_input_type pi,
                                          typename proof_system::proof_type pr) :
                                vk(vk),
                                pi(pi), pr(pr) {};
                        };

                        static inline std::vector<chunk_type> process() {

                            constexpr static const std::size_t g1_modulus_chunks_coeff =
                                3 * CurveType::g1_type::underlying_field_type::arity;
                            constexpr static const std::size_t g2_modulus_chunks_coeff =
                                3 * CurveType::g2_type::underlying_field_type::arity;

                            std::vector<chunk_type> output(modulus_chunks *
                                                           (g1_modulus_chunks_coeff + g2_modulus_chunks_coeff));

                            std::vector<chunk_type>::iterator write_iter = output.begin();

                            using g2_field_value = typename CurveType::g2_type::underlying_field_type::value_type;

                            typename CurveType::g1_type::value_type input_g1(16 * 99 + 13, 17, 10 * 16 + 7);
                            typename CurveType::g2_type::value_type input_g2(g2_field_value(16 * 7, 1),
                                                                             g2_field_value(11, 7),
                                                                             g2_field_value(12 * 16 + 9, 5 * 16 + 1));

                            group_type_process<typename CurveType::g1_type>(input_g1, write_iter);
                            group_type_process<typename CurveType::g2_type>(input_g2, write_iter);

                            std::cout << "g1:" << std::endl;
                            for (int i = 0; i < modulus_chunks * (g1_modulus_chunks_coeff); ++i) {
                                std::cout << i % modulus_chunks << ": 0x" << std::hex << int(output[i]) << std::endl;
                            }

                            std::cout << "g2:" << std::endl;
                            for (int i = modulus_chunks * g1_modulus_chunks_coeff;
                                 i < modulus_chunks * (g1_modulus_chunks_coeff + g2_modulus_chunks_coeff);
                                 ++i) {
                                std::cout << i % modulus_chunks << ": 0x" << std::hex << int(output[i]) << std::endl;
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
