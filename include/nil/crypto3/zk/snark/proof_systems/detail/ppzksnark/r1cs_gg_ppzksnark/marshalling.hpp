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
#include <nil/crypto3/zk/snark/sparse_vector.hpp>
#include <nil/crypto3/zk/snark/accumulation_vector.hpp>

#include <nil/marshalling/field/int_value.hpp>
#include <nil/marshalling/field/bitmask_value.hpp>
#include <nil/marshalling/field/enum_value.hpp>
#include <nil/marshalling/field/array_list.hpp>
#include <nil/marshalling/field/string.hpp>
#include <nil/marshalling/field/bitfield.hpp>
#include <nil/marshalling/field/optional.hpp>
#include <nil/marshalling/field/bundle.hpp>
#include <nil/marshalling/field/float_value.hpp>
#include <nil/marshalling/field/no_value.hpp>
#include <nil/marshalling/field/variant.hpp>

#include <nil/marshalling/compile_control.hpp>
#include <nil/marshalling/units.hpp>
#include <nil/marshalling/version.hpp>

#include <nil/marshalling/message.hpp>
#include <nil/marshalling/message_base.hpp>
#include <nil/marshalling/msg_factory.hpp>
#include <nil/marshalling/generic_message.hpp>

#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/stream_endian.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename ProofSystem>
                    struct verifier_data_from_bits;

                    template<typename CurveType>
                    struct verifier_data_from_bits<r1cs_gg_ppzksnark<CurveType>> {
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
                        typename std::enable_if<
                                        !::nil::crypto3::detail::is_extended_field<FieldType>::value,
                                     typename FieldType::value_type>::type field_type_process (
                            std::vector<chunk_type>::iterator &read_iter){

                            using field_type = FieldType;

                            modulus_type fp_out;

                            boost::multiprecision::import_bits(fp_out, read_iter, read_iter + modulus_chunks,
                                                               chunk_size, false);

                            read_iter += modulus_chunks;

                            return typename field_type::value_type(fp_out);
                        }

                        template<typename FieldType>
                        static inline 
                        typename std::enable_if<
                                        ::nil::crypto3::detail::is_extended_field<FieldType>::value,
                                     typename FieldType::value_type>::type field_type_process (
                            std::vector<chunk_type>::iterator &read_iter){

                            using field_type = FieldType;

                            typename field_type::value_type::data_type data;
                            const std::size_t data_dimension = field_type::arity / 
                                                   field_type::underlying_field_type::arity;
                            
                            for(int n = 0; n < data_dimension; ++n){
                                data[n] = field_type_process<typename field_type::underlying_field_type>(read_iter);
                            }

                            return typename field_type::value_type(data);
                        }

                        template<typename GroupType>
                        static inline typename GroupType::value_type
                            group_type_process(typename std::vector<chunk_type>::iterator &read_iter) {

                            typename GroupType::underlying_field_type::value_type X = 
                                field_type_process<typename GroupType::underlying_field_type>(read_iter);

                            typename GroupType::underlying_field_type::value_type Y = 
                                field_type_process<typename GroupType::underlying_field_type>(read_iter);

                            typename GroupType::underlying_field_type::value_type Z = 
                                field_type_process<typename GroupType::underlying_field_type>(read_iter);

                            return typename GroupType::value_type(X, Y, Z);
                        }

                        static inline std::size_t std_size_t_process (
                            std::vector<chunk_type>::iterator &read_iter){

                            std::vector<std::size_t> vector_s(1, 0);
                            auto iter = vector_s.begin();

                            std::size_t vector_c_size = 4;
                            std::vector<chunk_type> vector_c;

                            vector_c.reserve(vector_c_size);
                            vector_c.insert(vector_c.end(), read_iter, read_iter + vector_c_size);

                            auto internal_read_iter = read_iter;
                            nil::crypto3::detail::pack_from<
                                nil::crypto3::stream_endian::big_octet_big_bit, 8, 32>(
                                    vector_c,
                                    iter);

                            read_iter += sizeof(std::size_t);

                            return vector_s[0];
                        }

                        template <typename T>
                        static inline sparse_vector<T> sparse_vector_process (
                            std::vector<chunk_type>::iterator &read_iter){

                            std::size_t indices_count = std_size_t_process (read_iter);

                            std::vector<std::size_t> indices(indices_count, 0);

                            for (std::size_t i = 0; i < indices_count; i++){
                                indices[i] = std_size_t_process (read_iter);
                            }

                            std::size_t values_count = std_size_t_process (read_iter);

                            std::vector<typename T::value_type> values(values_count);

                            for (std::size_t i = 0; i < values_count; i++){
                                values[i] = group_type_process<T> (read_iter);
                            }

                            std::size_t domain_size_ = std_size_t_process(read_iter);

                            sparse_vector<T> sv;

                            sv.indices = indices;
                            sv.values = values;
                            sv.domain_size_ = domain_size_;

                            return sv;
                        }

                        template <typename T>
                        static inline accumulation_vector<T> accumulation_vector_process (
                            std::vector<chunk_type>::iterator &read_iter){

                            typename T::value_type first = group_type_process<T>(read_iter);
                            sparse_vector<T> rest = sparse_vector_process<T>(read_iter);

                            return accumulation_vector<T> (std::move(first), std::move(rest));
                        }

                        static inline typename proof_system::verification_key_type verification_key_process (
                            std::vector<chunk_type>::iterator &read_iter){

                            using verification_key_type = typename proof_system::verification_key_type;

                            typename CurveType::gt_type::value_type alpha_g1_beta_g2 = 
                                field_type_process<typename CurveType::gt_type>(read_iter);
                            typename CurveType::g2_type::value_type gamma_g2 = 
                                group_type_process<typename CurveType::g2_type>(read_iter);
                            typename CurveType::g2_type::value_type delta_g2 = 
                                group_type_process<typename CurveType::g2_type>(read_iter);

                            accumulation_vector<typename CurveType::g1_type> gamma_ABC_g1 = 
                                accumulation_vector_process<typename CurveType::g1_type> (read_iter);

                            //verification_key_type vk = verification_key_type (
                            //    alpha_g1_beta_g2, gamma_g2, delta_g2, gamma_ABC_g1);

                            return verification_key_type (
                                alpha_g1_beta_g2, gamma_g2, delta_g2, gamma_ABC_g1);
                        }

                        static inline typename proof_system::primary_input_type primary_input_process (
                            std::vector<chunk_type>::iterator &read_iter){

                            using primary_input_type = typename proof_system::primary_input_type;

                            std::size_t pi_count = std_size_t_process(read_iter);

                            std::vector<typename CurveType::scalar_field_type::value_type> pi (pi_count);

                            for (std::size_t i = 0; i < pi_count; i++){
                                pi[i] = field_type_process<typename CurveType::scalar_field_type>(read_iter);
                            }

                            //primary_input_type pi_ = primary_input_type(pi);

                            return primary_input_type(pi);
                        }

                        static inline typename proof_system::proof_type proof_process (
                            std::vector<chunk_type>::iterator &read_iter){

                            using proof_type = typename proof_system::proof_type;

                            typename CurveType::g1_type::value_type g_A = 
                                group_type_process<typename CurveType::g1_type>(read_iter);
                            typename CurveType::g2_type::value_type g_B = 
                                group_type_process<typename CurveType::g2_type>(read_iter);
                            typename CurveType::g1_type::value_type g_C = 
                                group_type_process<typename CurveType::g1_type>(read_iter);

                            proof_type pr = proof_type(std::move(g_A), std::move(g_B), std::move(g_C));
                            return pr;
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

                        static inline verifier_data process(const std::vector<chunk_type> &data) {

                            typename std::vector<chunk_type>::const_iterator read_iter = data.begin();

                            typename proof_system::verification_key_type vk = 
                                verification_key_process(read_iter);

                            typename proof_system::primary_input_type pi = 
                                primary_input_process(read_iter);

                            typename proof_system::proof_type pr = 
                                proof_process(read_iter);
                            
                            return verifier_data(vk, pi, pr);
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
                        typename std::enable_if<
                                        !::nil::crypto3::detail::is_extended_field<FieldType>::value,
                                     void>::type field_type_process (
                            typename FieldType::value_type input_fp, 
                            std::vector<chunk_type>::iterator &write_iter){

                            boost::multiprecision::export_bits(modulus_type(input_fp.data), 
                                write_iter, chunk_size, false);
                            write_iter += modulus_chunks;
                        }

                        template<typename FieldType>
                        static inline 
                        typename std::enable_if<
                                        ::nil::crypto3::detail::is_extended_field<FieldType>::value,
                                     void>::type field_type_process (
                            typename FieldType::value_type input_fp, 
                            std::vector<chunk_type>::iterator &write_iter){

                            using field_type = FieldType;

                            const std::size_t data_dimension = field_type::arity / 
                                                   field_type::underlying_field_type::arity;
                            
                            for(int n = 0; n < data_dimension; ++n){
                                field_type_process<typename field_type::underlying_field_type>(
                                    input_fp.data[n], write_iter);

                            }
                        }

                        template<typename GroupType>
                        static inline void group_type_process(typename GroupType::value_type input_g,
                                                              typename std::vector<chunk_type>::iterator &write_iter) {

                            field_type_process<typename GroupType::underlying_field_type>(input_g.X, write_iter);
                            field_type_process<typename GroupType::underlying_field_type>(input_g.Y, write_iter);
                            field_type_process<typename GroupType::underlying_field_type>(input_g.Z, write_iter);
                        }

                        static inline void std_size_t_process (
                            std::size_t input_s,
                            std::vector<chunk_type>::iterator &write_iter){

                            std::vector<std::size_t> vector_s = {input_s};
                            auto iter = vector_s.begin();

                            auto internal_write_iter = write_iter;
                            nil::crypto3::detail::pack_to<
                                nil::crypto3::stream_endian::big_octet_big_bit, 32, 8>(
                                    vector_s,
                                    internal_write_iter);

                            write_iter += sizeof(std::size_t);
                        }

                        template <typename T>
                        static inline void sparse_vector_process (
                            sparse_vector<T> input_sp,
                            std::vector<chunk_type>::iterator &write_iter){

                            std::size_t indices_count = input_sp.size();

                            std_size_t_process(indices_count, write_iter);

                            for (std::size_t i = 0; i < indices_count; i++){
                                std_size_t_process(input_sp.indices[i], write_iter);
                            }

                            std::size_t values_count = input_sp.values.size();

                            std_size_t_process(values_count, write_iter);

                            for (std::size_t i = 0; i < values_count; i++){
                                group_type_process<T>(input_sp.values[i], write_iter);
                            }

                            std_size_t_process(input_sp.domain_size_, write_iter);
                        }

                        template <typename T>
                        static inline void accumulation_vector_process (
                            accumulation_vector<T> input_acc,
                            std::vector<chunk_type>::iterator &write_iter){

                            group_type_process<T>(input_acc.first, write_iter);
                            sparse_vector_process(input_acc.rest, write_iter);
                        }

                        static inline void verification_key_process (
                            typename proof_system::verification_key_type vk,
                            std::vector<chunk_type>::iterator &write_iter){


                            field_type_process<typename CurveType::gt_type>(vk.alpha_g1_beta_g2, write_iter);
                            group_type_process<typename CurveType::g2_type>(vk.gamma_g2, write_iter);
                            group_type_process<typename CurveType::g2_type>(vk.delta_g2, write_iter);

                            accumulation_vector_process(vk.gamma_ABC_g1, write_iter);
                        }

                        static inline void primary_input_process (
                            typename proof_system::primary_input_type pi,
                            std::vector<chunk_type>::iterator &write_iter){

                            std::size_t pi_count = pi.size();

                            std_size_t_process(pi_count, write_iter);

                            for (std::size_t i = 0; i < pi_count; i++){
                                field_type_process<typename CurveType::scalar_field_type>(pi[i], write_iter);
                            }

                        }

                        static inline void proof_process (
                            typename proof_system::proof_type pr,
                            std::vector<chunk_type>::iterator &write_iter){

                            group_type_process<typename CurveType::g1_type>(pr.g_A, write_iter);
                            group_type_process<typename CurveType::g2_type>(pr.g_B, write_iter);
                            group_type_process<typename CurveType::g1_type>(pr.g_C, write_iter);

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

                        static inline std::vector<chunk_type> process (verifier_data vd){

                            constexpr static const std::size_t g1_modulus_chunks_coeff =
                                3 * CurveType::g1_type::underlying_field_type::arity;
                            constexpr static const std::size_t g2_modulus_chunks_coeff =
                                3 * CurveType::g2_type::underlying_field_type::arity;

                            //TODO: count size correctly:
                            std::vector<chunk_type> output (modulus_chunks * 
                                                            (g1_modulus_chunks_coeff + g2_modulus_chunks_coeff) 
                                                            + sizeof(std::size_t));

                            typename std::vector<chunk_type>::iterator write_iter = output.begin();

                            verification_key_process(vd.vk, write_iter);

                            primary_input_process(vd.pi, write_iter);

                            proof_process(vd.pr, write_iter);

                            return output;
                        }

                        static inline std::vector<chunk_type> process (typename proof_system::verification_key_type vk,
                                                                       typename proof_system::primary_input_type pi,
                                                                       typename proof_system::proof_type pr){

                            return process(verifier_data(vk, pi, pr));
                        }

                        static inline std::vector<chunk_type> process (){

                            return process(verifier_data());
                        }
                    };

                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_PSEUDO_MARSHALLING_HPP
