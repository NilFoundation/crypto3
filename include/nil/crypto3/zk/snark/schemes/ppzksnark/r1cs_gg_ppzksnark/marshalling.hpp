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

#ifndef CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_TYPES_HPP
#define CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_TYPES_HPP

#include <vector>
#include <tuple>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/sparse_vector.hpp>
#include <nil/crypto3/zk/snark/accumulation_vector.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>

#include <nil/crypto3/algebra/marshalling.hpp>

#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/stream_endian.hpp>

#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {

        using namespace nil::crypto3::zk::snark;
        using namespace nil::crypto3;

        template<typename ProofSystem>
        struct verifier_data_from_bits;

        template<typename CurveType>
        struct verifier_data_from_bits<nil::crypto3::zk::snark::r1cs_gg_ppzksnark<CurveType>> {

            using scheme_type = nil::crypto3::zk::snark::r1cs_gg_ppzksnark<CurveType>;

            using modulus_type = typename CurveType::base_field_type::modulus_type;

            constexpr static const std::size_t modulus_bits = CurveType::base_field_type::modulus_bits;

            using chunk_type = std::uint8_t;

            constexpr static const std::size_t chunk_size = 8;
            constexpr static const std::size_t modulus_chunks =
                modulus_bits / chunk_size + (modulus_bits % chunk_size ? 1 : 0);

            template<typename FieldType>
            static inline typename std::enable_if<!::nil::crypto3::algebra::is_extended_field<FieldType>::value,
                                                  typename FieldType::value_type>::type
                field_type_process(typename std::vector<chunk_type>::const_iterator &read_iter) {

                using field_type = FieldType;

                modulus_type fp_out;

                nil::crypto3::multiprecision::import_bits(fp_out, read_iter, read_iter + modulus_chunks, chunk_size,
                                                          false);

                read_iter += modulus_chunks;

                return typename field_type::value_type(fp_out);
            }

            template<typename FieldType>
            static inline typename std::enable_if<::nil::crypto3::algebra::is_extended_field<FieldType>::value,
                                                  typename FieldType::value_type>::type
                field_type_process(typename std::vector<chunk_type>::const_iterator &read_iter) {

                using field_type = FieldType;

                typename field_type::value_type::data_type data;
                const std::size_t data_dimension = field_type::arity / field_type::underlying_field_type::arity;

                for (int n = 0; n < data_dimension; ++n) {
                    data[n] = field_type_process<typename field_type::underlying_field_type>(read_iter);
                }

                return typename field_type::value_type(data);
            }

            template<typename GroupType>
            static inline typename GroupType::value_type
                group_type_process(typename std::vector<chunk_type>::const_iterator &read_iter) {

                typename GroupType::underlying_field_type::value_type X =
                    field_type_process<typename GroupType::underlying_field_type>(read_iter);

                typename GroupType::underlying_field_type::value_type Y =
                    field_type_process<typename GroupType::underlying_field_type>(read_iter);

                typename GroupType::underlying_field_type::value_type Z =
                    field_type_process<typename GroupType::underlying_field_type>(read_iter);

                return typename GroupType::value_type(X, Y, Z);
            }

            static inline std::size_t std_size_t_process(typename std::vector<chunk_type>::const_iterator &read_iter) {

                std::size_t std_size_t_byteblob_size = 4;
                std::vector<std::size_t> vector_s(1, 0);
                auto iter = vector_s.begin();

                std::size_t vector_c_size = 4;
                std::vector<chunk_type> vector_c;

                vector_c.reserve(vector_c_size);
                vector_c.insert(vector_c.end(), read_iter, read_iter + vector_c_size);

                nil::crypto3::detail::pack_from<nil::crypto3::stream_endian::big_octet_big_bit, 8, 32>(vector_c, iter);

                read_iter += std_size_t_byteblob_size;

                return vector_s[0];
            }

            template<typename T>
            static inline sparse_vector<T>
                sparse_vector_process(typename std::vector<chunk_type>::const_iterator &read_iter) {

                std::size_t indices_count = std_size_t_process(read_iter);

                std::vector<std::size_t> indices(indices_count, 0);

                for (std::size_t i = 0; i < indices_count; i++) {
                    indices[i] = std_size_t_process(read_iter);
                }

                std::size_t values_count = std_size_t_process(read_iter);

                std::vector<typename T::value_type> values(values_count);

                for (std::size_t i = 0; i < values_count; i++) {
                    values[i] = group_type_process<T>(read_iter);
                }

                std::size_t domain_size_ = std_size_t_process(read_iter);

                sparse_vector<T> sv;

                sv.indices = indices;
                sv.values = values;
                sv.domain_size_ = domain_size_;

                return sv;
            }

            template<typename T>
            static inline accumulation_vector<T>
                accumulation_vector_process(typename std::vector<chunk_type>::const_iterator &read_iter) {

                typename T::value_type first = group_type_process<T>(read_iter);
                sparse_vector<T> rest = sparse_vector_process<T>(read_iter);

                return accumulation_vector<T>(std::move(first), std::move(rest));
            }

            static inline typename scheme_type::verification_key_type
                verification_key_process(typename std::vector<chunk_type>::const_iterator &read_iter) {

                using verification_key_type = typename scheme_type::verification_key_type;

                typename CurveType::gt_type::value_type alpha_g1_beta_g2 =
                    field_type_process<typename CurveType::gt_type>(read_iter);
                typename CurveType::g2_type::value_type gamma_g2 =
                    group_type_process<typename CurveType::g2_type>(read_iter);
                typename CurveType::g2_type::value_type delta_g2 =
                    group_type_process<typename CurveType::g2_type>(read_iter);

                accumulation_vector<typename CurveType::g1_type> gamma_ABC_g1 =
                    accumulation_vector_process<typename CurveType::g1_type>(read_iter);

                // verification_key_type vk = verification_key_type (
                //    alpha_g1_beta_g2, gamma_g2, delta_g2, gamma_ABC_g1);

                return verification_key_type(alpha_g1_beta_g2, gamma_g2, delta_g2, gamma_ABC_g1);
            }

            static inline typename scheme_type::primary_input_type
                primary_input_process(typename std::vector<chunk_type>::const_iterator &read_iter) {

                using primary_input_type = typename scheme_type::primary_input_type;

                std::size_t pi_count = std_size_t_process(read_iter);

                std::vector<typename CurveType::scalar_field_type::value_type> pi(pi_count);

                for (std::size_t i = 0; i < pi_count; i++) {
                    pi[i] = field_type_process<typename CurveType::scalar_field_type>(read_iter);
                }

                return primary_input_type(pi);
            }

            static inline typename scheme_type::proof_type
                proof_process(typename std::vector<chunk_type>::const_iterator &read_iter) {

                using proof_type = typename scheme_type::proof_type;

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
                typename scheme_type::verification_key_type vk;
                typename scheme_type::primary_input_type pi;
                typename scheme_type::proof_type pr;

                verifier_data() {};

                verifier_data(typename scheme_type::verification_key_type vk,
                              typename scheme_type::primary_input_type pi,
                              typename scheme_type::proof_type pr) :
                    vk(vk),
                    pi(pi), pr(pr) {};
            };

            template<typename DataType>
            static inline verifier_data process(const DataType &data) {
                return verifier_data();
            }

            static inline verifier_data process(const std::vector<chunk_type> &data) {

                typename std::vector<chunk_type>::const_iterator read_iter = data.begin();

                typename scheme_type::verification_key_type vk = verification_key_process(read_iter);

                typename scheme_type::primary_input_type pi = primary_input_process(read_iter);

                typename scheme_type::proof_type pr = proof_process(read_iter);

                return verifier_data(vk, pi, pr);
            }
        };

        template<typename ProofSystem>
        struct verifier_data_to_bits;

        // TODO: reimplement private functions using field value type trait
        template<typename CurveType>
        struct verifier_data_to_bits<nil::crypto3::zk::snark::r1cs_gg_ppzksnark<CurveType>> {

            using scheme_type = nil::crypto3::zk::snark::r1cs_gg_ppzksnark<CurveType>;

            constexpr static const std::size_t modulus_bits = CurveType::base_field_type::modulus_bits;

            using chunk_type = std::uint8_t;

            constexpr static const std::size_t chunk_size = 8;
            constexpr static const std::size_t modulus_chunks =
                modulus_bits / chunk_size + (modulus_bits % chunk_size ? 1 : 0);

            template<typename FieldType>

            static inline
                typename std::enable_if<!::nil::crypto3::algebra::is_extended_field<FieldType>::value, void>::type
                field_type_process(typename FieldType::value_type input_fp,
                                   typename std::vector<chunk_type>::iterator &write_iter) {

                typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::backends::cpp_int_backend<>>
                    modulus_type;

                nil::crypto3::multiprecision::export_bits(modulus_type(input_fp.data), write_iter, chunk_size, false);
                write_iter += modulus_chunks;
            }

            template<typename FieldType>
            static inline
                typename std::enable_if<::nil::crypto3::algebra::is_extended_field<FieldType>::value, void>::type
                field_type_process(typename FieldType::value_type input_fp,
                                   typename std::vector<chunk_type>::iterator &write_iter) {

                using field_type = FieldType;

                const std::size_t data_dimension = field_type::arity / field_type::underlying_field_type::arity;

                for (int n = 0; n < data_dimension; ++n) {
                    field_type_process<typename field_type::underlying_field_type>(input_fp.data[n], write_iter);
                }
            }

            template<typename GroupType>
            static inline void group_type_process(typename GroupType::value_type input_g,
                                                  typename std::vector<chunk_type>::iterator &write_iter) {

                field_type_process<typename GroupType::underlying_field_type>(input_g.X, write_iter);
                field_type_process<typename GroupType::underlying_field_type>(input_g.Y, write_iter);
                field_type_process<typename GroupType::underlying_field_type>(input_g.Z, write_iter);
            }

            static inline void std_size_t_process(std::size_t input_s, std::vector<chunk_type>::iterator &write_iter) {

                std::size_t std_size_t_byteblob_size = 4;

                std::vector<std::size_t> vector_s = {input_s};

                auto internal_write_iter = write_iter;
                nil::crypto3::detail::pack_to<nil::crypto3::stream_endian::big_octet_big_bit, 32, 8>(
                    vector_s, internal_write_iter);

                write_iter += std_size_t_byteblob_size;
            }

            template<typename T>
            static inline void sparse_vector_process(sparse_vector<T> input_sp,
                                                     typename std::vector<chunk_type>::iterator &write_iter) {

                std::size_t indices_count = input_sp.size();

                std_size_t_process(indices_count, write_iter);

                for (std::size_t i = 0; i < indices_count; i++) {
                    std_size_t_process(input_sp.indices[i], write_iter);
                }

                std::size_t values_count = input_sp.values.size();

                std_size_t_process(values_count, write_iter);

                for (std::size_t i = 0; i < values_count; i++) {
                    group_type_process<T>(input_sp.values[i], write_iter);
                }

                std_size_t_process(input_sp.domain_size_, write_iter);
            }

            template<typename T>
            static inline void accumulation_vector_process(accumulation_vector<T> input_acc,
                                                           typename std::vector<chunk_type>::iterator &write_iter) {

                group_type_process<T>(input_acc.first, write_iter);
                sparse_vector_process(input_acc.rest, write_iter);
            }

            static inline void verification_key_process(typename scheme_type::verification_key_type vk,
                                                        typename std::vector<chunk_type>::iterator &write_iter) {

                field_type_process<typename CurveType::gt_type>(vk.alpha_g1_beta_g2, write_iter);
                group_type_process<typename CurveType::g2_type>(vk.gamma_g2, write_iter);
                group_type_process<typename CurveType::g2_type>(vk.delta_g2, write_iter);

                accumulation_vector_process(vk.gamma_ABC_g1, write_iter);
            }

            static inline void primary_input_process(typename scheme_type::primary_input_type pi,
                                                     typename std::vector<chunk_type>::iterator &write_iter) {

                std::size_t pi_count = pi.size();

                std_size_t_process(pi_count, write_iter);

                for (std::size_t i = 0; i < pi_count; i++) {
                    field_type_process<typename CurveType::scalar_field_type>(pi[i], write_iter);
                }
            }

            static inline void proof_process(typename scheme_type::proof_type pr,
                                             typename std::vector<chunk_type>::iterator &write_iter) {

                group_type_process<typename CurveType::g1_type>(pr.g_A, write_iter);
                group_type_process<typename CurveType::g2_type>(pr.g_B, write_iter);
                group_type_process<typename CurveType::g1_type>(pr.g_C, write_iter);
            }

        public:
            struct verifier_data {
                typename scheme_type::verification_key_type vk;
                typename scheme_type::primary_input_type pi;
                typename scheme_type::proof_type pr;

                verifier_data() {};

                verifier_data(typename scheme_type::verification_key_type vk,
                              typename scheme_type::primary_input_type pi,
                              typename scheme_type::proof_type pr) :
                    vk(vk),
                    pi(pi), pr(pr) {};
            };

            static inline std::vector<chunk_type> process(verifier_data vd) {

                std::size_t g1_size = modulus_chunks * 3 * CurveType::g1_type::underlying_field_type::arity;
                std::size_t g2_size = modulus_chunks * 3 * CurveType::g2_type::underlying_field_type::arity;
                std::size_t std_size_t_byteblob_size = 4;

                std::size_t gt_size = modulus_chunks * CurveType::gt_type::arity;

                std::size_t sparse_vector_size =
                    std_size_t_byteblob_size + vd.vk.gamma_ABC_g1.rest.size() * std_size_t_byteblob_size +
                    std_size_t_byteblob_size + vd.vk.gamma_ABC_g1.rest.values.size() * g1_size +
                    std_size_t_byteblob_size;

                std::size_t verification_key_size = gt_size + g2_size + g2_size + g1_size + sparse_vector_size;
                std::size_t primary_input_size = std_size_t_byteblob_size + vd.pi.size() * modulus_chunks;
                std::size_t proof_size = g1_size + g2_size + g1_size;

                std::vector<chunk_type> output(verification_key_size + primary_input_size + proof_size);

                typename std::vector<chunk_type>::iterator write_iter = output.begin();

                verification_key_process(vd.vk, write_iter);

                primary_input_process(vd.pi, write_iter);

                proof_process(vd.pr, write_iter);

                return output;
            }

            static inline std::vector<chunk_type> process(typename scheme_type::verification_key_type vk,
                                                          typename scheme_type::primary_input_type pi,
                                                          typename scheme_type::proof_type pr) {

                return process(verifier_data(vk, pi, pr));
            }

            static inline std::vector<chunk_type> process() {

                return process(verifier_data());
            }
        };

        /************************ TON Virtual Machine compatible serialization *************************/

        template<typename ProofSystem>
        struct verifier_input_deserializer_tvm;

        template<>
        struct verifier_input_deserializer_tvm<
            nil::crypto3::zk::snark::r1cs_gg_ppzksnark<algebra::curves::bls12<381>>> {

            using CurveType = typename algebra::curves::bls12<381>;
            using scheme_type = nil::crypto3::zk::snark::r1cs_gg_ppzksnark<CurveType>;

            using chunk_type = std::uint8_t;
            constexpr static const std::size_t chunk_size = 8;

            static const std::size_t std_size_t_byteblob_size = 4;
            static const std::size_t g1_byteblob_size = curve_element_serializer<CurveType>::sizeof_field_element;
            static const std::size_t g2_byteblob_size = 2 * curve_element_serializer<CurveType>::sizeof_field_element;
            static const std::size_t fp_byteblob_size = CurveType::base_field_type::modulus_bits / chunk_size +
                                                        (CurveType::base_field_type::modulus_bits % chunk_size ? 1 : 0);
            static const std::size_t gt_byteblob_size = 2 * 3 * 2 * fp_byteblob_size;
            static const std::size_t fr_byteblob_size =
                CurveType::scalar_field_type::modulus_bits / chunk_size +
                (CurveType::scalar_field_type::modulus_bits % chunk_size ? 1 : 0);

            template<typename FieldType>
            static inline typename std::enable_if<!::nil::crypto3::algebra::is_extended_field<FieldType>::value,
                                                  typename FieldType::value_type>::type
                field_type_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                   typename std::vector<chunk_type>::const_iterator read_iter_end,
                                   status_type &processingStatus) {

                processingStatus = status_type::success;

                using modulus_type = typename FieldType::modulus_type;
                using field_type = FieldType;
                /*constexpr const std::size_t modulus_bits = FieldType::modulus_bits;
                constexpr const std::size_t modulus_chunks = modulus_bits / chunk_size + (modulus_bits % chunk_size ? 1
                : 0);

                if (std::distance(read_iter_begin, read_iter_end) < modulus_chunks){
                    processingStatus = status_type::not_enough_data;

                    return field_type::value_type::zero();
                }

                modulus_type fp_out;

                nil::crypto3::multiprecision::import_bits(fp_out, read_iter_begin, read_iter_begin + modulus_chunks,
                                                          chunk_size, false);*/

                std::pair<bool, typename field_type::value_type> processed =
                    field_bincode<field_type>::field_element_from_bytes(read_iter_begin, read_iter_end);

                if (!std::get<0>(processed)) {
                    processingStatus = status_type::invalid_msg_data;

                    return field_type::value_type::zero();
                }

                return std::get<1>(processed);
            }

            template<typename FieldType>
            static inline typename std::enable_if<::nil::crypto3::algebra::is_extended_field<FieldType>::value,
                                                  typename FieldType::value_type>::type
                field_type_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                   typename std::vector<chunk_type>::const_iterator read_iter_end,
                                   status_type &processingStatus) {

                using modulus_type = typename FieldType::modulus_type;
                using field_type = FieldType;
                // constexpr const std::size_t modulus_bits = FieldType::modulus_bits;
                // constexpr const std::size_t modulus_chunks = modulus_bits / chunk_size + (modulus_bits % chunk_size ?
                // 1 : 0);

                // if (std::distance(read_iter_begin, read_iter_end) <
                //     field_type::arity * modulus_chunks){

                //     processingStatus = status_type::not_enough_data;

                //     return field_type::value_type::zero();
                // }

                // typename field_type::value_type::data_type data;
                // const std::size_t data_dimension =
                //     field_type::arity / field_type::underlying_field_type::arity;

                // for (int n = 0; n < data_dimension; ++n) {
                //     data[n] = field_type_process<typename field_type::underlying_field_type>(read_iter_begin + n *
                //     field_type::underlying_field_type::arity * modulus_chunks,
                //                                                                              read_iter_begin + (n +
                //                                                                              1) *
                //                                                                              field_type::underlying_field_type::arity
                //                                                                              * modulus_chunks,
                //                                                                              processingStatus);
                //     if (processingStatus != status_type::success){
                //         return field_type::value_type::zero();
                //     }
                // }

                // return typename field_type::value_type(data);

                std::pair<bool, typename field_type::value_type> processed =
                    field_bincode<field_type>::field_element_from_bytes(read_iter_begin, read_iter_end);

                if (!std::get<0>(processed)) {
                    processingStatus = status_type::invalid_msg_data;

                    return field_type::value_type::zero();
                }

                return std::get<1>(processed);
            }

            template<typename GroupType>
            static inline typename GroupType::value_type
                g1_group_type_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                      typename std::vector<chunk_type>::const_iterator read_iter_end,
                                      status_type &processingStatus) {

                processingStatus = status_type::success;

                typename curve_element_serializer<CurveType>::compressed_g1_octets input_array;

                for (std::size_t i = 0; i < g1_byteblob_size; ++i) {
                    input_array[i] = read_iter_begin[i];
                }

                return curve_element_serializer<CurveType>::octets_to_g1_point(input_array);
            }

            template<typename GroupType>
            static inline typename GroupType::value_type
                g2_group_type_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                      typename std::vector<chunk_type>::const_iterator read_iter_end,
                                      status_type &processingStatus) {

                processingStatus = status_type::success;

                typename curve_element_serializer<CurveType>::compressed_g2_octets input_array;

                for (std::size_t i = 0; i < g2_byteblob_size; ++i) {
                    input_array[i] = read_iter_begin[i];
                }

                return curve_element_serializer<CurveType>::octets_to_g2_point(input_array);
            }

            static inline std::size_t
                std_size_t_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                   typename std::vector<chunk_type>::const_iterator read_iter_end,
                                   status_type &processingStatus) {

                processingStatus = status_type::success;

                if (std::distance(read_iter_begin, read_iter_end) < std_size_t_byteblob_size) {

                    processingStatus = status_type::not_enough_data;

                    return 0;
                }

                std::vector<std::size_t> vector_s(1, 0);
                auto iter = vector_s.begin();

                std::size_t vector_c_size = std_size_t_byteblob_size;
                std::vector<chunk_type> vector_c;

                vector_c.reserve(vector_c_size);
                vector_c.insert(vector_c.end(), read_iter_begin, read_iter_begin + vector_c_size);

                nil::crypto3::detail::pack_from<nil::crypto3::stream_endian::big_octet_big_bit, 8, 32>(vector_c, iter);

                return vector_s[0];
            }

            template<typename T>
            static inline sparse_vector<T>
                g1_sparse_vector_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                         typename std::vector<chunk_type>::const_iterator read_iter_end,
                                         status_type &processingStatus) {

                if (std::distance(read_iter_begin, read_iter_end) < std_size_t_byteblob_size) {

                    processingStatus = status_type::not_enough_data;

                    return sparse_vector<T>();
                }

                std::size_t indices_count =
                    std_size_t_process(read_iter_begin, read_iter_begin + std_size_t_byteblob_size, processingStatus);

                if (processingStatus != status_type::success) {
                    return sparse_vector<T>();
                }

                if (std::distance(read_iter_begin, read_iter_end) <
                    std_size_t_byteblob_size + indices_count * std_size_t_byteblob_size +
                        indices_count * g1_byteblob_size + std_size_t_byteblob_size) {

                    processingStatus = status_type::not_enough_data;

                    return sparse_vector<T>();
                }

                std::vector<std::size_t> indices(indices_count, 0);

                for (std::size_t i = 0; i < indices_count; i++) {
                    indices[i] = std_size_t_process(
                        read_iter_begin + std_size_t_byteblob_size + std_size_t_byteblob_size * i,
                        read_iter_begin + std_size_t_byteblob_size + (i + 1) * std_size_t_byteblob_size,
                        processingStatus);
                    if (processingStatus != status_type::success) {
                        return sparse_vector<T>();
                    }
                }

                std::vector<typename T::value_type> values(indices_count);

                for (std::size_t i = 0; i < indices_count; i++) {
                    values[i] = g1_group_type_process<T>(
                        read_iter_begin + std_size_t_byteblob_size + indices_count * std_size_t_byteblob_size +
                            i * g1_byteblob_size,
                        read_iter_begin + std_size_t_byteblob_size + indices_count * std_size_t_byteblob_size +
                            (i + 1) * g1_byteblob_size,
                        processingStatus);
                    if (processingStatus != status_type::success) {
                        return sparse_vector<T>();
                    }
                }

                std::size_t domain_size_ = std_size_t_process(
                    read_iter_begin + std_size_t_byteblob_size + indices_count * std_size_t_byteblob_size +
                        indices_count * g1_byteblob_size,
                    read_iter_begin + std_size_t_byteblob_size + indices_count * std_size_t_byteblob_size +
                        indices_count * g1_byteblob_size + std_size_t_byteblob_size,
                    processingStatus);
                if (processingStatus != status_type::success) {
                    return sparse_vector<T>();
                }

                sparse_vector<T> sv;

                sv.indices = indices;
                sv.values = values;
                sv.domain_size_ = domain_size_;

                // assert (sv.is_valid());
                assert(sv.values.size() == sv.indices.size());

                return sv;
            }

            template<typename T>
            static inline accumulation_vector<T>
                g1_accumulation_vector_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                               typename std::vector<chunk_type>::const_iterator read_iter_end,
                                               status_type &processingStatus) {

                if (std::distance(read_iter_begin, read_iter_end) < g1_byteblob_size) {

                    processingStatus = status_type::not_enough_data;

                    return accumulation_vector<T>();
                }

                typename T::value_type first =
                    g1_group_type_process<T>(read_iter_begin, read_iter_begin + g1_byteblob_size, processingStatus);

                if (processingStatus != status_type::success) {
                    return accumulation_vector<T>();
                }

                sparse_vector<T> rest =
                    g1_sparse_vector_process<T>(read_iter_begin + g1_byteblob_size, read_iter_end, processingStatus);

                if (processingStatus != status_type::success) {
                    return accumulation_vector<T>();
                }

                return accumulation_vector<T>(std::move(first), std::move(rest));
            }

            static inline typename scheme_type::verification_key_type
                verification_key_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                         typename std::vector<chunk_type>::const_iterator read_iter_end,
                                         status_type &processingStatus) {

                if (std::distance(read_iter_begin, read_iter_end) <
                    gt_byteblob_size + g2_byteblob_size + g2_byteblob_size) {

                    processingStatus = status_type::not_enough_data;

                    return typename scheme_type::verification_key_type();
                }

                typename CurveType::gt_type::value_type alpha_g1_beta_g2 =
                    field_type_process<typename CurveType::gt_type>(
                        read_iter_begin, read_iter_begin + gt_byteblob_size, processingStatus);

                if (processingStatus != status_type::success) {
                    return typename scheme_type::verification_key_type();
                }

                typename CurveType::g2_type::value_type gamma_g2 = g2_group_type_process<typename CurveType::g2_type>(
                    read_iter_begin + gt_byteblob_size,
                    read_iter_begin + gt_byteblob_size + g2_byteblob_size,
                    processingStatus);
                if (processingStatus != status_type::success) {
                    return typename scheme_type::verification_key_type();
                }

                typename CurveType::g2_type::value_type delta_g2 = g2_group_type_process<typename CurveType::g2_type>(
                    read_iter_begin + gt_byteblob_size + g2_byteblob_size,
                    read_iter_begin + gt_byteblob_size + g2_byteblob_size + g2_byteblob_size,
                    processingStatus);
                if (processingStatus != status_type::success) {
                    return typename scheme_type::verification_key_type();
                }

                accumulation_vector<typename CurveType::g1_type> gamma_ABC_g1 =
                    g1_accumulation_vector_process<typename CurveType::g1_type>(read_iter_begin + gt_byteblob_size +
                                                                                    g2_byteblob_size + g2_byteblob_size,
                                                                                read_iter_end,
                                                                                processingStatus);

                if (processingStatus != status_type::success) {
                    return typename scheme_type::verification_key_type();
                }

                return typename scheme_type::verification_key_type(alpha_g1_beta_g2, gamma_g2, delta_g2, gamma_ABC_g1);
            }

            static inline typename scheme_type::primary_input_type
                primary_input_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                      typename std::vector<chunk_type>::const_iterator read_iter_end,
                                      status_type &processingStatus) {

                if (std::distance(read_iter_begin, read_iter_end) < std_size_t_byteblob_size) {

                    processingStatus = status_type::not_enough_data;

                    return typename scheme_type::primary_input_type();
                }

                std::size_t pi_count =
                    std_size_t_process(read_iter_begin, read_iter_begin + std_size_t_byteblob_size, processingStatus);

                if (processingStatus != status_type::success) {
                    return typename scheme_type::primary_input_type();
                }

                if (std::distance(read_iter_begin, read_iter_end) <
                    std_size_t_byteblob_size + pi_count * fr_byteblob_size) {

                    processingStatus = status_type::not_enough_data;

                    return typename scheme_type::primary_input_type();
                }

                std::vector<typename CurveType::scalar_field_type::value_type> pi(pi_count);

                for (std::size_t i = 0; i < pi_count; i++) {
                    pi[i] = field_type_process<typename CurveType::scalar_field_type>(
                        read_iter_begin + std_size_t_byteblob_size + i * fr_byteblob_size,
                        read_iter_begin + std_size_t_byteblob_size + (i + 1) * fr_byteblob_size,
                        processingStatus);

                    if (processingStatus != status_type::success) {
                        return typename scheme_type::primary_input_type();
                    }
                }

                return typename scheme_type::primary_input_type(pi);
            }

            static inline typename scheme_type::proof_type
                proof_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                              typename std::vector<chunk_type>::const_iterator read_iter_end,
                              status_type &processingStatus) {

                if (std::distance(read_iter_begin, read_iter_end) <
                    g1_byteblob_size + g2_byteblob_size + g1_byteblob_size) {

                    processingStatus = status_type::not_enough_data;

                    return typename scheme_type::proof_type();
                }

                typename CurveType::g1_type::value_type g_A = g1_group_type_process<typename CurveType::g1_type>(
                    read_iter_begin, read_iter_begin + g1_byteblob_size, processingStatus);

                if (processingStatus != status_type::success) {
                    return typename scheme_type::proof_type();
                }

                typename CurveType::g2_type::value_type g_B = g2_group_type_process<typename CurveType::g2_type>(
                    read_iter_begin + g1_byteblob_size,
                    read_iter_begin + g1_byteblob_size + g2_byteblob_size,
                    processingStatus);

                if (processingStatus != status_type::success) {
                    return typename scheme_type::proof_type();
                }

                typename CurveType::g1_type::value_type g_C = g1_group_type_process<typename CurveType::g1_type>(
                    read_iter_begin + g1_byteblob_size + g2_byteblob_size,
                    read_iter_begin + g1_byteblob_size + g2_byteblob_size + g1_byteblob_size,
                    processingStatus);

                if (processingStatus != status_type::success) {
                    return typename scheme_type::proof_type();
                }

                return typename scheme_type::proof_type(std::move(g_A), std::move(g_B), std::move(g_C));
            }

            static inline std::tuple<typename scheme_type::verification_key_type,
                                     typename scheme_type::primary_input_type, typename scheme_type::proof_type>
                verifier_input_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                       typename std::vector<chunk_type>::const_iterator read_iter_end,
                                       status_type &processingStatus) {

                const std::size_t proof_byteblob_size = g1_byteblob_size + g2_byteblob_size + g1_byteblob_size;

                if (std::distance(read_iter_begin, read_iter_end) < proof_byteblob_size) {

                    processingStatus = status_type::not_enough_data;

                    return std::make_tuple(typename scheme_type::verification_key_type(),
                                           typename scheme_type::primary_input_type(),
                                           typename scheme_type::proof_type());
                }

                typename scheme_type::proof_type de_prf =
                    proof_process(read_iter_begin, read_iter_begin + proof_byteblob_size, processingStatus);

                if (processingStatus != status_type::success) {
                    return std::make_tuple(typename scheme_type::verification_key_type(),
                                           typename scheme_type::primary_input_type(),
                                           typename scheme_type::proof_type());
                }

                const std::size_t primary_input_byteblob_size =
                    std_size_t_byteblob_size +
                    fr_byteblob_size *
                        std_size_t_process(read_iter_begin + proof_byteblob_size,
                                           read_iter_begin + proof_byteblob_size + std_size_t_byteblob_size,
                                           processingStatus);

                if (processingStatus != status_type::success) {
                    return std::make_tuple(typename scheme_type::verification_key_type(),
                                           typename scheme_type::primary_input_type(),
                                           typename scheme_type::proof_type());
                }

                typename scheme_type::primary_input_type de_pi =
                    primary_input_process(read_iter_begin + proof_byteblob_size,
                                          read_iter_begin + proof_byteblob_size + primary_input_byteblob_size,
                                          processingStatus);

                if (processingStatus != status_type::success) {
                    return std::make_tuple(typename scheme_type::verification_key_type(),
                                           typename scheme_type::primary_input_type(),
                                           typename scheme_type::proof_type());
                }

                typename scheme_type::verification_key_type de_vk =
                    verification_key_process(read_iter_begin + proof_byteblob_size + primary_input_byteblob_size,
                                             read_iter_end,
                                             processingStatus);

                if (processingStatus != status_type::success) {
                    return std::make_tuple(typename scheme_type::verification_key_type(),
                                           typename scheme_type::primary_input_type(),
                                           typename scheme_type::proof_type());
                }

                return std::make_tuple(de_vk, de_pi, de_prf);
            }
        };

        template<typename ProofSystem>
        struct verifier_input_serializer_tvm;

        template<>
        struct verifier_input_serializer_tvm<nil::crypto3::zk::snark::r1cs_gg_ppzksnark<algebra::curves::bls12<381>>> {

            using CurveType = typename algebra::curves::bls12<381>;
            using scheme_type = nil::crypto3::zk::snark::r1cs_gg_ppzksnark<CurveType>;

            using chunk_type = std::uint8_t;

            constexpr static const std::size_t chunk_size = 8;

            template<typename FieldType>

            static inline
                typename std::enable_if<!::nil::crypto3::algebra::is_extended_field<FieldType>::value, void>::type
                field_type_process(typename FieldType::value_type input_fp,
                                   typename std::vector<chunk_type>::iterator &write_iter) {

                typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::backends::cpp_int_backend<>>
                    modulus_type;

                constexpr const std::size_t modulus_bits = FieldType::modulus_bits;

                constexpr const std::size_t modulus_chunks =
                    modulus_bits / chunk_size + (modulus_bits % chunk_size ? 1 : 0);

                nil::crypto3::multiprecision::export_bits(modulus_type(input_fp.data), write_iter, chunk_size, false);
                write_iter += modulus_chunks;
            }

            template<typename FieldType>
            static inline
                typename std::enable_if<::nil::crypto3::algebra::is_extended_field<FieldType>::value, void>::type
                field_type_process(typename FieldType::value_type input_fp,
                                   typename std::vector<chunk_type>::iterator &write_iter) {

                using field_type = FieldType;

                const std::size_t data_dimension = field_type::arity / field_type::underlying_field_type::arity;

                for (int n = 0; n < data_dimension; ++n) {
                    field_type_process<typename field_type::underlying_field_type>(input_fp.data[n], write_iter);
                }
            }

            template<typename GroupType>
            static inline void g1_group_type_process(typename GroupType::value_type input_g,
                                                     typename std::vector<chunk_type>::iterator &write_iter) {

                auto compressed_curve_group_element =
                    curve_element_serializer<CurveType>::point_to_octets_compress(input_g);

                copy(compressed_curve_group_element.begin(), compressed_curve_group_element.end(), write_iter);

                write_iter += compressed_curve_group_element.size();
            }

            template<typename GroupType>
            static inline void g2_group_type_process(typename GroupType::value_type input_g,
                                                     typename std::vector<chunk_type>::iterator &write_iter) {

                auto compressed_curve_group_element =
                    curve_element_serializer<CurveType>::point_to_octets_compress(input_g);

                copy(compressed_curve_group_element.begin(), compressed_curve_group_element.end(), write_iter);

                write_iter += compressed_curve_group_element.size();
            }

            static inline void std_size_t_process(std::size_t input_s, std::vector<chunk_type>::iterator &write_iter) {

                std::size_t std_size_t_byteblob_size = 4;
                std::vector<std::size_t> vector_s = {input_s};

                auto internal_write_iter = write_iter;
                nil::crypto3::detail::pack_to<nil::crypto3::stream_endian::big_octet_big_bit, 32, 8>(
                    vector_s, internal_write_iter);

                write_iter += std_size_t_byteblob_size;
            }

            template<typename T>
            static inline void g1_sparse_vector_process(sparse_vector<T> input_sv,
                                                        std::vector<chunk_type>::iterator &write_iter) {

                std::size_t ic_size = input_sv.values.size();
                // assert (input_sv.is_valid());
                assert(input_sv.values.size() == input_sv.indices.size());
                // Actual sparse_vector byteblob size is equal to
                //     (2 + ic_size) * std_size_t_byteblob_size + ic_size * g1_byteblob_size;
                // For accumulation vector it is
                // g1_byteblob_size more because of accumulation_vector.first

                std_size_t_process(ic_size, write_iter);

                for (auto ic_iter = input_sv.indices.begin(); ic_iter != input_sv.indices.end(); ic_iter++) {
                    std_size_t_process(*ic_iter, write_iter);
                }

                for (auto ic_iter = input_sv.values.begin(); ic_iter != input_sv.values.end(); ic_iter++) {
                    g1_group_type_process<typename CurveType::g1_type>(*ic_iter, write_iter);
                }

                std_size_t_process(input_sv.domain_size(), write_iter);
            }

            template<typename T>
            static inline void g1_accumulation_vector_process(accumulation_vector<T> input_av,
                                                              std::vector<chunk_type>::iterator &write_iter) {

                g1_group_type_process<typename CurveType::g1_type>(input_av.first, write_iter);

                g1_sparse_vector_process(input_av.rest, write_iter);
            }

            static inline std::vector<chunk_type> process(typename scheme_type::verification_key_type vk) {

                constexpr const std::size_t modulus_bits = CurveType::base_field_type::modulus_bits;

                constexpr const std::size_t modulus_chunks =
                    modulus_bits / chunk_size + (modulus_bits % chunk_size ? 1 : 0);

                std::size_t ic_size = 1 + vk.gamma_ABC_g1.rest.values.size();

                std::size_t g1_byteblob_size = curve_element_serializer<CurveType>::sizeof_field_element;
                std::size_t g2_byteblob_size = 2 * curve_element_serializer<CurveType>::sizeof_field_element;
                std::size_t std_size_t_byteblob_size = 4;

                std::size_t gt_byteblob_size = modulus_chunks * CurveType::gt_type::arity;

                std::size_t ic_byteblob_size = std_size_t_byteblob_size + ic_size * g1_byteblob_size;
                std::size_t sparse_vector_byteblob_size =
                    (2 + ic_size) * std_size_t_byteblob_size + ic_size * g1_byteblob_size;
                std::size_t accumulation_vector_byteblob_size = sparse_vector_byteblob_size + g1_byteblob_size;

                std::size_t verification_key_size =
                    gt_byteblob_size + g2_byteblob_size + g2_byteblob_size + accumulation_vector_byteblob_size;

                std::vector<chunk_type> output(verification_key_size);

                typename std::vector<chunk_type>::iterator write_iter = output.begin();

                field_type_process<typename CurveType::gt_type>(vk.alpha_g1_beta_g2, write_iter);
                g2_group_type_process<typename CurveType::g2_type>(vk.gamma_g2, write_iter);
                g2_group_type_process<typename CurveType::g2_type>(vk.delta_g2, write_iter);

                // std_size_t_process(ic_size, write_iter);

                // g1_group_type_process<typename CurveType::g1_type>(vk.gamma_ABC_g1.first, write_iter);

                // for (auto ic_iter = vk.gamma_ABC_g1.rest.values.begin(); ic_iter !=
                // vk.gamma_ABC_g1.rest.values.end(); ic_iter++) {
                //     g1_group_type_process<typename CurveType::g1_type>(*ic_iter, write_iter);
                // }

                g1_accumulation_vector_process(vk.gamma_ABC_g1, write_iter);

                return output;
            }

            static inline std::vector<chunk_type> process(typename scheme_type::primary_input_type pi) {

                constexpr const std::size_t modulus_bits = CurveType::scalar_field_type::modulus_bits;

                constexpr const std::size_t modulus_chunks =
                    modulus_bits / chunk_size + (modulus_bits % chunk_size ? 1 : 0);

                std::size_t std_size_t_byteblob_size = 4;

                std::size_t pi_count = pi.size();

                std::size_t primary_byteblob_input_size = std_size_t_byteblob_size + pi_count * modulus_chunks;

                std::vector<chunk_type> output(primary_byteblob_input_size);

                typename std::vector<chunk_type>::iterator write_iter = output.begin();

                std_size_t_process(pi_count, write_iter);

                for (std::size_t i = 0; i < pi_count; i++) {
                    field_type_process<typename CurveType::scalar_field_type>(pi[i], write_iter);
                }

                return output;
            }

            static inline std::vector<chunk_type> process(typename scheme_type::proof_type pr) {

                std::size_t g1_byteblob_size = curve_element_serializer<CurveType>::sizeof_field_element;
                std::size_t g2_byteblob_size = 2 * curve_element_serializer<CurveType>::sizeof_field_element;

                std::size_t proof_size = g1_byteblob_size + g2_byteblob_size + g1_byteblob_size;

                std::vector<chunk_type> output(proof_size);

                typename std::vector<chunk_type>::iterator write_iter = output.begin();

                g1_group_type_process<typename CurveType::g1_type>(pr.g_A, write_iter);
                g2_group_type_process<typename CurveType::g2_type>(pr.g_B, write_iter);
                g1_group_type_process<typename CurveType::g1_type>(pr.g_C, write_iter);

                return output;
            }
        };

    }    // namespace marshalling
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_TYPES_HPP
