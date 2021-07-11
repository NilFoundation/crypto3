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
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>
#include <nil/crypto3/zk/snark/relations/variable.hpp>
#include <nil/crypto3/zk/snark/commitments/detail/element_knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/commitments/knowledge_commitment.hpp>

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
            static const std::size_t linear_term_byteblob_size = std_size_t_byteblob_size + fr_byteblob_size;
            static const std::size_t g2g1_element_kc_byteblob_size = g2_byteblob_size + g1_byteblob_size;

            template<typename FieldType>
            static inline typename std::enable_if<!::nil::crypto3::algebra::is_extended_field<FieldType>::value,
                                                  typename FieldType::value_type>::type
                field_type_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                   typename std::vector<chunk_type>::const_iterator read_iter_end,
                                   status_type &processingStatus) {

                processingStatus = status_type::success;

                using modulus_type = typename FieldType::modulus_type;
                using field_type = FieldType;

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

                processingStatus = status_type::success;
                
                using modulus_type = typename FieldType::modulus_type;
                using field_type = FieldType;

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

            static inline linear_term<typename CurveType::scalar_field_type>
                linear_term_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                    typename std::vector<chunk_type>::const_iterator read_iter_end,
                                    status_type &processingStatus) {

                processingStatus = status_type::success;

                std::size_t index =
                    std_size_t_process(read_iter_begin, read_iter_begin + std_size_t_byteblob_size, processingStatus);

                if (processingStatus != status_type::success) {
                    return linear_term<typename CurveType::scalar_field_type>();
                }

                typename CurveType::scalar_field_type::value_type coeff =
                    field_type_process<typename CurveType::scalar_field_type>(
                        read_iter_begin + std_size_t_byteblob_size,
                        read_iter_begin + std_size_t_byteblob_size + fr_byteblob_size,
                        processingStatus);

                return linear_term<typename CurveType::scalar_field_type>(
                    variable<typename CurveType::scalar_field_type>(index), coeff);
            }

            static inline linear_combination<typename CurveType::scalar_field_type>
                linear_combination_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                           typename std::vector<chunk_type>::const_iterator read_iter_end,
                                           status_type &processingStatus) {

                processingStatus = status_type::success;

                std::size_t terms_count =
                    std_size_t_process(read_iter_begin, read_iter_begin + std_size_t_byteblob_size, processingStatus);

                if (processingStatus != status_type::success) {
                    return linear_combination<typename CurveType::scalar_field_type>();
                }

                std::vector<linear_term<typename CurveType::scalar_field_type>> terms(terms_count);

                for (std::size_t i = 0; i < terms_count; i++) {
                    terms[i] = linear_term_process(
                        read_iter_begin + std_size_t_byteblob_size + i * linear_term_byteblob_size,
                        read_iter_begin + std_size_t_byteblob_size + (i + 1) * linear_term_byteblob_size,
                        processingStatus);

                    if (processingStatus != status_type::success) {
                        return linear_combination<typename CurveType::scalar_field_type>();
                    }
                }

                return linear_combination<typename CurveType::scalar_field_type>(terms);
            }

            static inline r1cs_constraint<typename CurveType::scalar_field_type>
                r1cs_constraint_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                        typename std::vector<chunk_type>::const_iterator read_iter_end,
                                        status_type &processingStatus) {

                std::size_t a_terms_count =
                    std_size_t_process(read_iter_begin, read_iter_begin + std_size_t_byteblob_size, processingStatus);

                if (processingStatus != status_type::success) {
                    return r1cs_constraint<typename CurveType::scalar_field_type>();
                }

                std::size_t a_byte_size = a_terms_count * linear_term_byteblob_size + std_size_t_byteblob_size;
                linear_combination<typename CurveType::scalar_field_type> a =
                    linear_combination_process(read_iter_begin, read_iter_begin + a_byte_size, processingStatus);
                if (processingStatus != status_type::success) {
                    return r1cs_constraint<typename CurveType::scalar_field_type>();
                }

                std::size_t b_terms_count = std_size_t_process(read_iter_begin + a_byte_size,
                                                               read_iter_begin + a_byte_size + std_size_t_byteblob_size,
                                                               processingStatus);

                if (processingStatus != status_type::success) {
                    return r1cs_constraint<typename CurveType::scalar_field_type>();
                }

                std::size_t b_byte_size = b_terms_count * linear_term_byteblob_size + std_size_t_byteblob_size;
                linear_combination<typename CurveType::scalar_field_type> b = linear_combination_process(
                    read_iter_begin + a_byte_size, read_iter_begin + a_byte_size + b_byte_size, processingStatus);
                if (processingStatus != status_type::success) {
                    return r1cs_constraint<typename CurveType::scalar_field_type>();
                }

                std::size_t c_terms_count =
                    std_size_t_process(read_iter_begin + a_byte_size + b_byte_size,
                                       read_iter_begin + a_byte_size + b_byte_size + std_size_t_byteblob_size,
                                       processingStatus);

                if (processingStatus != status_type::success) {
                    return r1cs_constraint<typename CurveType::scalar_field_type>();
                }

                std::size_t c_byte_size = c_terms_count * linear_term_byteblob_size + std_size_t_byteblob_size;
                linear_combination<typename CurveType::scalar_field_type> c =
                    linear_combination_process(read_iter_begin + a_byte_size + b_byte_size,
                                               read_iter_begin + a_byte_size + b_byte_size + c_byte_size,
                                               processingStatus);
                if (processingStatus != status_type::success) {
                    return r1cs_constraint<typename CurveType::scalar_field_type>();
                }

                return r1cs_constraint<typename CurveType::scalar_field_type>(a, b, c);
            }

            static inline r1cs_constraint_system<typename CurveType::scalar_field_type>
                r1cs_constraint_system_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                               typename std::vector<chunk_type>::const_iterator read_iter_end,
                                               status_type &processingStatus) {

                std::size_t primary_input_size =
                    std_size_t_process(read_iter_begin, read_iter_begin + std_size_t_byteblob_size, processingStatus);

                if (processingStatus != status_type::success) {
                    return r1cs_constraint_system<typename CurveType::scalar_field_type>();
                }

                std::size_t auxiliary_input_size = std_size_t_process(read_iter_begin + std_size_t_byteblob_size,
                                                                      read_iter_begin + 2 * std_size_t_byteblob_size,
                                                                      processingStatus);

                if (processingStatus != status_type::success) {
                    return r1cs_constraint_system<typename CurveType::scalar_field_type>();
                }

                std::size_t rc_count = std_size_t_process(read_iter_begin + 2 * std_size_t_byteblob_size,
                                                          read_iter_begin + 3 * std_size_t_byteblob_size,
                                                          processingStatus);

                if (processingStatus != status_type::success) {
                    return r1cs_constraint_system<typename CurveType::scalar_field_type>();
                }

                std::vector<r1cs_constraint<typename CurveType::scalar_field_type>> constraints(rc_count);

                auto read_iter_current_begin = read_iter_begin + 3 * std_size_t_byteblob_size;

                for (std::size_t i = 0; i < rc_count; i++) {

                    std::size_t total_r1cs_constraint_byteblob_size = std_size_t_process(
                        read_iter_current_begin, read_iter_current_begin + std_size_t_byteblob_size, processingStatus);

                    read_iter_current_begin += std_size_t_byteblob_size;

                    constraints[i] =
                        r1cs_constraint_process(read_iter_current_begin,
                                                read_iter_current_begin + total_r1cs_constraint_byteblob_size,
                                                processingStatus);
                    read_iter_current_begin += total_r1cs_constraint_byteblob_size;
                }

                r1cs_constraint_system<typename CurveType::scalar_field_type> res =
                    r1cs_constraint_system<typename CurveType::scalar_field_type>();

                res.primary_input_size = primary_input_size;
                res.auxiliary_input_size = auxiliary_input_size;
                res.constraints = constraints;

                return res;
            }

            static inline crypto3::zk::snark::detail::element_kc<typename CurveType::g2_type,
                                                                 typename CurveType::g1_type>
                g2g1_element_kc_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                        typename std::vector<chunk_type>::const_iterator read_iter_end,
                                        status_type &processingStatus) {

                typename CurveType::g2_type::value_type g = g2_group_type_process<typename CurveType::g2_type>(
                    read_iter_begin, read_iter_begin + g2_byteblob_size, processingStatus);

                typename CurveType::g1_type::value_type h = g1_group_type_process<typename CurveType::g1_type>(
                    read_iter_begin + g2_byteblob_size,
                    read_iter_begin + g2_byteblob_size + g1_byteblob_size,
                    processingStatus);
                return crypto3::zk::snark::detail::element_kc<typename CurveType::g2_type, typename CurveType::g1_type>(
                    g, h);
            }

            static inline knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type>
                g2g1_knowledge_commitment_vector_process(
                    typename std::vector<chunk_type>::const_iterator read_iter_begin,
                    typename std::vector<chunk_type>::const_iterator read_iter_end,
                    status_type &processingStatus) {

                using T = knowledge_commitment<typename CurveType::g2_type, typename CurveType::g1_type>;

                if (std::distance(read_iter_begin, read_iter_end) < std_size_t_byteblob_size) {

                    processingStatus = status_type::not_enough_data;

                    return sparse_vector<T>();
                }

                std::size_t indices_count =
                    std_size_t_process(read_iter_begin, read_iter_begin + std_size_t_byteblob_size, processingStatus);

                if (processingStatus != status_type::success) {
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
                    values[i] = g2g1_element_kc_process(
                        read_iter_begin + std_size_t_byteblob_size + indices_count * std_size_t_byteblob_size +
                            i * g2g1_element_kc_byteblob_size,
                        read_iter_begin + std_size_t_byteblob_size + indices_count * std_size_t_byteblob_size +
                            (i + 1) * g2g1_element_kc_byteblob_size,
                        processingStatus);
                    if (processingStatus != status_type::success) {
                        return sparse_vector<T>();
                    }
                }

                std::size_t domain_size_ = std_size_t_process(
                    read_iter_begin + std_size_t_byteblob_size + indices_count * std_size_t_byteblob_size +
                        indices_count * g2g1_element_kc_byteblob_size,
                    read_iter_begin + std_size_t_byteblob_size + indices_count * std_size_t_byteblob_size +
                        indices_count * g2g1_element_kc_byteblob_size + std_size_t_byteblob_size,
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
                    field_type_process<typename CurveType::gt_type>(read_iter_begin, read_iter_begin + gt_byteblob_size,
                                                                    processingStatus);

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

            static inline typename scheme_type::proving_key_type
                proving_key_process(typename std::vector<chunk_type>::const_iterator read_iter_begin,
                                    typename std::vector<chunk_type>::const_iterator read_iter_end,
                                    status_type &processingStatus) {

                auto read_iter_current_begin = read_iter_begin;

                typename CurveType::g1_type::value_type alpha_g1 = g1_group_type_process<typename CurveType::g1_type>(
                    read_iter_current_begin, read_iter_current_begin + g1_byteblob_size, processingStatus);
                read_iter_current_begin += g1_byteblob_size;
                typename CurveType::g1_type::value_type beta_g1 = g1_group_type_process<typename CurveType::g1_type>(
                    read_iter_current_begin, read_iter_current_begin + g1_byteblob_size, processingStatus);
                read_iter_current_begin += g1_byteblob_size;
                typename CurveType::g2_type::value_type beta_g2 = g2_group_type_process<typename CurveType::g2_type>(
                    read_iter_current_begin, read_iter_current_begin + g2_byteblob_size, processingStatus);
                read_iter_current_begin += g2_byteblob_size;
                typename CurveType::g1_type::value_type delta_g1 = g1_group_type_process<typename CurveType::g1_type>(
                    read_iter_current_begin, read_iter_current_begin + g1_byteblob_size, processingStatus);
                read_iter_current_begin += g1_byteblob_size;
                typename CurveType::g2_type::value_type delta_g2 = g2_group_type_process<typename CurveType::g2_type>(
                    read_iter_current_begin, read_iter_current_begin + g2_byteblob_size, processingStatus);
                read_iter_current_begin += g2_byteblob_size;
                std::size_t A_query_size = std_size_t_process(
                    read_iter_current_begin, read_iter_current_begin + std_size_t_byteblob_size, processingStatus);

                read_iter_current_begin += std_size_t_byteblob_size;
                std::vector<typename CurveType::g1_type::value_type> A_query(A_query_size);

                for (std::size_t i = 0; i < A_query_size; ++i) {
                    A_query[i] = g1_group_type_process<typename CurveType::g1_type>(
                        read_iter_current_begin, read_iter_current_begin + g1_byteblob_size, processingStatus);
                    read_iter_current_begin += g1_byteblob_size;
                }

                std::size_t total_B_query_size = std_size_t_process(
                    read_iter_current_begin, read_iter_current_begin + std_size_t_byteblob_size, processingStatus);

                read_iter_current_begin += std_size_t_byteblob_size;

                knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type> B_query =
                    g2g1_knowledge_commitment_vector_process(
                        read_iter_current_begin, read_iter_current_begin + total_B_query_size, processingStatus);

                read_iter_current_begin += total_B_query_size;

                std::size_t H_query_size = std_size_t_process(
                    read_iter_current_begin, read_iter_current_begin + std_size_t_byteblob_size, processingStatus);

                read_iter_current_begin += std_size_t_byteblob_size;
                std::vector<typename CurveType::g1_type::value_type> H_query(H_query_size);

                for (std::size_t i = 0; i < H_query_size; ++i) {
                    H_query[i] = g1_group_type_process<typename CurveType::g1_type>(
                        read_iter_current_begin, read_iter_current_begin + g1_byteblob_size, processingStatus);
                    read_iter_current_begin += g1_byteblob_size;
                }

                std::size_t L_query_size = std_size_t_process(
                    read_iter_current_begin, read_iter_current_begin + std_size_t_byteblob_size, processingStatus);

                read_iter_current_begin += std_size_t_byteblob_size;
                std::vector<typename CurveType::g1_type::value_type> L_query(L_query_size);

                for (std::size_t i = 0; i < L_query_size; ++i) {
                    L_query[i] = g1_group_type_process<typename CurveType::g1_type>(
                        read_iter_current_begin, read_iter_current_begin + g1_byteblob_size, processingStatus);
                    read_iter_current_begin += g1_byteblob_size;
                }

                r1cs_constraint_system<typename CurveType::scalar_field_type> constraint_system =
                    r1cs_constraint_system_process(read_iter_current_begin, read_iter_end, processingStatus);

                return typename scheme_type::proving_key_type(
                    std::move(alpha_g1), std::move(beta_g1), std::move(beta_g2), std::move(delta_g1),
                    std::move(delta_g2), std::move(A_query), std::move(B_query), std::move(H_query), std::move(L_query),
                    std::move(constraint_system));
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

            static const std::size_t std_size_t_byteblob_size = 4;
            static const std::size_t g1_byteblob_size = curve_element_serializer<CurveType>::sizeof_field_element;
            static const std::size_t g2_byteblob_size = 2 * curve_element_serializer<CurveType>::sizeof_field_element;
            static const std::size_t fp_byteblob_size = CurveType::base_field_type::modulus_bits / chunk_size +
                                                        (CurveType::base_field_type::modulus_bits % chunk_size ? 1 : 0);
            static const std::size_t gt_byteblob_size = 2 * 3 * 2 * fp_byteblob_size;
            static const std::size_t fr_byteblob_size =
                CurveType::scalar_field_type::modulus_bits / chunk_size +
                (CurveType::scalar_field_type::modulus_bits % chunk_size ? 1 : 0);
            static const std::size_t linear_term_byteblob_size = std_size_t_byteblob_size + fr_byteblob_size;
            static const std::size_t g2g1_element_kc_byteblob_size = g2_byteblob_size + g1_byteblob_size;

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

            template<typename T>
            static inline void linear_term_process(linear_term<T> input_lt,
                                                   std::vector<chunk_type>::iterator &write_iter) {

                std_size_t_process(input_lt.index, write_iter);

                field_type_process<T>(input_lt.coeff, write_iter);
            }

            template<typename T>
            static inline void linear_combination_process(linear_combination<T> input_cm,
                                                          std::vector<chunk_type>::iterator &write_iter) {

                std_size_t_process(input_cm.terms.size(), write_iter);

                for (auto it = input_cm.terms.begin(); it != input_cm.terms.end(); it++) {
                    linear_term_process<T>(*it, write_iter);
                }
            }

            static inline std::size_t
                get_r1cs_constraint_byteblob_size(r1cs_constraint<typename CurveType::scalar_field_type> input_rc) {

                return input_rc.a.terms.size() * (std_size_t_byteblob_size + fr_byteblob_size) +
                       std_size_t_byteblob_size +
                       input_rc.b.terms.size() * (std_size_t_byteblob_size + fr_byteblob_size) +
                       std_size_t_byteblob_size +
                       input_rc.c.terms.size() * (std_size_t_byteblob_size + fr_byteblob_size) +
                       std_size_t_byteblob_size;
            }

            template<typename T>
            static inline void r1cs_constraint_process(r1cs_constraint<T> input_rc,
                                                       std::vector<chunk_type>::iterator &write_iter) {

                std_size_t_process(get_r1cs_constraint_byteblob_size(input_rc), write_iter);
                linear_combination_process<T>(input_rc.a, write_iter);
                linear_combination_process<T>(input_rc.b, write_iter);
                linear_combination_process<T>(input_rc.c, write_iter);
            }

            template<typename T>
            static inline void r1cs_constraint_system_process(r1cs_constraint_system<T> input_rs,
                                                              std::vector<chunk_type>::iterator &write_iter) {

                std_size_t_process(input_rs.primary_input_size, write_iter);
                std_size_t_process(input_rs.auxiliary_input_size, write_iter);
                std_size_t_process(input_rs.constraints.size(), write_iter);

                for (auto it = input_rs.constraints.begin(); it != input_rs.constraints.end(); it++) {
                    r1cs_constraint_process<T>(*it, write_iter);
                }
            }

            static inline void g2g1_element_kc_process(
                crypto3::zk::snark::detail::element_kc<typename CurveType::g2_type, typename CurveType::g1_type>
                    input_ek,
                std::vector<chunk_type>::iterator &write_iter) {

                g2_group_type_process<typename CurveType::g2_type>(input_ek.g, write_iter);
                g1_group_type_process<typename CurveType::g1_type>(input_ek.h, write_iter);
            }

            static inline std::size_t get_g2g1_knowledge_commitment_vector_size(
                knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type> input_kv) {

                return (2 + input_kv.indices.size()) * std_size_t_byteblob_size +
                       input_kv.values.size() * (g2_byteblob_size + g1_byteblob_size);
            }

            static inline void g2g1_knowledge_commitment_vector_process(
                knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type>
                    input_kv,
                std::vector<chunk_type>::iterator &write_iter) {

                std_size_t_process(get_g2g1_knowledge_commitment_vector_size(input_kv), write_iter);

                std::size_t ic_size = input_kv.values.size();

                std_size_t_process(ic_size, write_iter);

                for (auto ic_iter = input_kv.indices.begin(); ic_iter != input_kv.indices.end(); ic_iter++) {
                    std_size_t_process(*ic_iter, write_iter);
                }

                for (auto ic_iter = input_kv.values.begin(); ic_iter != input_kv.values.end(); ic_iter++) {
                    g2g1_element_kc_process(*ic_iter, write_iter);
                }

                std_size_t_process(input_kv.domain_size(), write_iter);
            }

            static inline std::vector<chunk_type> process(typename scheme_type::proving_key_type pk) {

                std::size_t proving_key_size = 3*g1_byteblob_size + 
                    2*g2_byteblob_size + pk.A_query.size()*g1_byteblob_size +
                    get_g2g1_knowledge_commitment_vector_size(pk.B_query) + 
                    pk.H_query.size()*g1_byteblob_size + 
                    pk.L_query.size()*g1_byteblob_size +
                    2 * std_size_t_byteblob_size;

                for (auto it = pk.constraint_system.constraints.begin(); 
                        it != pk.constraint_system.constraints.end(); it++) {
                    proving_key_size += get_r1cs_constraint_byteblob_size(*it);
                }

                proving_key_size *= 2;

                std::vector<chunk_type> output(proving_key_size);

                typename std::vector<chunk_type>::iterator write_iter = output.begin();

                g1_group_type_process<typename CurveType::g1_type>(pk.alpha_g1, write_iter);
                g1_group_type_process<typename CurveType::g1_type>(pk.beta_g1, write_iter);
                g2_group_type_process<typename CurveType::g2_type>(pk.beta_g2, write_iter);
                g1_group_type_process<typename CurveType::g1_type>(pk.delta_g1, write_iter);
                g2_group_type_process<typename CurveType::g2_type>(pk.delta_g2, write_iter);

                std_size_t_process(pk.A_query.size(), write_iter);

                for (auto it = pk.A_query.begin(); it != pk.A_query.end(); it++) {
                    g1_group_type_process<typename CurveType::g1_type>(*it, write_iter);
                }

                g2g1_knowledge_commitment_vector_process(pk.B_query, write_iter);

                std_size_t_process(pk.H_query.size(), write_iter);

                for (auto it = pk.H_query.begin(); it != pk.H_query.end(); it++) {
                    g1_group_type_process<typename CurveType::g1_type>(*it, write_iter);
                }

                std_size_t_process(pk.L_query.size(), write_iter);

                for (auto it = pk.L_query.begin(); it != pk.L_query.end(); it++) {
                    g1_group_type_process<typename CurveType::g1_type>(*it, write_iter);
                }

                r1cs_constraint_system_process<typename CurveType::scalar_field_type>(pk.constraint_system, write_iter);

                return output;
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