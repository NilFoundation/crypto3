//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_REDSHIFT_PROOF_HPP
#define CRYPTO3_MARSHALLING_REDSHIFT_PROOF_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/containers/types/merkle_proof.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/list_polynomial_commitment.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/redshift/proof.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase,
                         typename RedshiftProof,
                         typename = typename std::enable_if<
                             std::is_same<RedshiftProof,
                                          nil::crypto3::zk::snark::redshift_proof<
                                              typename RedshiftProof::commitment_scheme_type>>::value,
                             bool>::type,
                         typename... TOptions>
                using redshift_proof = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // std::vector<typename RedshiftProof::commitment_scheme_type::commitment_type> f_commitments
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                            // TODO: review std::uint8_t type usage (for example, pedersen outputs array of bits)
                            // typename RedshiftProof::commitment_scheme_type::commitment_type
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                        // TODO: review std::uint8_t type usage (for example, pedersen outputs array of bits)
                        // typename RedshiftProof::commitment_scheme_type::commitment_type P_commitment
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                        // TODO: review std::uint8_t type usage (for example, pedersen outputs array of bits)
                        // typename RedshiftProof::commitment_scheme_type::commitment_type Q_commitment
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // std::vector<typename CommitmentSchemeType::commitment_type> T_commitments
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                            // TODO: review std::uint8_t type usage (for example, pedersen outputs array of bits)
                            // typename RedshiftProof::commitment_scheme_type::commitment_type
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // std::vector<typename CommitmentSchemeType::proof_type> f_lpc_proofs
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // typename CommitmentSchemeType::proof_type P_lpc_proof
                        lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type>,
                        // typename CommitmentSchemeType::proof_type Q_lpc_proof
                        lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type>,
                        // std::vector<typename CommitmentSchemeType::proof_type> T_lpc_proofs
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>;

                template<typename RedshiftProof, typename Endianness>
                redshift_proof<nil::marshalling::field_type<Endianness>, RedshiftProof>
                    fill_redshift_proof(const RedshiftProof &redshift_prf) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using octet_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint8_t>;
                    using digest_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        octet_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using digest_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        digest_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using lpc_proof_marshalling_type =
                        lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type>;
                    using lpc_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        lpc_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;

                    // std::vector<typename CommitmentSchemeType::commitment_type> f_commitments;
                    digest_vector_marshalling_type filled_f_commitments;
                    for (const auto &c : redshift_prf.f_commitments) {
                        digest_marshalling_type filled_digest;
                        for (const auto c_i : c) {
                            filled_digest.value().push_back(octet_marshalling_type(c_i));
                        }
                        filled_f_commitments.value().push_back(filled_digest);
                    }

                    // typename CommitmentSchemeType::commitment_type P_commitment
                    digest_marshalling_type filled_P_commitment;
                    for (const auto c_i : redshift_prf.P_commitment) {
                        filled_P_commitment.value().push_back(octet_marshalling_type(c_i));
                    }

                    // typename CommitmentSchemeType::commitment_type Q_commitment
                    digest_marshalling_type filled_Q_commitment;
                    for (const auto c_i : redshift_prf.Q_commitment) {
                        filled_Q_commitment.value().push_back(octet_marshalling_type(c_i));
                    }

                    // std::vector<typename CommitmentSchemeType::commitment_type> T_commitments
                    digest_vector_marshalling_type filled_T_commitments;
                    for (const auto &c : redshift_prf.T_commitments) {
                        digest_marshalling_type filled_digest;
                        for (const auto c_i : c) {
                            filled_digest.value().push_back(octet_marshalling_type(c_i));
                        }
                        filled_T_commitments.value().push_back(filled_digest);
                    }

                    // std::vector<typename CommitmentSchemeType::proof_type> f_lpc_proofs
                    lpc_proof_vector_marshalling_type filled_f_lpc_proofs;
                    for (const auto &p : redshift_prf.f_lpc_proofs) {
                        filled_f_lpc_proofs.value().push_back(
                            fill_lpc_proof<typename RedshiftProof::commitment_scheme_type, Endianness>(p));
                    }

                    // std::vector<typename CommitmentSchemeType::proof_type> T_lpc_proofs
                    lpc_proof_vector_marshalling_type filled_T_lpc_proofs;
                    for (const auto &p : redshift_prf.T_lpc_proofs) {
                        filled_T_lpc_proofs.value().push_back(
                            fill_lpc_proof<typename RedshiftProof::commitment_scheme_type, Endianness>(p));
                    }

                    return redshift_proof<nil::marshalling::field_type<Endianness>, RedshiftProof>(
                        std::make_tuple(filled_f_commitments,
                                        filled_P_commitment,
                                        filled_Q_commitment,
                                        filled_T_commitments,
                                        filled_f_lpc_proofs,
                                        fill_lpc_proof<typename RedshiftProof::commitment_scheme_type, Endianness>(
                                            redshift_prf.P_lpc_proof),
                                        fill_lpc_proof<typename RedshiftProof::commitment_scheme_type, Endianness>(
                                            redshift_prf.Q_lpc_proof),
                                        filled_T_lpc_proofs));
                }

                template<typename RedshiftProof, typename Endianness>
                RedshiftProof make_redshift_proof(const redshift_proof<nil::marshalling::field_type<Endianness>,
                                                                       RedshiftProof> &filled_redshift_prf) {

                    RedshiftProof redshift_prf;

                    // std::vector<typename CommitmentSchemeType::commitment_type> f_commitments;
                    for (std::size_t i = 0; i < std::get<0>(filled_redshift_prf.value()).value().size(); ++i) {
                        typename RedshiftProof::commitment_scheme_type::commitment_type c;
                        assert(c.size() == std::get<0>(filled_redshift_prf.value()).value().at(i).value().size());
                        for (std::size_t j = 0;
                             j < std::get<0>(filled_redshift_prf.value()).value().at(i).value().size();
                             ++j) {
                            c.at(j) = std::get<0>(filled_redshift_prf.value()).value().at(i).value().at(j).value();
                        }
                        redshift_prf.f_commitments.push_back(c);
                    }

                    // typename CommitmentSchemeType::commitment_type P_commitment
                    assert(redshift_prf.P_commitment.size() == std::get<1>(filled_redshift_prf.value()).value().size());
                    for (std::size_t j = 0; j < std::get<1>(filled_redshift_prf.value()).value().size(); ++j) {
                        redshift_prf.P_commitment.at(j) =
                            std::get<1>(filled_redshift_prf.value()).value().at(j).value();
                    }

                    // typename CommitmentSchemeType::commitment_type Q_commitment
                    assert(redshift_prf.Q_commitment.size() == std::get<2>(filled_redshift_prf.value()).value().size());
                    for (std::size_t j = 0; j < std::get<2>(filled_redshift_prf.value()).value().size(); ++j) {
                        redshift_prf.Q_commitment.at(j) =
                            std::get<2>(filled_redshift_prf.value()).value().at(j).value();
                    }

                    // std::vector<typename CommitmentSchemeType::commitment_type> T_commitments
                    for (std::size_t i = 0; i < std::get<3>(filled_redshift_prf.value()).value().size(); ++i) {
                        typename RedshiftProof::commitment_scheme_type::commitment_type c;
                        assert(c.size() == std::get<3>(filled_redshift_prf.value()).value().at(i).value().size());
                        for (std::size_t j = 0;
                             j < std::get<3>(filled_redshift_prf.value()).value().at(i).value().size();
                             ++j) {
                            c.at(j) = std::get<3>(filled_redshift_prf.value()).value().at(i).value().at(j).value();
                        }
                        redshift_prf.T_commitments.push_back(c);
                    }

                    // std::vector<typename CommitmentSchemeType::proof_type> f_lpc_proofs
                    for (std::size_t i = 0; i < std::get<4>(filled_redshift_prf.value()).value().size(); ++i) {
                        redshift_prf.f_lpc_proofs.push_back(
                            make_lpc_proof<typename RedshiftProof::commitment_scheme_type, Endianness>(
                                std::get<4>(filled_redshift_prf.value()).value().at(i)));
                    }

                    // typename CommitmentSchemeType::proof_type P_lpc_proof
                    redshift_prf.P_lpc_proof =
                        make_lpc_proof<typename RedshiftProof::commitment_scheme_type, Endianness>(
                            std::get<5>(filled_redshift_prf.value()));

                    // typename CommitmentSchemeType::proof_type Q_lpc_proof
                    redshift_prf.Q_lpc_proof =
                        make_lpc_proof<typename RedshiftProof::commitment_scheme_type, Endianness>(
                            std::get<6>(filled_redshift_prf.value()));

                    // std::vector<typename CommitmentSchemeType::proof_type> T_lpc_proofs
                    for (std::size_t i = 0; i < std::get<7>(filled_redshift_prf.value()).value().size(); ++i) {
                        redshift_prf.T_lpc_proofs.push_back(
                            make_lpc_proof<typename RedshiftProof::commitment_scheme_type, Endianness>(
                                std::get<7>(filled_redshift_prf.value()).value().at(i)));
                    }

                    return redshift_prf;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_REDSHIFT_PROOF_HPP
