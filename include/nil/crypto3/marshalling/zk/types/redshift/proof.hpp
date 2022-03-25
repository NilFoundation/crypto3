//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021-2022 Ilias Khairullin <ilias@nil.foundation>
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

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/redshift/proof.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<
                    typename TTypeBase, typename RedshiftProof,
                    typename = typename std::enable_if<
                        std::is_same<RedshiftProof, nil::crypto3::zk::snark::redshift_proof<
                                                        typename RedshiftProof::field_type,
                                                        typename RedshiftProof::commitment_scheme_type_witness,
                                                        typename RedshiftProof::commitment_scheme_type_permutation,
                                                        typename RedshiftProof::commitment_scheme_type_quotient,
                                                        typename RedshiftProof::commitment_scheme_type_public>>::value,
                        bool>::type,
                    typename... TOptions>
                using redshift_evaluation_proof = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // typename FieldType::value_type challenge
                        field_element<TTypeBase, typename RedshiftProof::field_type::value_type>,
                        // std::vector<typename CommitmentSchemeTypeWitness::proof_type> witness
                        nil::marshalling::types::array_list<
                            TTypeBase, lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type_witness>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // std::vector<typename CommitmentSchemeTypePermutation::proof_type> permutation
                        nil::marshalling::types::array_list<
                            TTypeBase, lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type_permutation>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // std::vector<typename CommitmentSchemeTypeQuotient::proof_type> quotient
                        nil::marshalling::types::array_list<
                            TTypeBase, lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type_quotient>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // std::vector<typename commitment_scheme_type_public::proof_type> id_permutation
                        nil::marshalling::types::array_list<
                            TTypeBase, lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type_public>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // std::vector<typename commitment_scheme_type_public::proof_type> sigma_permutation
                        nil::marshalling::types::array_list<
                            TTypeBase, lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type_public>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // std::vector<typename commitment_scheme_type_public::proof_type> public_input
                        nil::marshalling::types::array_list<
                            TTypeBase, lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type_public>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // std::vector<typename commitment_scheme_type_public::proof_type> constant
                        nil::marshalling::types::array_list<
                            TTypeBase, lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type_public>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // std::vector<typename commitment_scheme_type_public::proof_type> selector
                        nil::marshalling::types::array_list<
                            TTypeBase, lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type_public>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // std::vector<typename commitment_scheme_type_public::proof_type> special_selectors
                        nil::marshalling::types::array_list<
                            TTypeBase, lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type_public>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>;

                template<
                    typename TTypeBase, typename RedshiftProof,
                    typename = typename std::enable_if<
                        std::is_same<RedshiftProof, nil::crypto3::zk::snark::redshift_proof<
                                                        typename RedshiftProof::field_type,
                                                        typename RedshiftProof::commitment_scheme_type_witness,
                                                        typename RedshiftProof::commitment_scheme_type_permutation,
                                                        typename RedshiftProof::commitment_scheme_type_quotient,
                                                        typename RedshiftProof::commitment_scheme_type_public>>::value,
                        bool>::type,
                    typename... TOptions>
                using redshift_proof = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                        // TODO: review std::uint8_t type usage (for example, pedersen outputs array of bits)
                        // typename CommitmentSchemeTypePermutation::commitment_type v_perm_commitment
                        nil::marshalling::types::array_list<
                            TTypeBase, nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // std::vector<typename CommitmentSchemeTypeWitness::commitment_type> witness_commitments
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::array_list<
                                TTypeBase, nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // std::vector<typename CommitmentSchemeTypeQuotient::commitment_type> T_commitments
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::array_list<
                                TTypeBase, nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // evaluation_proof eval_proof
                        redshift_evaluation_proof<TTypeBase, RedshiftProof>>>;

                template<typename RedshiftProof, typename Endianness>
                redshift_evaluation_proof<nil::marshalling::field_type<Endianness>, RedshiftProof>
                    fill_redshift_evaluation_proof(const typename RedshiftProof::evaluation_proof &proof) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using field_marhsalling_type =
                        field_element<TTypeBase, typename RedshiftProof::field_type::value_type>;
                    using lpc_witness_proof_marshalling_type =
                        lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type_witness>;
                    using lpc_witness_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, lpc_witness_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using lpc_permutation_proof_marshalling_type =
                        lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type_permutation>;
                    using lpc_permutation_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, lpc_permutation_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using lpc_quotient_proof_marshalling_type =
                        lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type_quotient>;
                    using lpc_quotient_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, lpc_quotient_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using lpc_public_proof_marshalling_type =
                        lpc_proof<TTypeBase, typename RedshiftProof::commitment_scheme_type_public>;
                    using lpc_public_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, lpc_public_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;

                    // typename FieldType::value_type challenge
                    field_marhsalling_type filled_challenge = field_marhsalling_type(proof.challenge);

                    // std::vector<typename CommitmentSchemeTypeWitness::proof_type> witness
                    lpc_witness_proof_vector_marshalling_type filled_witness;
                    for (const auto &p : proof.witness) {
                        filled_witness.value().push_back(
                            fill_lpc_proof<typename RedshiftProof::commitment_scheme_type_witness, Endianness>(p));
                    }

                    // std::vector<typename CommitmentSchemeTypePermutation::proof_type> permutation
                    lpc_permutation_proof_vector_marshalling_type filled_permutation;
                    for (const auto &p : proof.permutation) {
                        filled_permutation.value().push_back(
                            fill_lpc_proof<typename RedshiftProof::commitment_scheme_type_permutation, Endianness>(p));
                    }

                    // std::vector<typename CommitmentSchemeTypeQuotient::proof_type> quotient
                    lpc_quotient_proof_vector_marshalling_type filled_quotient;
                    for (const auto &p : proof.quotient) {
                        filled_quotient.value().push_back(
                            fill_lpc_proof<typename RedshiftProof::commitment_scheme_type_quotient, Endianness>(p));
                    }

                    // std::vector<typename commitment_scheme_type_public::proof_type> id_permutation
                    lpc_public_proof_vector_marshalling_type filled_id_permutation;
                    for (const auto &p : proof.id_permutation) {
                        filled_id_permutation.value().push_back(
                            fill_lpc_proof<typename RedshiftProof::commitment_scheme_type_public, Endianness>(p));
                    }

                    // std::vector<typename commitment_scheme_type_public::proof_type> sigma_permutation
                    lpc_public_proof_vector_marshalling_type filled_sigma_permutation;
                    for (const auto &p : proof.sigma_permutation) {
                        filled_sigma_permutation.value().push_back(
                            fill_lpc_proof<typename RedshiftProof::commitment_scheme_type_public, Endianness>(p));
                    }

                    // std::vector<typename commitment_scheme_type_public::proof_type> public_input
                    lpc_public_proof_vector_marshalling_type filled_public_input;
                    for (const auto &p : proof.public_input) {
                        filled_public_input.value().push_back(
                            fill_lpc_proof<typename RedshiftProof::commitment_scheme_type_public, Endianness>(p));
                    }

                    // std::vector<typename commitment_scheme_type_public::proof_type> constant
                    lpc_public_proof_vector_marshalling_type filled_constant;
                    for (const auto &p : proof.constant) {
                        filled_constant.value().push_back(
                            fill_lpc_proof<typename RedshiftProof::commitment_scheme_type_public, Endianness>(p));
                    }

                    // std::vector<typename commitment_scheme_type_public::proof_type> selector
                    lpc_public_proof_vector_marshalling_type filled_selector;
                    for (const auto &p : proof.selector) {
                        filled_selector.value().push_back(
                            fill_lpc_proof<typename RedshiftProof::commitment_scheme_type_public, Endianness>(p));
                    }

                    // std::vector<typename commitment_scheme_type_public::proof_type> special_selectors
                    lpc_public_proof_vector_marshalling_type filled_special_selectors;
                    for (const auto &p : proof.special_selectors) {
                        filled_special_selectors.value().push_back(
                            fill_lpc_proof<typename RedshiftProof::commitment_scheme_type_public, Endianness>(p));
                    }

                    return redshift_evaluation_proof<nil::marshalling::field_type<Endianness>, RedshiftProof>(
                        std::make_tuple(filled_challenge, filled_witness, filled_permutation, filled_quotient,
                                        filled_id_permutation, filled_sigma_permutation, filled_public_input,
                                        filled_constant, filled_selector, filled_special_selectors));
                }

                template<typename RedshiftProof, typename Endianness>
                typename RedshiftProof::evaluation_proof make_redshift_evaluation_proof(
                    const redshift_evaluation_proof<nil::marshalling::field_type<Endianness>, RedshiftProof>
                        &filled_proof) {

                    typename RedshiftProof::evaluation_proof proof;

                    // typename FieldType::value_type challenge
                    proof.challenge = std::get<0>(filled_proof.value()).value();

                    // std::vector<typename CommitmentSchemeTypeWitness::proof_type> witness
                    for (std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); ++i) {
                        proof.witness.emplace_back(
                            make_lpc_proof<typename RedshiftProof::commitment_scheme_type_witness, Endianness>(
                                std::get<1>(filled_proof.value()).value().at(i)));
                    }

                    // std::vector<typename CommitmentSchemeTypePermutation::proof_type> permutation
                    for (std::size_t i = 0; i < std::get<2>(filled_proof.value()).value().size(); ++i) {
                        proof.permutation.emplace_back(
                            make_lpc_proof<typename RedshiftProof::commitment_scheme_type_permutation, Endianness>(
                                std::get<2>(filled_proof.value()).value().at(i)));
                    }

                    // std::vector<typename CommitmentSchemeTypeQuotient::proof_type> quotient
                    for (std::size_t i = 0; i < std::get<3>(filled_proof.value()).value().size(); ++i) {
                        proof.quotient.emplace_back(
                            make_lpc_proof<typename RedshiftProof::commitment_scheme_type_quotient, Endianness>(
                                std::get<3>(filled_proof.value()).value().at(i)));
                    }

                    // std::vector<typename commitment_scheme_type_public::proof_type> id_permutation
                    for (std::size_t i = 0; i < std::get<4>(filled_proof.value()).value().size(); ++i) {
                        proof.id_permutation.emplace_back(
                            make_lpc_proof<typename RedshiftProof::commitment_scheme_type_public, Endianness>(
                                std::get<4>(filled_proof.value()).value().at(i)));
                    }

                    // std::vector<typename commitment_scheme_type_public::proof_type> sigma_permutation
                    for (std::size_t i = 0; i < std::get<5>(filled_proof.value()).value().size(); ++i) {
                        proof.sigma_permutation.emplace_back(
                            make_lpc_proof<typename RedshiftProof::commitment_scheme_type_public, Endianness>(
                                std::get<5>(filled_proof.value()).value().at(i)));
                    }

                    // std::vector<typename commitment_scheme_type_public::proof_type> public_input
                    for (std::size_t i = 0; i < std::get<6>(filled_proof.value()).value().size(); ++i) {
                        proof.public_input.emplace_back(
                            make_lpc_proof<typename RedshiftProof::commitment_scheme_type_public, Endianness>(
                                std::get<6>(filled_proof.value()).value().at(i)));
                    }

                    // std::vector<typename commitment_scheme_type_public::proof_type> constant
                    for (std::size_t i = 0; i < std::get<7>(filled_proof.value()).value().size(); ++i) {
                        proof.constant.emplace_back(
                            make_lpc_proof<typename RedshiftProof::commitment_scheme_type_public, Endianness>(
                                std::get<7>(filled_proof.value()).value().at(i)));
                    }

                    // std::vector<typename commitment_scheme_type_public::proof_type> selector
                    for (std::size_t i = 0; i < std::get<8>(filled_proof.value()).value().size(); ++i) {
                        proof.selector.emplace_back(
                            make_lpc_proof<typename RedshiftProof::commitment_scheme_type_public, Endianness>(
                                std::get<8>(filled_proof.value()).value().at(i)));
                    }

                    // std::vector<typename commitment_scheme_type_public::proof_type> special_selectors
                    for (std::size_t i = 0; i < std::get<9>(filled_proof.value()).value().size(); ++i) {
                        proof.special_selectors.emplace_back(
                            make_lpc_proof<typename RedshiftProof::commitment_scheme_type_public, Endianness>(
                                std::get<9>(filled_proof.value()).value().at(i)));
                    }

                    return proof;
                }

                template<typename RedshiftProof, typename Endianness>
                redshift_proof<nil::marshalling::field_type<Endianness>, RedshiftProof>
                    fill_redshift_proof(const RedshiftProof &proof) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using octet_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint8_t>;
                    using digest_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, octet_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using commitment_marshalling_type = digest_marshalling_type;
                    using commitment_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, commitment_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;

                    // typename CommitmentSchemeTypePermutation::commitment_type v_perm_commitment
                    commitment_marshalling_type filled_v_perm_commitment;
                    for (const auto c : proof.v_perm_commitment) {
                        filled_v_perm_commitment.value().push_back(octet_marshalling_type(c));
                    }

                    // std::vector<typename CommitmentSchemeTypeWitness::commitment_type> witness_commitments
                    commitment_vector_marshalling_type filled_witness_commitments;
                    for (const auto &comm : proof.witness_commitments) {
                        commitment_marshalling_type filled_c;
                        for (const auto c : comm) {
                            filled_c.value().push_back(octet_marshalling_type(c));
                        }
                        filled_witness_commitments.value().push_back(filled_c);
                    }

                    // std::vector<typename CommitmentSchemeTypeQuotient::commitment_type> T_commitments
                    commitment_vector_marshalling_type filled_T_commitments;
                    for (const auto &comm : proof.T_commitments) {
                        commitment_marshalling_type filled_c;
                        for (const auto c : comm) {
                            filled_c.value().push_back(octet_marshalling_type(c));
                        }
                        filled_T_commitments.value().push_back(filled_c);
                    }

                    return redshift_proof<TTypeBase, RedshiftProof>(
                        std::make_tuple(filled_v_perm_commitment, filled_witness_commitments, filled_T_commitments,
                                        fill_redshift_evaluation_proof<RedshiftProof, Endianness>(proof.eval_proof)));
                }

                template<typename RedshiftProof, typename Endianness>
                RedshiftProof make_redshift_proof(
                    const redshift_proof<nil::marshalling::field_type<Endianness>, RedshiftProof> &filled_proof) {

                    RedshiftProof proof;

                    // typename CommitmentSchemeTypePermutation::commitment_type v_perm_commitment
                    assert(proof.v_perm_commitment.size() == std::get<0>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<0>(filled_proof.value()).value().size(); ++i) {
                        proof.v_perm_commitment.at(i) = std::get<0>(filled_proof.value()).value().at(i).value();
                    }

                    // std::vector<typename CommitmentSchemeTypeWitness::commitment_type> witness_commitments
                    for (std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); ++i) {
                        typename RedshiftProof::commitment_scheme_type_witness::commitment_type comm;
                        assert(comm.size() == std::get<1>(filled_proof.value()).value().at(i).value().size());
                        for (std::size_t j = 0; j < std::get<1>(filled_proof.value()).value().at(i).value().size();
                             ++j) {
                            comm.at(j) = std::get<1>(filled_proof.value()).value().at(i).value().at(j).value();
                        }
                        proof.witness_commitments.push_back(comm);
                    }

                    // std::vector<typename CommitmentSchemeTypeQuotient::commitment_type> T_commitments
                    for (std::size_t i = 0; i < std::get<2>(filled_proof.value()).value().size(); ++i) {
                        typename RedshiftProof::commitment_scheme_type_quotient::commitment_type comm;
                        assert(comm.size() == std::get<2>(filled_proof.value()).value().at(i).value().size());
                        for (std::size_t j = 0; j < std::get<2>(filled_proof.value()).value().at(i).value().size();
                             ++j) {
                            comm.at(j) = std::get<2>(filled_proof.value()).value().at(i).value().at(j).value();
                        }
                        proof.T_commitments.push_back(comm);
                    }

                    // evaluation_proof eval_proof
                    proof.eval_proof =
                        make_redshift_evaluation_proof<RedshiftProof, Endianness>(std::get<3>(filled_proof.value()));

                    return proof;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_REDSHIFT_PROOF_HPP
