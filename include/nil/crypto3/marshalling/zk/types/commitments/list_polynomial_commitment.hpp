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

#ifndef CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP
#define CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/containers/types/merkle_proof.hpp>

#include <nil/crypto3/zk/snark/commitments/list_polynomial_commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase,
                         typename LPCScheme,
                         typename = typename std::enable_if<
                             std::is_same<LPCScheme,
                                          nil::crypto3::zk::snark::list_polynomial_commitment_scheme<
                                              typename LPCScheme::field_type,
                                              typename LPCScheme::transcript_hash_type,
                                              LPCScheme::lambda,
                                              LPCScheme::k,
                                              LPCScheme::r,
                                              LPCScheme::m>>::value,
                             bool>::type,
                         typename... TOptions>
                using lpc_proof = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                        // std::array<merkle_proof_type, k> z_openings;
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            merkle_proof<TTypeBase, typename LPCScheme::openning_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                        // std::array<std::array<merkle_proof_type, m * r>, lambda> alpha_openings
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                merkle_proof<TTypeBase, typename LPCScheme::openning_type>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                        // std::array<std::array<merkle_proof_type, r>, lambda> f_y_openings
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                merkle_proof<TTypeBase, typename LPCScheme::openning_type>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                        // std::array<std::array<commitment_type, r - 1>, lambda> f_commitments
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                                // TODO: review std::uint8_t type usage (for example, pedersen outputs array of bits)
                                nil::marshalling::types::array_list<
                                    TTypeBase,
                                    nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                    nil::marshalling::option::sequence_size_field_prefix<
                                        nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                        // std::array<math::polynomial<typename FieldType::value_type>, lambda>
                        //  f_ip1_coefficients
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                field_element<TTypeBase, typename LPCScheme::field_type>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>;

                template<typename LPCScheme, typename Endianness>
                lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme>
                    fill_lpc_proof(const typename LPCScheme::proof_type &lpc_prf) {

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
                    using digest_vector_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        digest_vector_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using merkle_proof_marshalling_type = merkle_proof<TTypeBase, typename LPCScheme::openning_type>;
                    using merkle_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        merkle_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using merkle_proof_vector_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        merkle_proof_vector_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using field_marhsalling_type = field_element<TTypeBase, typename LPCScheme::field_type>;
                    using field_poly_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        field_marhsalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using field_poly_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        field_poly_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;

                    // std::array<merkle_proof_type, k> z_openings
                    merkle_proof_vector_marshalling_type filled_z_openings;
                    for (const auto &c : lpc_prf.z_openings) {
                        filled_z_openings.value().push_back(
                            fill_merkle_proof<typename LPCScheme::openning_type, Endianness>(c));
                    }

                    // std::array<std::array<merkle_proof_type, m * r>, lambda> alpha_openings
                    merkle_proof_vector_vector_marshalling_type filled_alpha_openings;
                    for (const auto &openings : lpc_prf.alpha_openings) {
                        merkle_proof_vector_marshalling_type filled_opening;
                        for (const auto &c : openings) {
                            filled_opening.value().push_back(
                                fill_merkle_proof<typename LPCScheme::openning_type, Endianness>(c));
                        }
                        filled_alpha_openings.value().push_back(filled_opening);
                    }

                    // std::array<std::array<merkle_proof_type, r>, lambda> f_y_openings
                    merkle_proof_vector_vector_marshalling_type filled_f_y_openings;
                    for (const auto &openings : lpc_prf.f_y_openings) {
                        merkle_proof_vector_marshalling_type filled_opening;
                        for (const auto &c : openings) {
                            filled_opening.value().push_back(
                                fill_merkle_proof<typename LPCScheme::openning_type, Endianness>(c));
                        }
                        filled_f_y_openings.value().push_back(filled_opening);
                    }

                    // std::array<std::array<commitment_type, r - 1>, lambda> f_commitments
                    digest_vector_vector_marshalling_type filled_f_commitments;
                    for (const auto &commitments : lpc_prf.f_commitments) {
                        digest_vector_marshalling_type filled_commitments;
                        for (const auto &c : commitments) {
                            digest_marshalling_type filled_digest;
                            for (const auto c_i : c) {
                                filled_digest.value().push_back(octet_marshalling_type(c_i));
                            }
                            filled_commitments.value().push_back(filled_digest);
                        }
                        filled_f_commitments.value().push_back(filled_commitments);
                    }

                    // std::array<math::polynomial<typename FieldType::value_type>, lambda>
                    //  f_ip1_coefficients
                    field_poly_vector_marshalling_type filled_f_ip1_coefficients;
                    for (const auto &poly : lpc_prf.f_ip1_coefficients) {
                        field_poly_marshalling_type filled_poly;
                        for (const auto &c : poly) {
                            filled_poly.value().push_back(
                                fill_field_element<typename LPCScheme::field_type, Endianness>(c));
                        }
                        filled_f_ip1_coefficients.value().push_back(filled_poly);
                    }

                    return lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme>(
                        std::make_tuple(filled_z_openings,
                                        filled_alpha_openings,
                                        filled_f_y_openings,
                                        filled_f_commitments,
                                        filled_f_ip1_coefficients));
                }

                template<typename LPCScheme, typename Endianness>
                typename LPCScheme::proof_type make_lpc_proof(
                    const lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme> &filled_lpc_prf) {

                    typename LPCScheme::proof_type lpc_prf;

                    // std::array<merkle_proof_type, k> z_openings
                    assert(lpc_prf.z_openings.size() == std::get<0>(filled_lpc_prf.value()).value().size());
                    for (std::size_t i = 0; i < std::get<0>(filled_lpc_prf.value()).value().size(); ++i) {
                        lpc_prf.z_openings.at(i) = make_merkle_proof<typename LPCScheme::openning_type, Endianness>(
                            std::get<0>(filled_lpc_prf.value()).value().at(i));
                    }

                    // std::array<std::array<merkle_proof_type, m * r>, lambda> alpha_openings
                    assert(lpc_prf.alpha_openings.size() == std::get<1>(filled_lpc_prf.value()).value().size());
                    for (std::size_t i = 0; i < std::get<1>(filled_lpc_prf.value()).value().size(); ++i) {
                        assert(lpc_prf.alpha_openings.at(i).size() ==
                               std::get<1>(filled_lpc_prf.value()).value().at(i).value().size());
                        for (std::size_t j = 0; j < std::get<1>(filled_lpc_prf.value()).value().at(i).value().size();
                             ++j) {
                            lpc_prf.alpha_openings.at(i).at(j) =
                                make_merkle_proof<typename LPCScheme::openning_type, Endianness>(
                                    std::get<1>(filled_lpc_prf.value()).value().at(i).value().at(j));
                        }
                    }

                    // std::array<std::array<merkle_proof_type, r>, lambda> f_y_openings
                    assert(lpc_prf.f_y_openings.size() == std::get<2>(filled_lpc_prf.value()).value().size());
                    for (std::size_t i = 0; i < std::get<2>(filled_lpc_prf.value()).value().size(); ++i) {
                        assert(lpc_prf.f_y_openings.at(i).size() ==
                               std::get<2>(filled_lpc_prf.value()).value().at(i).value().size());
                        for (std::size_t j = 0; j < std::get<2>(filled_lpc_prf.value()).value().at(i).value().size();
                             ++j) {
                            lpc_prf.f_y_openings.at(i).at(j) =
                                make_merkle_proof<typename LPCScheme::openning_type, Endianness>(
                                    std::get<2>(filled_lpc_prf.value()).value().at(i).value().at(j));
                        }
                    }

                    // std::array<std::array<commitment_type, r - 1>, lambda> f_commitments
                    assert(lpc_prf.f_commitments.size() == std::get<3>(filled_lpc_prf.value()).value().size());
                    for (std::size_t i = 0; i < std::get<3>(filled_lpc_prf.value()).value().size(); ++i) {
                        assert(lpc_prf.f_commitments.at(i).size() ==
                               std::get<3>(filled_lpc_prf.value()).value().at(i).value().size());
                        for (std::size_t j = 0; j < std::get<3>(filled_lpc_prf.value()).value().at(i).value().size();
                             ++j) {
                            assert(lpc_prf.f_commitments.at(i).at(j).size() ==
                                   std::get<3>(filled_lpc_prf.value()).value().at(i).value().at(j).value().size());
                            for (std::size_t k = 0;
                                 k < std::get<3>(filled_lpc_prf.value()).value().at(i).value().at(j).value().size();
                                 ++k) {
                                lpc_prf.f_commitments.at(i).at(j).at(k) = std::get<3>(filled_lpc_prf.value())
                                                                              .value()
                                                                              .at(i)
                                                                              .value()
                                                                              .at(j)
                                                                              .value()
                                                                              .at(k)
                                                                              .value();
                            }
                        }
                    }

                    // std::array<math::polynomial<typename FieldType::value_type>, lambda>
                    //  f_ip1_coefficients
                    assert(lpc_prf.f_ip1_coefficients.size() == std::get<4>(filled_lpc_prf.value()).value().size());
                    for (std::size_t i = 0; i < std::get<4>(filled_lpc_prf.value()).value().size(); ++i) {
                        std::vector<typename LPCScheme::field_type::value_type> poly_coeffs;
                        for (std::size_t j = 0; j < std::get<4>(filled_lpc_prf.value()).value().at(i).value().size();
                             ++j) {
                            poly_coeffs.push_back(
                                std::get<4>(filled_lpc_prf.value()).value().at(i).value().at(j).value());
                        }
                        lpc_prf.f_ip1_coefficients.at(i) = typename decltype(lpc_prf.f_ip1_coefficients)::value_type(
                            std::cbegin(poly_coeffs), std::cend(poly_coeffs));
                    }

                    return lpc_prf;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP
