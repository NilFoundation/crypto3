//---------------------------------------------------------------------------//
// Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
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
// @file Declaration of a struct used to initialize a transcript in the beginning of the prover.
//
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PLONK_PLACEHOLDER_TRANSCRIPT_INITIALIZATION_CONTEXT_HPP
#define CRYPTO3_PLONK_PLACEHOLDER_TRANSCRIPT_INITIALIZATION_CONTEXT_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

#include <nil/crypto3/marshalling/zk/types/placeholder/transcript_initialization_context.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {
                    template<typename PlaceholderParamsType>
                    struct transcript_initialization_context {

                        typedef typename PlaceholderParamsType::field_type field_type;
                        typedef PlaceholderParamsType placeholder_params_type;

                        using arithmetization_params = typename PlaceholderParamsType::arithmetization_params;
                        using commitment_scheme_type = typename PlaceholderParamsType::commitment_scheme_type;
                        using transcript_type = typename commitment_scheme_type::transcript_type;
                        using transcript_hash_type = typename commitment_scheme_type::transcript_hash_type;

                        transcript_initialization_context() = default;
                        transcript_initialization_context(
                                std::size_t rows_amount,
                                std::size_t usable_rows_amount,
                                const typename commitment_scheme_type::params_type& commitment_params,
                                const std::string& application_id)
                            : rows_amount(rows_amount)
                            , usable_rows_amount(usable_rows_amount)
                            , commitment_params(commitment_params)
                            , application_id(application_id)
                        { }
 
                        // All fields below this line must be included in the transcript initilization, including
                        // static const fields.

                        constexpr static const std::size_t witness_columns = PlaceholderParamsType::witness_columns;
                        constexpr static const std::size_t public_input_columns = PlaceholderParamsType::public_input_columns;
                        constexpr static const std::size_t constant_columns = PlaceholderParamsType::constant_columns;
                        constexpr static const std::size_t selector_columns = PlaceholderParamsType::selector_columns;

                        constexpr static const typename field_type::value_type delta = PlaceholderParamsType::delta;
 
                        std::size_t rows_amount;
                        std::size_t usable_rows_amount;

                        // Commitment params. All fields of this data structure must be included on marshalling,
                        // including some static constexpr parameters.
                        typename commitment_scheme_type::params_type commitment_params;

                        constexpr static const typename field_type::value_type modulus = field_type::modulus;

                        // Some application dependent string.
                        std::string application_id;
                    };

                    template <typename PlaceholderParamsType, typename transcript_hash_type>
                    void init_transcript(
                            transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>& transcript,
                            std::size_t rows_amount,
                            std::size_t usable_rows_amount,
                            const typename PlaceholderParamsType::commitment_scheme_type::params_type& commitment_params,
                            const std::string& application_id) {
                        nil::crypto3::zk::snark::detail::transcript_initialization_context<PlaceholderParamsType> context(
                            rows_amount,
                            usable_rows_amount,
                            commitment_params,
                            application_id
                        );

                        // Marshall the initialization context and push it to the transcript.
                        using Endianness = nil::marshalling::option::big_endian;
                        using TTypeBase = nil::marshalling::field_type<Endianness>;
                        using value_marshalling_type = nil::crypto3::marshalling::types::transcript_initialization_context<
                            TTypeBase, nil::crypto3::zk::snark::detail::transcript_initialization_context<PlaceholderParamsType>>;
                        auto filled_val = nil::crypto3::marshalling::types::fill_transcript_initialization_context<
                            Endianness, nil::crypto3::zk::snark::detail::transcript_initialization_context<PlaceholderParamsType>>(context);

                        std::vector<std::uint8_t> cv(filled_val.length(), 0x00);
                        auto write_iter = cv.begin();
                        nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());

                        transcript(cv);
                    }
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PLONK_PLACEHOLDER_TRANSCRIPT_INITIALIZATION_CONTEXT_HPP
