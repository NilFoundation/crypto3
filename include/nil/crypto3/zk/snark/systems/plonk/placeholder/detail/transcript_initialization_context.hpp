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

#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

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

                        using commitment_scheme_type = typename PlaceholderParamsType::commitment_scheme_type;
                        using transcript_type = typename commitment_scheme_type::transcript_type;
                        using transcript_hash_type = typename commitment_scheme_type::transcript_hash_type;

                        transcript_initialization_context() = default;
                        transcript_initialization_context(
                                std::size_t rows_amount,
                                std::size_t usable_rows_amount,
                                const typename commitment_scheme_type::params_type& commitment_params,
                                const plonk_table_description<field_type>& table_description,
                                const std::string& application_id,
                                const typename field_type::value_type& delta)
                            : witness_columns(table_description.witness_columns)
                            , public_input_columns(table_description.public_input_columns)
                            , constant_columns(table_description.constant_columns)
                            , selector_columns(table_description.selector_columns)
                            , rows_amount(rows_amount)
                            , usable_rows_amount(usable_rows_amount)
                            , delta(delta)
                            , commitment_params(commitment_params)
                            , application_id(application_id)
                        { }

                        // All fields below this line must be included in the transcript initilization, including
                        // static const fields.

                        std::size_t witness_columns;
                        std::size_t public_input_columns;
                        std::size_t constant_columns;
                        std::size_t selector_columns;

                        std::size_t rows_amount;
                        std::size_t usable_rows_amount;

                        // Commitment params. All fields of this data structure must be included on marshalling,
                        // including some static constexpr parameters.
                        const typename field_type::value_type delta;
                        typename commitment_scheme_type::params_type commitment_params;

                        constexpr static const typename field_type::value_type modulus = field_type::modulus;

                        // Some application dependent string.
                        std::string application_id;
                    };

                    template <typename PlaceholderParamsType, typename transcript_hash_type>
                    typename transcript_hash_type::digest_type compute_constraint_system_with_params_hash(
                            const plonk_constraint_system<typename PlaceholderParamsType::field_type>
                                &constraint_system,
                            const plonk_table_description<typename PlaceholderParamsType::field_type>
                                &table_description,
                            std::size_t rows_amount,
                            std::size_t usable_rows_amount,
                            const typename PlaceholderParamsType::commitment_scheme_type::params_type& commitment_params,
                            const std::string& application_id,
                            const typename PlaceholderParamsType::field_type::value_type& delta) {
                        nil::crypto3::zk::snark::detail::transcript_initialization_context<PlaceholderParamsType> context(
                            rows_amount,
                            usable_rows_amount,
                            commitment_params,
                            table_description,
                            application_id,
                            delta
                        );

                        // Marshall the initialization context and push it to the transcript.
                        using Endianness = nil::marshalling::option::big_endian;
                        auto filled_context = nil::crypto3::marshalling::types::fill_transcript_initialization_context<
                            Endianness, nil::crypto3::zk::snark::detail::transcript_initialization_context<PlaceholderParamsType>>(context);

                        std::vector<std::uint8_t> cv(filled_context.length(), 0x00);
                        auto write_iter = cv.begin();
                        nil::marshalling::status_type status = filled_context.write(write_iter, cv.size());
                        BOOST_ASSERT(status == nil::marshalling::status_type::success);

                        // Append constraint_system to the buffer "cv".
                        using FieldType = typename PlaceholderParamsType::field_type;
                        using ConstraintSystem = plonk_constraint_system<FieldType>;

                        auto filled_constraint_system = nil::crypto3::marshalling::types::fill_plonk_constraint_system<Endianness, ConstraintSystem>(constraint_system);
                        cv.resize(filled_context.length() + filled_constraint_system.length(), 0x00);

                        // Function write wants an lvalue as 1st parameter.
                        write_iter = cv.begin() + filled_context.length();
                        filled_constraint_system.write(write_iter, filled_constraint_system.length());

                        // Return hash of "cv", which contains concatenated constraint system and other initialization parameters.
                        return hash<transcript_hash_type>(cv);
                    }
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PLONK_PLACEHOLDER_TRANSCRIPT_INITIALIZATION_CONTEXT_HPP
