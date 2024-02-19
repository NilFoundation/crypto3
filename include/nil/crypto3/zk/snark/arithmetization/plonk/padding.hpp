//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PADDING_HPP
#define CRYPTO3_ZK_PLONK_PADDING_HPP

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename ColumnType>
                class plonk_table;

                template<typename FieldType, typename ColumnType>
                std::uint32_t basic_padding(plonk_table<FieldType, ColumnType> &table) {
                    std::uint32_t usable_rows_amount = table.rows_amount();

                    std::uint32_t padded_rows_amount = std::pow(2, std::ceil(std::log2(usable_rows_amount)));
                    if (padded_rows_amount == usable_rows_amount)
                        padded_rows_amount *= 2;

                    if (padded_rows_amount < 8)
                        padded_rows_amount = 8;

                    for (std::uint32_t w_index = 0; w_index <
                                                   table._private_table.witnesses_amount(); w_index++) {

                        table._private_table._witnesses[w_index].resize(padded_rows_amount,
                                                                    FieldType::value_type::zero());
                    }

                    for (std::uint32_t pi_index = 0; pi_index <
                                                   table._public_table.public_inputs_amount(); pi_index++) {

                        table._public_table._public_inputs[pi_index].resize(padded_rows_amount,
                                                                    FieldType::value_type::zero());
                    }

                    for (std::uint32_t c_index = 0; c_index <
                                                  table._public_table.constants_amount(); c_index++) {

                        table._public_table._constants[c_index].resize(padded_rows_amount,
                                                                    FieldType::value_type::zero());
                    }

                    for (std::uint32_t s_index = 0; s_index <
                                                  table._public_table.selectors_amount(); s_index++) {

                        table._public_table._selectors[s_index].resize(padded_rows_amount,
                                                                    FieldType::value_type::zero());
                    }

                    return padded_rows_amount;
                }


                template<typename FieldType, typename ColumnType>
                std::uint32_t zk_padding(
                    plonk_table<FieldType, ColumnType> &table,
                    typename nil::crypto3::random::algebraic_engine<FieldType> alg_rnd = nil::crypto3::random::algebraic_engine<FieldType>()
                ) {
                    std::uint32_t usable_rows_amount = table.rows_amount();

                    std::uint32_t padded_rows_amount = std::pow(2, std::ceil(std::log2(usable_rows_amount)));
                    if (padded_rows_amount == usable_rows_amount)
                        padded_rows_amount *= 2;

                    if (padded_rows_amount < 8)
                        padded_rows_amount = 8;

                    //std::cout << "usable_rows_amount = " << usable_rows_amount << std::endl;
                    //std::cout << "padded_rows_amount = " << padded_rows_amount << std::endl;

                    for (std::uint32_t w_index = 0; w_index < table._private_table.witnesses_amount(); w_index++) {
                        table._private_table._witnesses[w_index].resize(usable_rows_amount, FieldType::value_type::zero());
                    }

                    for (std::uint32_t pi_index = 0; pi_index < table._public_table.public_inputs_amount(); pi_index++) {
                        table._public_table._public_inputs[pi_index].resize(usable_rows_amount, FieldType::value_type::zero());
                    }

                    for (std::uint32_t c_index = 0; c_index < table._public_table.constants_amount(); c_index++) {
                        table._public_table._constants[c_index].resize(usable_rows_amount, FieldType::value_type::zero());
                    }

                    for (std::uint32_t s_index = 0; s_index < table._public_table.selectors_amount(); s_index++) {
                        table._public_table._selectors[s_index].resize(usable_rows_amount, FieldType::value_type::zero());
                    }


                    for (std::uint32_t w_index = 0; w_index < table._private_table.witnesses_amount(); w_index++) {
                        table._private_table._witnesses[w_index].resize(padded_rows_amount);
                        for(std::size_t i = usable_rows_amount; i < padded_rows_amount; i++) {
                            table._private_table._witnesses[w_index][i] = alg_rnd();
                        }
                    }

                    for (std::uint32_t pi_index = 0; pi_index < table._public_table.public_inputs_amount(); pi_index++) {
                        table._public_table._public_inputs[pi_index].resize(padded_rows_amount, FieldType::value_type::zero());
                    }

                    for (std::uint32_t c_index = 0; c_index < table._public_table.constants_amount(); c_index++) {
                        table._public_table._constants[c_index].resize(padded_rows_amount);
                        for(std::size_t i = usable_rows_amount; i < padded_rows_amount; i++) {
                            table._public_table._constants[c_index][i] = alg_rnd();
                        }
                    }

                    for (std::uint32_t s_index = 0; s_index < table._public_table.selectors_amount(); s_index++) {
                        table._public_table._selectors[s_index].resize(padded_rows_amount);
                        for(std::size_t i = usable_rows_amount; i < padded_rows_amount; i++) {
                            table._public_table._selectors[s_index][i] = alg_rnd();
                        }
                    }

                    return padded_rows_amount;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PADDING_HPP
