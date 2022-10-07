//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_CONSTRAINTS_RPN_STRING_LITERAL_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_CONSTRAINTS_RPN_STRING_LITERAL_HPP

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/rpn_expression.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/binding.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/vanishes_on_last_4_rows.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/unnormalized_lagrange_basis.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                constexpr const std::size_t count_delimiters(const char *expression) {
                    size_t i = 0;
                    size_t cnt = 0;
                    for (; expression[i] != '\0'; i++) {
                        if (expression[i] == ';') {
                            cnt++;
                        }
                    }
                    return cnt;
                }

                constexpr const std::size_t str_len(const char *expression) {
                    size_t size = 0;
                    for (; expression[size] != '\0'; size++) {
                    }
                    return size;
                }

                constexpr std::size_t find_str(const char *expression, const char *str, std::size_t n, std::size_t start_pos,
                                            std::size_t end_pos) {
                    size_t j = 0;
                    size_t i = start_pos;
                    for (; i < end_pos; i++) {
                        for (j = 0; j < n && expression[i + j] == str[j]; j++)
                            ;
                        if (j == n) {
                            return i;
                        }
                    }
                    return std::string::npos;
                }

                template<const std::size_t tokens_array_size, typename ArithmetizationType>
                constexpr size_t rpn_component_rows(const char *expression) {
                    using mul_component = zk::components::multiplication<ArithmetizationType, 0, 1, 2>;
                    using add_component = zk::components::addition<ArithmetizationType, 0, 1, 2>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, 0, 1, 2>;

                    using exponentiation_component = zk::components::exponentiation<ArithmetizationType, 64, 0, 1, 2, 3, 4, 5, 6,
                                                                                    7, 8, 9, 10, 11, 12, 13, 14>;

                    using vanishes_on_last_4_rows_component = zk::components::vanishes_on_last_4_rows<
                                        ArithmetizationType, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                                                                    11, 12, 13, 14>;

                    using unnormalized_lagrange_basis_component = zk::components::unnormalized_lagrange_basis<ArithmetizationType,
                         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

                    const std::size_t literal_string_size = str_len(expression);

                    const size_t mds_size = 3;
                    std::array<std::size_t, tokens_array_size> str_start = {};

                    std::array<std::size_t, tokens_array_size> str_end = {};
                    str_start[0] = 0;
                    str_end[tokens_array_size - 1] = literal_string_size;
                    size_t i = 0;
                    const char *alpha_c = "Alpha";
                    const char *beta_c = "Beta";
                    const char *gamma_c = "Gamma";
                    const char *joint_combiner_c = "JointCombiner";
                    const char *endo_coefficient_c = "EndoCoefficient";
                    const char *mds_c = "Mds";
                    const char *literal_c = "Literal";
                    const char *cell_c = "Cell";
                    const char *dup_c = "Dup";
                    const char *pow_c = "Pow";
                    const char *add_c = "Add";
                    const char *mul_c = "Mul";
                    const char *sub_c = "Sub";
                    const char *vanishes_on_last_4_rows_c = "VanishesOnLast4Rows";
                    const char *unnormalized_lagrange_basis_c = "UnnormalizedLagrangeBasis";
                    const char *store_c = "Store";
                    const char *load_c = "Load";
                    const char *del = ";";
                    for (i = 0; i < tokens_array_size - 1; i++) {
                        size_t pos = find_str(expression, del, 1, str_start[i], literal_string_size);
                        str_end[i] = pos;
                        str_start[i + 1] = pos + 1;
                    }
                    size_t rows = 1 + mds_size * mds_size;
                    for (i = 0; i < tokens_array_size; i++) {
                        if (find_str(expression, literal_c, 7, str_start[i], str_end[i]) != std::string::npos) {
                            rows++;
                        } else if (find_str(expression, pow_c, 3, str_start[i], str_end[i]) != std::string::npos) {
                            rows++;
                            rows += exponentiation_component::rows_amount;
                        } else if (find_str(expression, add_c, 3, str_start[i], str_end[i]) != std::string::npos) {
                            rows += add_component::rows_amount;
                        } else if (find_str(expression, mul_c, 3, str_start[i], str_end[i]) != std::string::npos) {
                            rows += mul_component::rows_amount;
                        } else if (find_str(expression, sub_c, 3, str_start[i], str_end[i]) != std::string::npos) {
                            rows += sub_component::rows_amount;
                        } else if (find_str(expression, vanishes_on_last_4_rows_c, 3, str_start[i], str_end[i]) != std::string::npos) {
                            rows += vanishes_on_last_4_rows_component::rows_amount;
                        }
                        else if (find_str(expression, unnormalized_lagrange_basis_c, 3, str_start[i], str_end[i]) != std::string::npos) {
                            rows += unnormalized_lagrange_basis_component::rows_amount;
                        }
                    }

                    return rows;
                }
            } // namespace components
        }   // namespace zk
    }     // namespace crypto3
} // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_CONSTRAINTS_RPN_STRING_LITERAL_HPP