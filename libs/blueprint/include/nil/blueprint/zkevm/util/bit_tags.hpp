//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#pragma once

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/lookup_library.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // This is utils for compressing bit-selectors
            // Assume that we have tag column with 0..N-1 options.
            // They may be packed in ceil(log2(N)) selector columns.

            template<typename BlueprintFieldType>
            std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>>
            bit_tag_constraints(
                const std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &bit_columns,
                typename BlueprintFieldType::integral_type N   // Maximum value
            ){
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                BOOST_ASSERT_MSG((1 << bit_columns.size())  > N, "Not enough columns for tag decomposition");

                std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> result;

                // Result of decomposition should be less than N
                typename BlueprintFieldType::integral_type mask = (1 << bit_columns.size());
                constraint_type prefix;
                bool first = true;
                for(std::size_t i = 0; i < bit_columns.size(); i++){
                    mask >>= 1;
                    if( mask > N ){
                        result.push_back(bit_columns[i]);                       // if N < mask, bit column from mask should be 0
                        continue;
                    }
                    result.push_back(bit_columns[i] * (bit_columns[i] - 1));    // overwise bit colums are with 0 or 1-s
                    if( mask & N ){
                        if( first ) {
                            first = false;
                            prefix = bit_columns[i];
                        } else {
                            prefix *= bit_columns[i];                      // if N-th bit is all comparing relations will be on put on this case
                        }
                    } else {
                        result.push_back(prefix * bit_columns[i]);    // for prefix this column should be 0
                    }
                }
                return result;
            }

            template <typename BlueprintFieldType>
            crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
            bit_tag_selector(
                const std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &bit_columns,
                std::size_t k
            ){
                crypto3::zk::snark::plonk_constraint<BlueprintFieldType> result;
                typename BlueprintFieldType::integral_type mask = (1 << bit_columns.size());
                bool first = true;
                for( std::size_t i = 0; i < bit_columns.size(); i++ ){
                    mask >>= 1;
                    if( first ){
                        first = false;
                        result = (((mask & k) == 0)?(1 - bit_columns[i]) :  bit_columns[i]);
                    } else
                        result*= (((mask & k) == 0)?(1 - bit_columns[i]) :  bit_columns[i]);
                }

                return result;
            }

            template <typename BlueprintFieldType>
            crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
            bit_tag_composition(
                const std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &bit_columns,
                const crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &k
            ){
                crypto3::zk::snark::plonk_constraint<BlueprintFieldType> result;
                typename BlueprintFieldType::integral_type mask = (1 << bit_columns.size());

                for( std::size_t i = 0; i < bit_columns.size(); i++ ){
                    mask >>= 1;
                    result *= 2;
                    result += bit_columns[i];
                }
                result -= k;

                return result;
            }
        }
    }
}
