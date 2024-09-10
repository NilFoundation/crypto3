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

#include <nil/blueprint/zkevm/util/bit_tags.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Chunks are not range checked here
            template<typename BlueprintFieldType>
            std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>>
            lexicographic_constraints(
                const std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &chunk_columns,
                const std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &indices_columns,
                const crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &diff
            ){
                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                std::vector<constraint_type> constraints;

                for(int i = 0; i < chunk_columns.size(); i++){
                    constraint_type dyn_selector = bit_tag_selector<BlueprintFieldType>(indices_columns, i);
                    std::cout << "Lexicographic constraints " << i << ": " << dyn_selector << std::endl;
                    for(int j = 0; j < i; j++){
                        var chunk = chunk_columns[j];
                        var chunk_prev (chunk_columns[j].index, -1, true);
                        constraints.push_back(dyn_selector * (chunk - chunk_prev));
                        //std::cout << "\t" << dyn_selector * (chunk - chunk_prev) << std::endl;
                    }
                    var chunk = chunk_columns[i];
                    var chunk_prev (chunk_columns[i].index, -1, true);
                    constraints.push_back(dyn_selector * (chunk - chunk_prev - diff));
                }

                return constraints;
            }
        }
    }
}