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

#ifndef CRYPTO3_ZK_PLONK_GATE_HPP
#define CRYPTO3_ZK_PLONK_GATE_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /************************* PLONK constraint ***********************************/

                template<typename FieldType>
                using plonk_constraint = non_linear_combination<FieldType, true>;

                /************************* PLONK gate ***********************************/

                template <typename FieldType>
                struct plonk_gate{
                    math::polynomial<typename FieldType::value_type> selector;
                    std::vector<plonk_constraint<FieldType>> constraints;

                    plonk_gate(math::polynomial<typename FieldType::value_type> &selector,
                                  const std::vector<plonk_constraint<FieldType>> &constraints): 
                        constraints(constraints), selector(selector) {
                    }

                    plonk_gate(std::size_t row_index, const snark::plonk_constraint<FieldType> &constraint):
                        constraints(std::vector<plonk_constraint<FieldType>> ({constraint})){

                        selector = math::polynomial<typename FieldType::value_type>();
                    }

                    plonk_gate(std::size_t row_index,
                                  const std::initializer_list<snark::plonk_constraint<FieldType>> &constraints): 
                        constraints(constraints){

                        selector = math::polynomial<typename FieldType::value_type>();
                    }

                    plonk_gate(std::initializer_list<std::size_t> row_indices,
                                  const snark::plonk_constraint<FieldType> &constraint):
                        constraints(std::vector<plonk_constraint<FieldType>> ({constraint})), selector() {

                        selector = math::polynomial<typename FieldType::value_type>();
                    }

                    plonk_gate(std::initializer_list<std::size_t> row_indices,
                                  const std::initializer_list<snark::plonk_constraint<FieldType>> &constraints):
                        constraints(constraints), selector() {

                        selector = math::polynomial<typename FieldType::value_type>();
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_GATE_HPP