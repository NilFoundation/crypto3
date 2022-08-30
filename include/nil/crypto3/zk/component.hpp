//---------------------------------------------------------------------------//
// Copyright (c) 2020-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_COMPONENT_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {

            template<typename ArithmetizationType, std::size_t... BlueprintParams>
            class blueprint;

            namespace components {

                template<typename ArithmetizationType, std::uint32_t... ComponentTemplateParams>
                class component;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount>
                class component<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount> {
                protected:

                    using witness_container_type = std::array<std::uint32_t, WitnessAmount>;
                    witness_container_type _W;

                    std::uint32_t _gates_amount;
                    std::uint32_t _rows_amount;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    typename witness_container_type::value_type W(std::uint32_t index) const {
                        return _W[index];
                    }

                public:

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    template <typename ContainerType>
                    component(ContainerType wires, std::uint32_t rows_amount, std::uint32_t gates_amount) :
                        _rows_amount(rows_amount), _gates_amount(gates_amount) {
                        std::copy_n(std::make_move_iterator(wires.begin()), WitnessAmount, _W.begin());
                    }

                    std::uint32_t rows_amount() const {
                        return _rows_amount;
                    }

                    std::uint32_t gates_amount() const {
                        return _gates_amount;
                    }
                };

                template<typename BlueprintFieldType>
                class component<snark::r1cs_constraint_system<BlueprintFieldType>> {
                protected:

                    typedef snark::r1cs_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    blueprint<ArithmetizationType> &bp;

                public:
                    component(blueprint<ArithmetizationType> &bp) : bp(bp) {
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_COMPONENT_HPP
