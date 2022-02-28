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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_N_WIRES_HELPER_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_N_WIRES_HELPER_HPP

#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                namespace detail {

                    template<typename ArithmetizationType,
                        std::size_t... WireIndexes>
                    class n_wires_helper;

                    template<typename BlueprintFieldType,
                        std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, 
                        std::size_t W4>
                    class n_wires_helper<snark::plonk_constraint_system<BlueprintFieldType>, 
                        W0, W1, W2, W3, W4>: 
                        public component<snark::plonk_constraint_system<BlueprintFieldType>> {

                        typedef snark::plonk_constraint_system<BlueprintFieldType> ArithmetizationType;
                        typedef blueprint<ArithmetizationType> blueprint_type;

                        using variable_type = snark::plonk_variable<BlueprintFieldType>;
                    public:

                        n_wires_helper(blueprint_type &bp):component<ArithmetizationType>(bp){}

                        constexpr static const std::array<std::array<typename blueprint_type::value_type, 5>,5> w = {{
                            {{
                                variable_type(W0, 
                                blueprint_type::value_type::rotation_type::pre_previous),
                                variable_type(W0, 
                                blueprint_type::value_type::rotation_type::previous),
                                variable_type(W0, 
                                blueprint_type::value_type::rotation_type::current),
                                variable_type(W0, 
                                blueprint_type::value_type::rotation_type::next),
                                variable_type(W0, 
                                blueprint_type::value_type::rotation_type::after_next)
                            }},
                            {{
                                variable_type(W1, 
                                blueprint_type::value_type::rotation_type::pre_previous),
                                variable_type(W1, 
                                blueprint_type::value_type::rotation_type::previous),
                                variable_type(W1, 
                                blueprint_type::value_type::rotation_type::current),
                                variable_type(W1, 
                                blueprint_type::value_type::rotation_type::next),
                                variable_type(W1, 
                                blueprint_type::value_type::rotation_type::after_next)
                            }},
                            {{
                                variable_type(W2, 
                                blueprint_type::value_type::rotation_type::pre_previous),
                                variable_type(W2, 
                                blueprint_type::value_type::rotation_type::previous),
                                variable_type(W2, 
                                blueprint_type::value_type::rotation_type::current),
                                variable_type(W2, 
                                blueprint_type::value_type::rotation_type::next),
                                variable_type(W2, 
                                blueprint_type::value_type::rotation_type::after_next)
                            }},
                            {{
                                variable_type(W3, 
                                blueprint_type::value_type::rotation_type::pre_previous),
                                variable_type(W3, 
                                blueprint_type::value_type::rotation_type::previous),
                                variable_type(W3, 
                                blueprint_type::value_type::rotation_type::current),
                                variable_type(W3, 
                                blueprint_type::value_type::rotation_type::next),
                                variable_type(W3, 
                                blueprint_type::value_type::rotation_type::after_next)
                            }},
                            {{
                                variable_type(W4, 
                                blueprint_type::value_type::rotation_type::pre_previous),
                                variable_type(W4, 
                                blueprint_type::value_type::rotation_type::previous),
                                variable_type(W4, 
                                blueprint_type::value_type::rotation_type::current),
                                variable_type(W4, 
                                blueprint_type::value_type::rotation_type::next),
                                variable_type(W4, 
                                blueprint_type::value_type::rotation_type::after_next)
                            }}
                        }};
                    };

                    template<typename BlueprintFieldType,
                        std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                        std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7,
                        std::size_t W8>
                    class n_wires_helper<snark::plonk_constraint_system<BlueprintFieldType>, 
                        W0, W1, W2, W3, W4, W5, W6, W7, W8>: 
                        public component<snark::plonk_constraint_system<BlueprintFieldType>> {

                        typedef snark::plonk_constraint_system<BlueprintFieldType> ArithmetizationType;
                        typedef blueprint<ArithmetizationType> blueprint_type;

                        using variable_type = snark::plonk_variable<BlueprintFieldType>;
                    public:

                        n_wires_helper(blueprint_type &bp):component<ArithmetizationType>(bp){}

                        constexpr static const std::array<std::array<typename blueprint_type::value_type, 5>,9> w = {{
                            {{
                                typename blueprint_type::value_type (W0, 
                                blueprint_type::value_type::rotation_type::pre_previous),
                                typename blueprint_type::value_type(W0, 
                                blueprint_type::value_type::rotation_type::previous),
                                typename blueprint_type::value_type(W0, 
                                blueprint_type::value_type::rotation_type::current),
                                typename blueprint_type::value_type(W0, 
                                blueprint_type::value_type::rotation_type::next),
                                typename blueprint_type::value_type(W0, 
                                blueprint_type::value_type::rotation_type::after_next)
                            }},
                            {{
                                typename blueprint_type::value_type (W1, 
                                blueprint_type::value_type::rotation_type::pre_previous),
                                typename blueprint_type::value_type(W1, 
                                blueprint_type::value_type::rotation_type::previous),
                                typename blueprint_type::value_type(W1, 
                                blueprint_type::value_type::rotation_type::current),
                                typename blueprint_type::value_type(W1, 
                                blueprint_type::value_type::rotation_type::next),
                                typename blueprint_type::value_type(W1, 
                                blueprint_type::value_type::rotation_type::after_next)
                            }},
                            {{
                                typename blueprint_type::value_type (W2, 
                                blueprint_type::value_type::rotation_type::pre_previous),
                                typename blueprint_type::value_type(W2, 
                                blueprint_type::value_type::rotation_type::previous),
                                typename blueprint_type::value_type(W2, 
                                blueprint_type::value_type::rotation_type::current),
                                typename blueprint_type::value_type(W2, 
                                blueprint_type::value_type::rotation_type::next),
                                typename blueprint_type::value_type(W2, 
                                blueprint_type::value_type::rotation_type::after_next)
                            }},
                            {{
                                typename blueprint_type::value_type (W3, 
                                blueprint_type::value_type::rotation_type::pre_previous),
                                typename blueprint_type::value_type(W3, 
                                blueprint_type::value_type::rotation_type::previous),
                                typename blueprint_type::value_type(W3, 
                                blueprint_type::value_type::rotation_type::current),
                                typename blueprint_type::value_type(W3, 
                                blueprint_type::value_type::rotation_type::next),
                                typename blueprint_type::value_type(W3, 
                                blueprint_type::value_type::rotation_type::after_next)
                            }},
                            {{
                                typename blueprint_type::value_type (W4, 
                                blueprint_type::value_type::rotation_type::pre_previous),
                                typename blueprint_type::value_type(W4, 
                                blueprint_type::value_type::rotation_type::previous),
                                typename blueprint_type::value_type(W4, 
                                blueprint_type::value_type::rotation_type::current),
                                typename blueprint_type::value_type(W4, 
                                blueprint_type::value_type::rotation_type::next),
                                typename blueprint_type::value_type(W4, 
                                blueprint_type::value_type::rotation_type::after_next)
                            }},
                            {{
                                typename blueprint_type::value_type (W5, 
                                blueprint_type::value_type::rotation_type::pre_previous),
                                typename blueprint_type::value_type(W5, 
                                blueprint_type::value_type::rotation_type::previous),
                                typename blueprint_type::value_type(W5, 
                                blueprint_type::value_type::rotation_type::current),
                                typename blueprint_type::value_type(W5, 
                                blueprint_type::value_type::rotation_type::next),
                                typename blueprint_type::value_type(W5, 
                                blueprint_type::value_type::rotation_type::after_next)
                            }},
                            {{
                                typename blueprint_type::value_type (W6, 
                                blueprint_type::value_type::rotation_type::pre_previous),
                                typename blueprint_type::value_type(W6, 
                                blueprint_type::value_type::rotation_type::previous),
                                typename blueprint_type::value_type(W6, 
                                blueprint_type::value_type::rotation_type::current),
                                typename blueprint_type::value_type(W6, 
                                blueprint_type::value_type::rotation_type::next),
                                typename blueprint_type::value_type(W6, 
                                blueprint_type::value_type::rotation_type::after_next)
                            }},
                            {{
                                typename blueprint_type::value_type (W7, 
                                blueprint_type::value_type::rotation_type::pre_previous),
                                typename blueprint_type::value_type(W7, 
                                blueprint_type::value_type::rotation_type::previous),
                                typename blueprint_type::value_type(W7, 
                                blueprint_type::value_type::rotation_type::current),
                                typename blueprint_type::value_type(W7, 
                                blueprint_type::value_type::rotation_type::next),
                                typename blueprint_type::value_type(W7, 
                                blueprint_type::value_type::rotation_type::after_next)
                            }},
                            {{
                                typename blueprint_type::value_type (W8, 
                                blueprint_type::value_type::rotation_type::pre_previous),
                                typename blueprint_type::value_type(W8, 
                                blueprint_type::value_type::rotation_type::previous),
                                typename blueprint_type::value_type(W8, 
                                blueprint_type::value_type::rotation_type::current),
                                typename blueprint_type::value_type(W8, 
                                blueprint_type::value_type::rotation_type::next),
                                typename blueprint_type::value_type(W8, 
                                blueprint_type::value_type::rotation_type::after_next)
                            }}
                        }};
                    };

                    template<typename BlueprintFieldType,
                        std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                        std::size_t W4>
                    constexpr std::array<std::array<
                        typename blueprint<snark::plonk_constraint_system<BlueprintFieldType>>::value_type, 5>,5>
                        const n_wires_helper<snark::plonk_constraint_system<BlueprintFieldType>,
                        W0, W1, W2, W3, W4>::w;

                    template<typename BlueprintFieldType,
                        std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                        std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7,
                        std::size_t W8>
                    constexpr std::array<std::array<
                        typename blueprint<snark::plonk_constraint_system<BlueprintFieldType>>::value_type, 5>,9>
                        const n_wires_helper<snark::plonk_constraint_system<BlueprintFieldType>,
                        W0, W1, W2, W3, W4, W5, W6, W7, W8>::w;

                }    // namespace detail
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_N_WIRES_HELPER_HPP
