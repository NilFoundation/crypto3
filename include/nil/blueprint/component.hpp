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

#ifndef CRYPTO3_BLUEPRINT_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENT_HPP

#include <string>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/constraint_satisfaction_problems/r1cs.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/assert.hpp>

namespace nil {
    namespace blueprint {

        template<typename ArithmetizationType, std::size_t... BlueprintParams>
        class blueprint;

        namespace components {

            template<typename ArithmetizationType>
            class component{};

            template<typename BlueprintFieldType, typename ArithmetizationParams,
                     std::uint32_t ConstantAmount, std::uint32_t PublicInputAmount>
            class plonk_component:
                public component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> {
            protected:

                using witness_container_type = std::vector<std::uint32_t>;
                using manifest_type = nil::blueprint::plonk_component_manifest;
            public:
                static constexpr std::size_t constants_amount = ConstantAmount;
                static constexpr std::size_t public_inputs_amount = PublicInputAmount;

                using constant_container_type = std::array<std::uint32_t, ConstantAmount>;
                using public_input_container_type = std::array<std::uint32_t, PublicInputAmount>;

                witness_container_type _W;
                constant_container_type _C;
                public_input_container_type _PI;
                // underlying_components_container_type _underlying_components;

                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                /**
                 * Get Witness column global index by its internal index.
                 *
                 * @param[in] internal witness signed index. For -1, last witness assumed.
                 */
                typename witness_container_type::value_type W(std::int32_t index) const {
                    return _W[(_W.size() + index) % _W.size()];
                }

                /**
                 * Get Constant column global index by its internal index.
                 *
                 * @param[in] internal constant signed index. For -1, last constant assumed.
                 */
                typename constant_container_type::value_type C(std::int32_t index) const {
                    return _C[(ConstantAmount + index)%ConstantAmount];
                }

                /**
                 * Get Public Input column global index by its internal index.
                 *
                 * @param[in] internal public input signed index. For -1, last public input assumed.
                 */
                typename public_input_container_type::value_type PI(std::int32_t index) const {
                    return _PI[(PublicInputAmount + index)%PublicInputAmount];
                }

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                /**
                 * Constructor from arbitrary container types.
                 *
                 * @tparam WitnessContainerType Input Witness Container Type
                 * @tparam ConstantContainerType Input Constant Container Type
                 * @tparam PublicInputContainerType Input PublicInput Container Type
                 * @param[in] witness Container with witness columns global indices.
                 * @param[in] constant Container with constant columns global indices.
                 * @param[in] public_input Container with public input columns global indices.
                 */
                template <typename WitnessContainerType, typename ConstantContainerType,
                    typename PublicInputContainerType>
                plonk_component(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, const manifest_type &manifest) {
                    _W.resize(witness.size());
                    std::copy_n(std::make_move_iterator(witness.begin()), witness.size(), _W.begin());
                    std::copy_n(std::make_move_iterator(constant.begin()), ConstantAmount, _C.begin());
                    std::copy_n(std::make_move_iterator(public_input.begin()), PublicInputAmount, _PI.begin());

                    BLUEPRINT_RELEASE_ASSERT(manifest.check_manifest(*this));
                }

                std::size_t witness_amount() const {
                    return _W.size();
                }

                std::size_t constant_amount() const {
                    return _C.size();
                }

                std::size_t public_input_amount() const {
                    return _PI.size();
                }
            };

            // namespace detail {
            //     /**
            //      * The specialized hash function for `unordered_map` PLONK component keys
            //      */
            //     struct component_hash {
            //         template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessAmount,
            //             ConstantAmount, PublicInputAmount>
            //         std::size_t operator() (const component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount,
            //                 ConstantAmount, PublicInputAmount> &node) const {

            //         }
            //     };

            // } // namespace detail


            template<typename BlueprintFieldType>
            class r1cs_component:
                public component<crypto3::zk::snark::r1cs_constraint_system<BlueprintFieldType>> {
            protected:

                typedef crypto3::zk::snark::r1cs_constraint_system<BlueprintFieldType>
                    ArithmetizationType;

                blueprint<ArithmetizationType> &bp;

            public:
                r1cs_component(blueprint<ArithmetizationType> &bp) : bp(bp) {
                }
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENT_HPP
