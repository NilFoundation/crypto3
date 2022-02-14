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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_EDDSA_9_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_EDDSA_9_WIRES_HPP


#include <nil/crypto3/math/detail/field_utils.hpp>

#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/component.hpp>
#include <nil/crypto3/zk/components/detail/plonk/n_wires.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename TArithmetization,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class eddsa_verifier_plonk;

                template<typename TBlueprintField,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8>
                class eddsa_verifier_plonk<snark::plonk_constraint_system<TBlueprintField, 9>,
                                                       CurveType,
                                                       W0,
                                                       W1,
                                                       W2,
                                                       W3,
                                                       W4,
                                                       W5,
                                                       W6,
                                                       W7,
                                                       W8>
                    : public detail::
                          n_wires_helper<snark::plonk_constraint_system<TBlueprintField, 9>, 
                          W0, W1, W2, W3, W4, W5, W6, W7, W8> {

                    typedef snark::plonk_constraint_system<TBlueprintField, 9> TArithmetization;
                    typedef blueprint<TArithmetization> blueprint_type;

                    std::size_t j;
                    typename CurveType::template g1_type<>::value_type B;

                    using n_wires_helper =
                        detail::n_wires_helper<snark::plonk_constraint_system<TBlueprintField, 9>, 
                        W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                    using n_wires_helper::w;
                    enum indices { m2 = 0, m1, cur, p1, p2 };

                    constexpr static const std::size_t L = 
                        math::detail::power_of_two(252) + 27742317777372353535851937790883648493;

                public:
                    eddsa_verifier_plonk(blueprint_type &bp,
                        std::pair<typename CurveType::value_type, typename CurveType> signature,
                        typename CurveType::value_type M,
                        typename CurveType::value_type A,
                        typename CurveType::value_type B) :
                    {}

                    void generate_gates() {

                    }

                    void generate_assignments(){

                    }

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_EDDSA_9_WIRES_HPP
