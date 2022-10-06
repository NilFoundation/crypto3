//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_DETAIL_LOOKUP_1BIT_HPP
#define CRYPTO3_ZK_BLUEPRINT_DETAIL_LOOKUP_1BIT_HPP

#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/blueprint/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                /**
                 * One-bit window lookup table using one constraint
                 */
                template<typename Field>
                struct lookup_1bit : public component<Field> {
                    using field_type = Field;
                    using field_value_type = typename Field::value_type;
                    using result_type = detail::blueprint_variable<Field>;

                    const std::vector<field_value_type> constants;
                    const detail::blueprint_variable<Field> bit;
                    result_type result;

                    /// Auto allocation of the result
                    template<typename Constants>
                    lookup_1bit(blueprint<Field> &bp,
                                const Constants &in_constants,
                                const detail::blueprint_variable<Field> &in_bit) :
                        component<Field>(bp),
                        constants(std::cbegin(in_constants), std::cend(in_constants)), bit(in_bit) {
                        assert(this->constants.size() == 2);
                        this->result.allocate(this->bp);
                    }

                    /// Manual allocation of the result
                    template<typename Constants>
                    lookup_1bit(blueprint<Field> &bp,
                                const Constants &in_constants,
                                const detail::blueprint_variable<Field> &in_bit,
                                const result_type &in_result) :
                        component<Field>(bp),
                        constants(std::cbegin(in_constants), std::cend(in_constants)), bit(in_bit), result(in_result) {
                        assert(this->constants.size() == 2);
                    }

                    void generate_r1cs_constraints() {
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                            {constants[0] + bit * constants[1] - (bit * constants[0])},
                            {field_value_type::one()},
                            result));
                    }

                    void generate_r1cs_witness() {
                        std::size_t i = static_cast<std::size_t>(
                            static_cast<typename field_type::integral_type>((this->bp.val(bit)).data));
                        this->bp.val(result) = constants[i];
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_DETAIL_LOOKUP_1BIT_HPP
