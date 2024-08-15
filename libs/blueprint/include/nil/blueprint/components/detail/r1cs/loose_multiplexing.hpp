//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_LOOSE_MULTIPLEXING_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_LOOSE_MULTIPLEXING_COMPONENT_HPP

#include <cassert>
#include <memory>

#include <nil/blueprint/component.hpp>
#include <nil/blueprint/components/detail/r1cs/packing.hpp>
#include <nil/blueprint/components/boolean/r1cs/inner_product.hpp>

#include <boost/multiprecision/number.hpp>
#include <nil/crypto3/zk/snark/arithmetization/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                /*
                  loose_multiplexing implements loose multiplexer:
                  index not in bounds -> success_flag = 0
                  index in bounds && success_flag = 1 -> result is correct
                  however if index is in bounds we can also set success_flag to 0 (and then result will be forced to
                  be 0)
                */
                template<typename FieldType>
                class loose_multiplexing : public nil::blueprint::components::component<FieldType> {
                public:
                    detail::blueprint_variable_vector<FieldType> alpha;

                private:
                    std::shared_ptr<inner_product<FieldType>> compute_result;

                public:
                    const detail::blueprint_linear_combination_vector<FieldType> arr;
                    const detail::blueprint_variable<FieldType> index;
                    const detail::blueprint_variable<FieldType> result;
                    const detail::blueprint_variable<FieldType> success_flag;

                    loose_multiplexing(blueprint<FieldType> &bp,
                                       const detail::blueprint_linear_combination_vector<FieldType> &arr,
                                       const detail::blueprint_variable<FieldType> &index,
                                       const detail::blueprint_variable<FieldType> &result,
                                       const detail::blueprint_variable<FieldType> &success_flag) :
                        nil::blueprint::components::component<FieldType>(bp),
                        arr(arr), index(index), result(result), success_flag(success_flag) {
                        alpha.allocate(bp, arr.size());
                        compute_result.reset(new inner_product<FieldType>(bp, alpha, arr, result));
                    };

                    void generate_gates() {
                        /* \alpha_i (index - i) = 0 */
                        for (std::size_t i = 0; i < arr.size(); ++i) {
                            this->bp.add_r1cs_constraint(zk::snark::r1cs_constraint<FieldType>(alpha[i], index - i, 0));
                        }

                        /* 1 * (\sum \alpha_i) = success_flag */
                        detail::blueprint_linear_combination<FieldType> a, b, c;
                        a.add_term(detail::blueprint_variable<FieldType>(0));
                        for (std::size_t i = 0; i < arr.size(); ++i) {
                            b.add_term(alpha[i]);
                        }
                        c.add_term(success_flag);
                        this->bp.add_r1cs_constraint(zk::snark::r1cs_constraint<FieldType>(a, b, c));

                        /* now success_flag is constrained to either 0 (if index is out of
                           range) or \alpha_i. constrain it and \alpha_i to zero */
                        generate_boolean_r1cs_constraint<FieldType>(this->bp, success_flag);

                        /* compute result */
                        compute_result->generate_gates();
                    }

                    void generate_assignments() {

                        /* assumes that idx can be fit in ulong; true for our purposes for now */
                        const typename FieldType::value_type valint = this->bp.val(index);

                        unsigned long idx = static_cast<unsigned long>(typename FieldType::integral_type(valint.data));

                        if (idx >= arr.size() || typename FieldType::integral_type(valint.data) >= arr.size()) {
                            for (std::size_t i = 0; i < arr.size(); ++i) {
                                this->bp.val(alpha[i]) = FieldType::value_type::zero();
                            }

                            this->bp.val(success_flag) = FieldType::value_type::zero();
                        } else {
                            for (std::size_t i = 0; i < arr.size(); ++i) {
                                this->bp.val(alpha[i]) =
                                    (i == idx ? FieldType::value_type::one() : FieldType::value_type::zero());
                            }

                            this->bp.val(success_flag) = FieldType::value_type::one();
                        }

                        compute_result->generate_assignments();
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_LOOSE_MULTIPLEXING_COMPONENT_HPP
