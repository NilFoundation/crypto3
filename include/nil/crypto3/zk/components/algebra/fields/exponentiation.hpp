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
// @file Declaration of interfaces for the exponentiation component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_EXPONENTIATION_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_EXPONENTIATION_COMPONENT_HPP

#include <memory>
#include <vector>

#include <nil/crypto3/multiprecision/wnaf.hpp>

#include <nil/crypto3/zk/components/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                /**
                 * The exponentiation component verifies field exponentiation in the field F_{p^k}.
                 *
                 * Note that the power is a constant (i.e., hardcoded into the component).
                 */
                template<typename FpkT,
                         template<class>
                         class Fpk_variableT,
                         template<class>
                         class Fpk_mul_componentT,
                         template<class>
                         class Fpk_sqr_componentT,
                         typename NumberType = typename FpkT::number_type>
                class exponentiation_component : component<typename FpkT::base_field_type> {
                public:
                    typedef typename FpkT::base_field_type FieldType;
                    typedef NumberType number_type;
                    std::vector<long> NAF;

                    std::vector<std::shared_ptr<Fpk_variableT<FpkT>>> intermediate;
                    std::vector<std::shared_ptr<Fpk_mul_componentT<FpkT>>> addition_steps;
                    std::vector<std::shared_ptr<Fpk_mul_componentT<FpkT>>> subtraction_steps;
                    std::vector<std::shared_ptr<Fpk_sqr_componentT<FpkT>>> doubling_steps;

                    Fpk_variableT<FpkT> elt;
                    number_type power;
                    Fpk_variableT<FpkT> result;

                    std::size_t intermed_count;
                    std::size_t add_count;
                    std::size_t sub_count;
                    std::size_t dbl_count;

                    template<typename Backend, typename multiprecision::expression_template_option ExpressionTemplates>
                    exponentiation_component(blueprint<FieldType> &bp,
                                             const Fpk_variableT<FpkT> &elt,
                                             const multiprecision::number<Backend, ExpressionTemplates> &power,
                                             const Fpk_variableT<FpkT> &result) :
                        component<FieldType>(bp),
                        elt(elt), power(power), result(result) {
                        NAF = multiprecision::find_wnaf(1, power);

                        intermed_count = 0;
                        add_count = 0;
                        sub_count = 0;
                        dbl_count = 0;

                        bool found_nonzero = false;
                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (found_nonzero) {
                                ++dbl_count;
                                ++intermed_count;
                            }

                            if (NAF[i] != 0) {
                                found_nonzero = true;

                                if (NAF[i] > 0) {
                                    ++add_count;
                                    ++intermed_count;
                                } else {
                                    ++sub_count;
                                    ++intermed_count;
                                }
                            }
                        }

                        intermediate.resize(intermed_count);
                        intermediate[0].reset(new Fpk_variableT<FpkT>(bp, FpkT::value_type::one()));
                        for (std::size_t i = 1; i < intermed_count; ++i) {
                            intermediate[i].reset(new Fpk_variableT<FpkT>(bp));
                        }
                        addition_steps.resize(add_count);
                        subtraction_steps.resize(sub_count);
                        doubling_steps.resize(dbl_count);

                        found_nonzero = false;

                        std::size_t dbl_id = 0, add_id = 0, sub_id = 0, intermed_id = 0;

                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (found_nonzero) {
                                doubling_steps[dbl_id].reset(new Fpk_sqr_componentT<FpkT>(
                                    bp,
                                    *intermediate[intermed_id],
                                    (intermed_id + 1 == intermed_count ? result : *intermediate[intermed_id + 1])));
                                ++intermed_id;
                                ++dbl_id;
                            }

                            if (NAF[i] != 0) {
                                found_nonzero = true;

                                if (NAF[i] > 0) {
                                    /* next = cur * elt */
                                    addition_steps[add_id].reset(new Fpk_mul_componentT<FpkT>(
                                        bp,
                                        *intermediate[intermed_id],
                                        elt,
                                        (intermed_id + 1 == intermed_count ? result : *intermediate[intermed_id + 1])));
                                    ++add_id;
                                    ++intermed_id;
                                } else {
                                    /* next = cur / elt, i.e. next * elt = cur */
                                    subtraction_steps[sub_id].reset(new Fpk_mul_componentT<FpkT>(
                                        bp,
                                        (intermed_id + 1 == intermed_count ? result : *intermediate[intermed_id + 1]),
                                        elt,
                                        *intermediate[intermed_id]));
                                    ++sub_id;
                                    ++intermed_id;
                                }
                            }
                        }
                    }
                    void generate_r1cs_constraints() {
                        for (std::size_t i = 0; i < add_count; ++i) {
                            addition_steps[i]->generate_r1cs_constraints();
                        }

                        for (std::size_t i = 0; i < sub_count; ++i) {
                            subtraction_steps[i]->generate_r1cs_constraints();
                        }

                        for (std::size_t i = 0; i < dbl_count; ++i) {
                            doubling_steps[i]->generate_r1cs_constraints();
                        }
                    }
                    void generate_r1cs_witness() {
                        intermediate[0]->generate_r1cs_witness(FpkT::value_type::one());

                        bool found_nonzero = false;
                        std::size_t dbl_id = 0, add_id = 0, sub_id = 0, intermed_id = 0;

                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (found_nonzero) {
                                doubling_steps[dbl_id]->generate_r1cs_witness();
                                ++intermed_id;
                                ++dbl_id;
                            }

                            if (NAF[i] != 0) {
                                found_nonzero = true;

                                if (NAF[i] > 0) {
                                    addition_steps[add_id]->generate_r1cs_witness();
                                    ++intermed_id;
                                    ++add_id;
                                } else {
                                    const typename FpkT::value_type cur_val = intermediate[intermed_id]->get_element();
                                    const typename FpkT::value_type elt_val = elt.get_element();
                                    const typename FpkT::value_type next_val = cur_val * elt_val.inversed();

                                    (intermed_id + 1 == intermed_count ? result : *intermediate[intermed_id + 1])
                                        .generate_r1cs_witness(next_val);

                                    subtraction_steps[sub_id]->generate_r1cs_witness();

                                    ++intermed_id;
                                    ++sub_id;
                                }
                            }
                        }
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_EXPONENTIATION_COMPONENT_HPP
