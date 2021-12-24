//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Noam Yemini <@NoamDev at GitHub>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_VARIABLE_HPP
#define CRYPTO3_ZK_BLUEPRINT_VARIABLE_HPP

#include <vector>

#include <nil/crypto3/multiprecision/integer.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>
#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>
#include <nil/crypto3/zk/snark/relations/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename TArithmetization>
                class blueprint;

                template<typename TArithmetization>
                class blueprint_variable;

                // template<std::size_t WireIndex, typename Rotation, typename TArithmetization, typename TBlueprintField>
                // class blueprint_variable;

                template<typename TBlueprintField>
                class blueprint_variable<snark::r1cs_constraint_system<TBlueprintField>> : 
                    public snark::variable<TBlueprintField, false> {
                public:
                    blueprint_variable(const typename snark::variable<TBlueprintField>::index_type index = 0) :
                        snark::variable<TBlueprintField>(index) {};

                    template<typename TArithmetization>
                    void allocate(blueprint<TArithmetization> &bp) {
                        this->index = bp.allocate_var_index();
                    }

                    static blueprint_variable constant() {
                        return blueprint_variable(0);
                    }
                };

                template<typename TBlueprintField, std::size_t WiresAmount>
                class blueprint_variable<snark::plonk_constraint_system<TBlueprintField, WiresAmount>> : 
                    public snark::variable<TBlueprintField, true> {

                public:
                    constexpr blueprint_variable(const std::size_t wire_index, 
                        typename snark::variable<TBlueprintField, true>::rotation_type rotation = 
                            snark::variable<TBlueprintField, true>::rotation_type::current) :
                        snark::variable<TBlueprintField, true>(wire_index, rotation) {};
                };

                template<typename TArithmetization>
                class blueprint_variable_vector;

                template<typename TBlueprintField>
                class blueprint_variable_vector<snark::r1cs_constraint_system<TBlueprintField>> : 
                    private std::vector<blueprint_variable<snark::r1cs_constraint_system<TBlueprintField>>> {

                    typedef snark::r1cs_constraint_system<TBlueprintField> TArithmetization;
                    typedef typename TBlueprintField::value_type field_value_type;
                    typedef std::vector<blueprint_variable<TArithmetization>> contents;

                public:
                    using typename contents::const_iterator;
                    using typename contents::const_reverse_iterator;
                    using typename contents::iterator;
                    using typename contents::reverse_iterator;

                    using contents::begin;
                    using contents::emplace_back;
                    using contents::erase;
                    using contents::empty;
                    using contents::end;
                    using contents::insert;
                    using contents::rbegin;
                    using contents::rend;
                    using contents::reserve;
                    using contents::size;
                    using contents::operator[];
                    using contents::resize;

                    blueprint_variable_vector() : contents() {};
                    blueprint_variable_vector(std::size_t count, 
                        const blueprint_variable<TArithmetization> &value) :
                        contents(count, value) {};
                    blueprint_variable_vector(typename contents::const_iterator first,
                                              typename contents::const_iterator last) :
                        contents(first, last) {};
                    blueprint_variable_vector(typename contents::const_reverse_iterator first,
                                              typename contents::const_reverse_iterator last) :
                        contents(first, last) {};

                    /* allocates blueprint_variable<TBlueprintField> vector in MSB->LSB order */
                    void allocate(blueprint<TArithmetization> &bp, const std::size_t n) {
                        (*this).resize(n);

                        for (std::size_t i = 0; i < n; ++i) {
                            (*this)[i].allocate(bp);
                        }
                    }

                    void fill_with_field_elements(blueprint<TArithmetization> &bp,
                                                  const std::vector<field_value_type> &vals) const {
                        assert(this->size() == vals.size());
                        for (std::size_t i = 0; i < vals.size(); ++i) {
                            bp.val((*this)[i]) = vals[i];
                        }
                    }

                    void fill_with_bits(blueprint<TArithmetization> &bp, const std::vector<bool> &bits) const {
                        assert(this->size() == bits.size());
                        for (std::size_t i = 0; i < bits.size(); ++i) {
                            bp.val((*this)[i]) = (bits[i] ? field_value_type::one() : field_value_type::zero());
                        }
                    }

                    void fill_with_bits_of_ulong(blueprint<TArithmetization> &bp, const unsigned long i) const {
                        this->fill_with_bits_of_field_element(bp, field_value_type(i));
                    }

                    void fill_with_bits_of_field_element(blueprint<TArithmetization> &bp, const field_value_type &r) const {
                        for (std::size_t i = 0; i < this->size(); ++i) {
                            bp.val((*this)[i]) = nil::crypto3::multiprecision::bit_test(r.data, i) ?
                                                     field_value_type::one() :
                                                     field_value_type::zero();
                        }
                    }

                    std::vector<field_value_type> get_vals(const blueprint<TArithmetization> &bp) const {
                        std::vector<field_value_type> result(this->size());
                        for (std::size_t i = 0; i < this->size(); ++i) {
                            result[i] = bp.val((*this)[i]);
                        }
                        return result;
                    }

                    std::vector<bool> get_bits(const blueprint<TArithmetization> &bp) const {
                        std::vector<bool> result;
                        for (std::size_t i = 0; i < this->size(); ++i) {
                            const field_value_type v = bp.val((*this)[i]);
                            assert(v.is_zero() || v.is_one());
                            result.push_back(v.is_one());
                        }
                        return result;
                    }

                    field_value_type get_field_element_from_bits(const blueprint<TArithmetization> &bp) const {
                        field_value_type result = field_value_type::zero();

                        for (std::size_t i = 0; i < this->size(); ++i) {
                            /* push in the new bit */
                            const field_value_type v = bp.val((*this)[this->size() - 1 - i]);
                            assert(v.is_zero() || v.is_one());
                            result += result + v;
                        }

                        return result;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_VARIABLE_HPP
