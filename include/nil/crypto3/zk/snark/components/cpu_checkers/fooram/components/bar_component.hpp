//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for an auxiliarry component for the FOORAM CPU.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BAR_COMPONENT_HPP
#define CRYPTO3_ZK_BAR_COMPONENT_HPP

#include <nil/crypto3/zk/snark/component.hpp>
#include <nil/crypto3/zk/snark/components/basic_components.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * The bar component checks linear combination
                 *                   Z = aX + bY (mod 2^w)
                 * for a, b - const, X, Y - vectors of w bits,
                 * where w is implicitly inferred, Z - a packed variable.
                 *
                 * This component is used four times in fooram:
                 * - PC' = PC + 1
                 * - load_addr = 2 * x + PC'
                 * - store_addr = x + PC
                 */
                template<typename FieldType>
                class bar_component : public component<FieldType> {
                public:
                    blueprint_linear_combination_vector<FieldType> X;
                    typename FieldType::value_type a;
                    blueprint_linear_combination_vector<FieldType> Y;
                    typename FieldType::value_type b;
                    blueprint_linear_combination<FieldType> Z_packed;
                    blueprint_variable_vector<FieldType> Z_bits;

                    blueprint_variable<FieldType> result;
                    blueprint_variable_vector<FieldType> overflow;
                    blueprint_variable_vector<FieldType> unpacked_result;

                    std::shared_ptr<packing_component<FieldType>> unpack_result;
                    std::shared_ptr<packing_component<FieldType>> pack_Z;

                    std::size_t width;
                    bar_component(blueprint<FieldType> &pb,
                               const blueprint_linear_combination_vector<FieldType> &X,
                               const typename FieldType::value_type &a,
                               const blueprint_linear_combination_vector<FieldType> &Y,
                               const typename FieldType::value_type &b,
                               const blueprint_linear_combination<FieldType> &Z_packed) :
                        component<FieldType>(pb),
                        X(X), a(a), Y(Y), b(b), Z_packed(Z_packed) {
                        assert(X.size() == Y.size());
                        width = X.size();

                        result.allocate(pb);
                        Z_bits.allocate(pb, width);
                        overflow.allocate(pb, 2 * width);

                        unpacked_result.insert(unpacked_result.end(), Z_bits.begin(), Z_bits.end());
                        unpacked_result.insert(unpacked_result.end(), overflow.begin(), overflow.end());

                        unpack_result.reset(new packing_component<FieldType>(pb, unpacked_result, result));
                        pack_Z.reset(new packing_component<FieldType>(pb, Z_bits, Z_packed));
                    }

                    void generate_r1cs_constraints() {
                        unpack_result->generate_r1cs_constraints(true);
                        pack_Z->generate_r1cs_constraints(false);

                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            1, a * pb_packing_sum<FieldType>(X) + b * pb_packing_sum<FieldType>(Y), result));
                    }

                    void generate_r1cs_witness() {
                        this->pb.val(result) =
                            X.get_field_element_from_bits(this->pb) * a + Y.get_field_element_from_bits(this->pb) * b;
                        unpack_result->generate_r1cs_witness_from_packed();

                        pack_Z->generate_r1cs_witness_from_bits();
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BAR_COMPONENT_HPP
