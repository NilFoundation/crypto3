//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for an auxiliarry gadget for the FOORAM CPU.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BAR_GADGET_HPP
#define CRYPTO3_ZK_BAR_GADGET_HPP

#include <nil/crypto3/zk/snark/component.hpp>
#include <nil/crypto3/zk/snark/components/basic_components.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * The bar gadget checks linear combination
                 *                   Z = aX + bY (mod 2^w)
                 * for a, b - const, X, Y - vectors of w bits,
                 * where w is implicitly inferred, Z - a packed variable.
                 *
                 * This gadget is used four times in fooram:
                 * - PC' = PC + 1
                 * - load_addr = 2 * x + PC'
                 * - store_addr = x + PC
                 */
                template<typename FieldType>
                class bar_component : public component<FieldType> {
                public:
                    pb_linear_combination_array<FieldType> X;
                    FieldType::value_type a;
                    pb_linear_combination_array<FieldType> Y;
                    FieldType::value_type b;
                    pb_linear_combination<FieldType> Z_packed;
                    pb_variable_array<FieldType> Z_bits;

                    variable<FieldType> result;
                    pb_variable_array<FieldType> overflow;
                    pb_variable_array<FieldType> unpacked_result;

                    std::shared_ptr<packing_component<FieldType>> unpack_result;
                    std::shared_ptr<packing_component<FieldType>> pack_Z;

                    std::size_t width;
                    bar_component(blueprint<FieldType> &pb,
                               const pb_linear_combination_array<FieldType> &X,
                               const FieldType::value_type &a,
                               const pb_linear_combination_array<FieldType> &Y,
                               const FieldType::value_type &b,
                               const pb_linear_combination<FieldType> &Z_packed) :
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

#endif    // CRYPTO3_ZK_BAR_GADGET_HPP
