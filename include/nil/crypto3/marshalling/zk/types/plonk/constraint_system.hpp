//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ZK_PLONK_CONSTRAINT_SYSTEM_HPP
#define CRYPTO3_MARSHALLING_ZK_PLONK_CONSTRAINT_SYSTEM_HPP

#include <type_traits>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/zk/types/plonk/lookup_gate.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/gate.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/copy_constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/lookup_table.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase>
                using public_input_sizes_type =
                nil::marshalling::types::array_list<
                    TTypeBase,
                    nil::marshalling::types::integral<TTypeBase, std::size_t>,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                template<typename TTypeBase, typename PlonkConstraintSystem>
                using plonk_constraint_system = nil::marshalling::types::bundle<
                    TTypeBase, std::tuple<
                        plonk_gates< TTypeBase, typename PlonkConstraintSystem::gates_container_type::value_type >, // gates
                        plonk_copy_constraints< TTypeBase, typename PlonkConstraintSystem::variable_type >,              // copy constraints
                        plonk_lookup_gates< TTypeBase, typename PlonkConstraintSystem::lookup_gates_container_type::value_type >,  // lookup constraints
                        // If we don't have lookup gates, we don't need lookup tables
                        plonk_lookup_tables< TTypeBase, typename PlonkConstraintSystem::lookup_tables_type::value_type >,  // lookup tables
                        // public input sizes
                        public_input_sizes_type<TTypeBase>
                    >
                >;

                template<typename Endianness, typename PlonkConstraintSystem>
                plonk_constraint_system<nil::marshalling::field_type<Endianness>, PlonkConstraintSystem>
                fill_plonk_constraint_system(const PlonkConstraintSystem &system) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using result_type = plonk_constraint_system<nil::marshalling::field_type<Endianness>, PlonkConstraintSystem>;
                    public_input_sizes_type<TTypeBase> public_input_sizes;
                    for(std::size_t i = 0; i < system.public_input_sizes_num(); i++){
                        public_input_sizes.value().push_back(nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>(system.public_input_size(i)));
                    }

                    return result_type(std::make_tuple(
                        fill_plonk_gates<Endianness, typename PlonkConstraintSystem::gates_container_type::value_type>(system.gates()),
                        fill_plonk_copy_constraints<Endianness, typename PlonkConstraintSystem::variable_type>(system.copy_constraints()),
                        fill_plonk_lookup_gates<Endianness, typename PlonkConstraintSystem::lookup_gates_container_type::value_type>(system.lookup_gates()),
                        fill_plonk_lookup_tables<Endianness, typename PlonkConstraintSystem::lookup_tables_type::value_type>(system.lookup_tables()),
                        public_input_sizes
                    ));
                }

                template<typename Endianness, typename PlonkConstraintSystem>
                PlonkConstraintSystem
                make_plonk_constraint_system(
                    const plonk_constraint_system<nil::marshalling::field_type<Endianness>, PlonkConstraintSystem> &filled_system
                ){
                    std::vector<std::size_t> public_input_sizes;
                    for(std::size_t i = 0; i < std::get<4>(filled_system.value()).value().size(); i++){
                        public_input_sizes.push_back(std::get<4>(filled_system.value()).value().at(i).value());
                    }
                    return PlonkConstraintSystem(
                        make_plonk_gates<Endianness, typename PlonkConstraintSystem::gates_container_type::value_type>(std::get<0>(filled_system.value())),
                        make_plonk_copy_constraints<Endianness, typename PlonkConstraintSystem::variable_type>(std::get<1>(filled_system.value())),
                        make_plonk_lookup_gates<Endianness, typename PlonkConstraintSystem::lookup_gates_container_type::value_type>(std::get<2>(filled_system.value())),
                        make_plonk_lookup_tables<Endianness, typename PlonkConstraintSystem::lookup_tables_type::value_type>(std::get<3>(filled_system.value())),
                        public_input_sizes
                    );
                }
            } //namespace types
        } // namespace marshalling
    } // namespace crypto3
} // namespace nil

#endif
