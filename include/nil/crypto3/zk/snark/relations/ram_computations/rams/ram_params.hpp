//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of public-parameter selector for RAMs.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_RAM_PARAMS_HPP_
#define CRYPTO3_ZK_RAM_PARAMS_HPP_

#include <vector>

#include <nil/crypto3/zk/snark/relations/ram_computations/memory/memory_store_trace.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /*
                  When declaring a new RAMType one should do a make it a class that declares typedefs for:

                  base_field_type
                  ram_cpu_checker_type
                  architecture_params_type

                  For ram_to_r1cs reduction currently the following are also necessary:
                  protoboard_type (e.g. tinyram_blueprint<FieldType>)
                  component_base_type (e.g. tinyram_component<FieldType>)
                  cpu_state_variable_type (must have blueprint_variable_vector<FieldType> all_vars)

                  The RAMType class must also have a static std::size_t variable
                  timestamp_length, which specifies the zk-SNARK reduction timestamp
                  length.
                */

                template<typename RAMType>
                using ram_base_field = typename RAMType::base_field_type;

                template<typename RAMType>
                using ram_cpu_state = std::vector<bool>;

                template<typename RAMType>
                using ram_boot_trace = memory_store_trace;

                template<typename RAMType>
                using ram_blueprint = typename RAMType::protoboard_type;

                template<typename RAMType>
                using ram_component_base = typename RAMType::component_base_type;

                template<typename RAMType>
                using ram_cpu_checker = typename RAMType::cpu_checker_type;

                template<typename RAMType>
                using ram_architecture_params = typename RAMType::architecture_params_type;

                template<typename RAMType>
                using ram_input_tape = std::vector<std::size_t>;

                /*
                  One should also make the following methods for ram_architecture_params

                  (We are not yet making a ram_architecture_params base class, as it
                  would require base class for ram_program

                  TODO: make this base class)

                  std::size_t address_size();
                  std::size_t value_size();
                  std::size_t cpu_state_size();
                  std::size_t initial_pc_addr();
                  std::vector<bool> initial_cpu_state();
                */

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // RAM_PARAMS_HPP_
