//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of public parameters for TinyRAM.
//---------------------------------------------------------------------------//

#ifndef TINYRAM_PARAMS_HPP_
#define TINYRAM_PARAMS_HPP_

#include <nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/tinyram_cpu_checker.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/ram_params.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/tinyram/tinyram_aux.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class ram_tinyram {
                public:
                    static std::size_t timestamp_length;

                    typedef FieldType base_field_type;
                    typedef tinyram_protoboard<FieldType> protoboard_type;
                    typedef tinyram_gadget<FieldType> gadget_base_type;
                    typedef tinyram_cpu_checker<FieldType> cpu_checker_type;
                    typedef tinyram_architecture_params architecture_params_type;
                };

                template<typename FieldType>
                std::size_t ram_tinyram<FieldType>::timestamp_length = 300;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // TINYRAM_PARAMS_HPP_
