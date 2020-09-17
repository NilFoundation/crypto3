//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of public parameters for FOORAM.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_FOORAM_PARAMS_HPP_
#define CRYPTO3_ZK_FOORAM_PARAMS_HPP_

#include <nil/crypto3/zk/snark/gadgets/cpu_checkers/fooram/fooram_cpu_checker.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/fooram/fooram_aux.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/ram_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class ram_fooram {
                public:
                    typedef FieldType base_field_type;
                    typedef fooram_protoboard<FieldType> protoboard_type;
                    typedef fooram_gadget<FieldType> gadget_base_type;
                    typedef fooram_cpu_checker<FieldType> cpu_checker_type;
                    typedef fooram_architecture_params architecture_params_type;

                    static std::size_t timestamp_length;
                };

                template<typename FieldType>
                std::size_t ram_fooram<FieldType>::timestamp_length = 300;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // FOORAM_PARAMS_HPP_
