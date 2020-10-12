//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of public-parameter selector for the RAM zkSNARK.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_RAM_ZKSNARK_PARAMS_HPP_
#define CRYPTO3_ZK_RAM_ZKSNARK_PARAMS_HPP_

#include <nil/crypto3/zk/snark/relations/ram_computations/rams/ram_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * The interfaces of the RAM zkSNARK are templatized via the parameter
                 * ram_zksnark_ppT. When used, the interfaces must be invoked with
                 * a particular parameter choice; let 'my_ram_zksnark_pp' denote this choice.
                 *
                 * The class my_ram_zksnark_pp must contain typedefs for the typenames
                 * - PCD_pp, and
                 * - machine_pp.
                 *
                 * For example, if you want to use the types my_PCD_pp and my_machine_pp,
                 * then you would declare my_ram_zksnark_pp as follows:
                 *
                 *   class my_ram_zksnark_pp {
                 *   public:
                 *       typedef my_PCD_pp PCD_pp;
                 *       typedef my_machine_pp machine_pp;
                 *   };
                 *
                 * Having done the above, my_ram_zksnark_pp can be used as a template parameter.
                 *
                 * See default_tinyram_zksnark_pp in the file
                 *
                 *   common/default_types/tinyram_zksnark_pp.hpp
                 *
                 * for an example of the above steps for the case of "RAM=TinyRAM".
                 *
                 */

                /*
                 * Below are various template aliases (used for convenience).
                 */

                template<typename ram_zksnark_ppT>
                using ram_zksnark_PCD_pp = typename ram_zksnark_ppT::PCD_pp;

                template<typename ram_zksnark_ppT>
                using ram_zksnark_machine_pp = typename ram_zksnark_ppT::machine_pp;

                template<typename ram_zksnark_ppT>
                using ram_zksnark_architecture_params =
                    ram_architecture_params<ram_zksnark_machine_pp<ram_zksnark_ppT>>;

                template<typename ram_zksnark_ppT>
                using ram_zksnark_primary_input = ram_boot_trace<ram_zksnark_machine_pp<ram_zksnark_ppT>>;

                template<typename ram_zksnark_ppT>
                using ram_zksnark_auxiliary_input = ram_input_tape<ram_zksnark_machine_pp<ram_zksnark_ppT>>;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // RAM_ZKSNARK_PARAMS_HPP_
