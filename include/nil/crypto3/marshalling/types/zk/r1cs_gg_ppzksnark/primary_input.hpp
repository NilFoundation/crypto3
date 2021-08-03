//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_PRIMARY_INPUT_HPP
#define CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_PRIMARY_INPUT_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/tag.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/marshalling/types/algebra/field_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase, 
                         typename PrimaryInput,
                         typename = typename std::enable_if<
                             std::is_same<PrimaryInput, 
                                zk::snark::r1cs_primary_input<
                                    typename PrimaryInput::value_type::field_type
                                >
                             >::value,
                             bool>::type,
                         typename... TOptions>
                using r1cs_gg_ppzksnark_primary_input = 
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        field_element<
                            TTypeBase, 
                            typename PrimaryInput::value_type::field_type
                        >,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<
                                TTypeBase, 
                                std::size_t
                            >
                        > 
                    >;

                template <typename PrimaryInput, 
                          typename Endianness>
                r1cs_gg_ppzksnark_primary_input<nil::marshalling::field_type<
                                Endianness>,
                                PrimaryInput>
                    fill_r1cs_gg_ppzksnark_primary_input(PrimaryInput r1cs_gg_ppzksnark_primary_input_inp){

                    return fill_field_element_vector<typename PrimaryInput::value_type::field_type, 
                                Endianness>(r1cs_gg_ppzksnark_primary_input_inp);
                }

                template <typename PrimaryInput, 
                          typename Endianness>
                PrimaryInput
                    construct_r1cs_gg_ppzksnark_primary_input(
                        r1cs_gg_ppzksnark_primary_input<nil::marshalling::field_type<
                                Endianness>,
                                PrimaryInput> filled_r1cs_gg_ppzksnark_primary_input){

                    return construct_field_element_vector<typename PrimaryInput::value_type::field_type, 
                        Endianness>(filled_r1cs_gg_ppzksnark_primary_input);
                }

            }    // namespace types
        }        // namespace marshalling
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_PRIMARY_INPUT_HPP
