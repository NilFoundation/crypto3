//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP
#define CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/zk/snark/commitments/list_polynomial_commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase,
                         typename LPCScheme,
                         typename = typename std::enable_if<
                             std::is_same<LPCScheme, 
                                nil::crypto3::zk::snark::list_polynomial_commitment<>
                             >::value,
                             bool>::type,
                         typename... TOptions>
                using lpc_proof = 
                    nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // std::array<merkle_proof_type, k> z_openings;
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                // merkle_proof_type
                                merkle_proof<
                                    TTypeBase,
                                    LPCScheme::openning_type
                                >,
                                nil::marshalling::option::fixed_size_storage<LPCScheme::k>
                            >,
                            // std::array<std::array<merkle_proof_type, m * r>, lamda> alpha_openings
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                // layer path
                                nil::marshalling::types::array_list<
                                    TTypeBase,
                                    // merkle_proof_type
                                    merkle_proof<
                                        TTypeBase,
                                        LPCScheme::openning_type
                                    >,
                                    nil::marshalling::option::fixed_size_storage<LPCScheme::m * LPCScheme::r>
                                >,
                                nil::marshalling::option::fixed_size_storage<LPCScheme::lamda>
                            >,
                            // std::array<std::array<merkle_proof_type, r>, lamda> f_y_openings
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                // layer path
                                nil::marshalling::types::array_list<
                                    TTypeBase,
                                    // merkle_proof_type
                                    merkle_proof<
                                        TTypeBase,
                                        LPCScheme::openning_type
                                    >,
                                    nil::marshalling::option::fixed_size_storage<LPCScheme::r>
                                >,
                                nil::marshalling::option::fixed_size_storage<LPCScheme::lamda>
                            >,
                            // std::array<std::array<commitment_type, r - 1>, lamda> f_commitments
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                // layer path
                                nil::marshalling::types::array_list<
                                    TTypeBase,
                                    // merkle_proof_type
                                    merkle_proof<
                                        TTypeBase,
                                        LPCScheme::openning_type
                                    >,
                                    nil::marshalling::option::fixed_size_storage<LPCScheme::r - 1>
                                >,
                                nil::marshalling::option::fixed_size_storage<LPCScheme::lamda>
                            >,
                            // std::array<std::array<typename FieldType::value_type>, lambda> 
                            //     f_ip1_coefficients
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                // layer path
                                nil::marshalling::types::array_list<
                                    TTypeBase,
                                    // merkle_proof_type
                                    merkle_proof<
                                        TTypeBase,
                                        LPCScheme::openning_type
                                    >,
                                    nil::marshalling::option::fixed_size_storage<LPCScheme::...>
                                >,
                                nil::marshalling::option::fixed_size_storage<LPCScheme::lamda>
                            >
                        >
                    >;

            }    // namespace types
        }        // namespace marshalling
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP
