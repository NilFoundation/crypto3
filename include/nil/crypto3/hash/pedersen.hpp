//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_HASH_PEDERSEN_HPP
#define CRYPTO3_HASH_PEDERSEN_HPP

#include <nil/crypto3/hash/find_group_hash.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            /*!
             * @brief Pedersen hash
             *
             * @tparam Group
             * @tparam Params
             */
            // TODO: use blake2s by default
            template<typename Params = find_group_hash_default_params, typename BasePointHashGenerator = sha2<256>,
                     typename Group = algebra::curves::jubjub::template g1_type<
                         nil::crypto3::algebra::curves::coordinates::affine,
                         nil::crypto3::algebra::curves::forms::twisted_edwards>>
            struct pedersen {
                using params = Params;
                using group_type = Group;

                using base_point_hash_generator = BasePointHashGenerator;
                using base_point_generator = find_group_hash<params, base_point_hash_generator, group_type>;

                using curve_type = typename group_type::curve_type;
                using group_value_type = typename group_type::value_type;

                // TODO: use marshalling method to determine bit size of serialized group_value_type
                static constexpr std::size_t digest_bits = group_type::field_type::value_bits;
                using digest_type = std::array<bool, digest_bits>;

                struct construction {
                    struct params_type {
                        typedef nil::marshalling::option::little_endian digest_endian;
                    };

                    typedef void type;
                };
            };
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_PEDERSEN_HPP
