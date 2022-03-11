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

#ifndef CRYPTO3_HASH_TYPE_TRAITS_HPP
#define CRYPTO3_HASH_TYPE_TRAITS_HPP

#include <type_traits>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            template<typename Params, typename Hash, typename Group>
            struct find_group_hash;

            template<typename Params, typename BasePointGeneratorHash, typename Group>
            struct pedersen_to_point;

            template<typename Params, typename BasePointGeneratorHash, typename Group>
            struct pedersen;

            template<typename Field, typename Hash, typename Params>
            struct h2f;

            template<typename Group, typename Hash, typename Params>
            struct h2c;

            template<typename Hash>
            struct is_find_group_hash : std::bool_constant<false> { };

            template<typename Params, typename Hash, typename Group>
            struct is_find_group_hash<find_group_hash<Params, Hash, Group>> : std::bool_constant<true> { };

            template<typename Hash>
            struct is_pedersen : std::bool_constant<false> { };

            template<typename Params, typename BasePointGeneratorHash, typename Group>
            struct is_pedersen<pedersen_to_point<Params, BasePointGeneratorHash, Group>> : std::bool_constant<true> { };

            template<typename Params, typename BasePointGeneratorHash, typename Group>
            struct is_pedersen<pedersen<Params, BasePointGeneratorHash, Group>> : std::bool_constant<true> { };

            template<typename Hash>
            struct is_h2f : std::bool_constant<false> { };

            template<typename Field, typename Hash, typename Params>
            struct is_h2f<h2f<Field, Hash, Params>> : std::bool_constant<true> { };

            template<typename Hash>
            struct is_h2c : std::bool_constant<false> { };

            template<typename Group, typename Hash, typename Params>
            struct is_h2c<h2c<Group, Hash, Params>> : std::bool_constant<true> { };

        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_TYPE_TRAITS_HPP
