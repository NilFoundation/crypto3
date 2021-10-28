//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
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

#ifndef CRYPTO3_PROPERTY_HPP
#define CRYPTO3_PROPERTY_HPP

#include <boost/property_map/property_map.hpp>

namespace nil {
    namespace crypto3 {
        namespace property {

            enum vertex_hash_t
            {
                vertex_hash
            };
            namespace boost
            {
                BOOST_INSTALL_PROPERTY(vertex, hash);
            }

            template<typename Hash>
            struct MerkleTree_basic_policy {
                typedef std::array<uint8_t, Hash::digest_size> hash_result_type;
                constexpr static const std::size_t hash_digest_size = Hash::digest_size;
                typedef boost::property<hash_t, hash_result_type> hash_property;
            };
        }        // namespace property
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PROPERTY_HPP
