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

#ifndef CRYPTO3_PUBKEY_SSS_WEIGHTED_BASIC_TYPES_HPP
#define CRYPTO3_PUBKEY_SSS_WEIGHTED_BASIC_TYPES_HPP

#include <unordered_map>

#include <nil/crypto3/pubkey/secret_sharing/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Group>
            struct sss_weighted_basic_policy : public sss_basic_policy<Group> {
            protected:
                typedef sss_basic_policy<Group> base_type;

            public:
                //===========================================================================
                // public weighted secret sharing scheme types

                using weights_type = std::vector<std::size_t>;
                // using share_type =
                //     std::pair<std::size_t, std::unordered_map<std::size_t, typename base_type::private_element_type>>;
                // using public_share_type =
                //     std::pair<std::size_t, std::unordered_map<std::size_t, typename base_type::public_element_type>>;

                //===========================================================================
                // public constraints checking meta-functions

                // //
                // // check elements
                // //
                // template<typename Weight>
                // using check_weight_t =
                //     typename std::enable_if<std::is_unsigned<typename Weight::first_type>::value &&
                //                                 std::is_unsigned<typename Weight::second_type>::value,
                //                             bool>::type;
                //
                // template<typename Share,
                //          typename base_type::template check_index_t<typename Share::first_type> = true,
                //          typename ResultT =
                //              typename base_type::template check_share_t<typename Share::second_type::value_type>>
                // using check_share_t = ResultT;
                //
                // template<typename PublicShare,
                //          typename base_type::template check_index_t<typename PublicShare::first_type> = true,
                //          typename ResultT = typename base_type::template check_public_share_t<
                //              typename PublicShare::second_type::value_type>>
                // using check_public_share_t = ResultT;
                //
                // //
                // // check iterators
                // //
                // template<typename WeightIt,
                //          typename ResultT = check_weight_t<typename std::iterator_traits<WeightIt>::value_type>>
                // using check_weight_iterator_t = ResultT;
                //
                // template<typename ShareIt,
                //          typename ResultT = check_share_t<typename std::iterator_traits<ShareIt>::value_type>>
                // using check_share_iterator_t = ResultT;
                //
                // template<typename PublicShareIt,
                //          typename ResultT =
                //              check_public_share_t<typename std::iterator_traits<PublicShareIt>::value_type>>
                // using check_public_share_iterator_t = ResultT;
                //
                // //
                // // check ranges
                // //
                // template<typename Weights, typename ResultT = check_weight_iterator_t<typename Weights::iterator>>
                // using check_weights_t = ResultT;
                //
                // template<typename Shares, typename ResultT = check_share_t<typename Shares::iterator>>
                // using check_shares_t = ResultT;
                //
                // template<typename PublicShares,
                //          typename ResultT = check_public_share_t<typename PublicShares::iterator>>
                // using check_public_shares_t = ResultT;
                
                static inline bool check_weight(const std::size_t &w) {
                    return 0 < w;
                }
                //
                // static inline public_share_type get_weighted_public_share(const share_type &s) {
                //     assert(base_type::check_participant_index(s.first));
                //     public_share_type public_share;
                //     public_share.first = s.first;
                //     for (const auto &part_s : s.second) {
                //         assert(public_share.second.emplace(base_type::get_public_share(part_s)).second);
                //     }
                //     return public_share;
                // }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SSS_WEIGHTED_BASIC_TYPES_HPP
