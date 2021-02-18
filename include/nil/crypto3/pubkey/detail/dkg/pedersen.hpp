//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_PEDERSEN_DKG_HPP
#define CRYPTO3_PUBKEY_PEDERSEN_DKG_HPP

#include <numeric>

#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics/sum.hpp>

#include <nil/crypto3/pubkey/detail/secret_sharing/feldman.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                //
                // "A threshold cryptosystem without a trusted party" by Torben Pryds Pedersen.
                // https://dl.acm.org/citation.cfm?id=1754929
                //
                template<typename Group>
                struct pedersen_dkg : feldman_sss<Group> {
                    typedef feldman_sss<Group> base_type;

                    typedef typename base_type::group_type group_type;
                    typedef typename base_type::base_field_type base_field_type;
                    typedef typename base_type::scalar_field_type scalar_field_type;

                    typedef typename base_type::group_value_type group_value_type;
                    typedef typename base_type::base_field_value_type base_field_value_type;
                    typedef typename base_type::scalar_field_value_type scalar_field_value_type;

                    typedef boost::accumulators::accumulator_set<
                        scalar_field_value_type, boost::accumulators::features<boost::accumulators::tag::sum>>
                        share_reducing_acc_type;

                    typedef boost::accumulators::accumulator_set<
                        group_value_type, boost::accumulators::features<boost::accumulators::tag::sum>>
                        public_coeffs_reducing_acc_type;

                    template<typename PublicCoeffsRange,
                             typename std::enable_if<
                                 std::is_same<group_value_type, typename PublicCoeffsRange::value_type>::value,
                                 bool>::type = true>
                    static inline group_value_type reduce_public_coeffs(const PublicCoeffsRange &coeffs) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicCoeffsRange>));

                        return std::accumulate(coeffs.begin(), coeffs.end(), group_value_type::zero());
                    }

                    static inline group_value_type reduce_public_coeffs(public_coeffs_reducing_acc_type &&acc) {
                        return boost::accumulators::sum(acc);
                    }

                    template<typename SharesRange,
                             typename std::enable_if<
                                 std::is_same<scalar_field_value_type, typename SharesRange::value_type>::value,
                                 bool>::type = true>
                    static inline scalar_field_value_type reduce_shares(const SharesRange &shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SharesRange>));

                        return std::accumulate(shares.begin(), shares.end(), scalar_field_value_type::zero());
                    }

                    static inline scalar_field_value_type reduce_shares(share_reducing_acc_type &&acc) {
                        return boost::accumulators::sum(acc);
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif CRYPTO3_PUBKEY_PEDERSEN_DKG_HPP
