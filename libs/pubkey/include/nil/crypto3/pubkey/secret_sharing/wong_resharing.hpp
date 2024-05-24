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

#ifndef CRYPTO3_PUBKEY_WONG_RESHARING_DKG_HPP
#define CRYPTO3_PUBKEY_WONG_RESHARING_DKG_HPP

#include <nil/crypto3/pubkey/detail/dkg/pedersen.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                //
                // "Verifiable Secret Redistribution for Threshold Signing Schemes", by T. Wong et al.
                // https://www.cs.cmu.edu/~wing/publications/Wong-Wing02b.pdf
                //
                template<typename Group>
                struct wong_resharing : pedersen_dkg<Group> {
                    typedef pedersen_dkg<Group> base_type;

                    typedef typename base_type::private_element_type private_element_type;
                    typedef typename base_type::public_element_type public_element_type;
                    typedef typename base_type::private_elements_type private_elements_type;
                    typedef typename base_type::indexed_private_elements_type indexed_private_elements_type;

                    //===========================================================================
                    // implicitly ordered in/out

                    template<typename OldPublicSharesRange,
                             typename = typename std::enable_if<
                                 std::is_same<public_element_type, typename OldPublicSharesRange::value_type>::value,
                                 bool>::type>
                    static inline bool verify_old_secret(const private_element_type &old_secret,
                                                         const OldPublicSharesRange &old_public_shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const OldPublicSharesRange>));

                        return verify_old_secret(base_type::get_public_element(old_secret), old_public_shares);
                    }

                    template<typename OldPublicSharesRange,
                             typename = typename std::enable_if<
                                 std::is_same<public_element_type, typename OldPublicSharesRange::value_type>::value,
                                 bool>::type>
                    static inline bool verify_old_secret(const public_element_type &old_public_secret,
                                                         const OldPublicSharesRange &old_public_shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const OldPublicSharesRange>));

                        std::size_t shares_len = std::distance(old_public_shares.begin(), old_public_shares.end());
                        public_element_type temp = public_element_type::zero();
                        std::size_t i = 1;

                        for (const auto &gs_i : old_public_shares) {
                            temp = temp + gs_i * base_type::eval_basis_poly(shares_len, i++);
                        }
                        return old_public_secret == temp;
                    }

                    //===========================================================================
                    // explicitly ordered in/out

                    template<typename OldPublicSharesContainer,
                             typename = typename std::enable_if<
                                 std::is_integral<typename OldPublicSharesContainer::key_type>::value &&
                                     std::is_same<public_element_type,
                                                  typename OldPublicSharesContainer::mapped_type>::value,
                                 bool>::type>
                    static inline bool verify_old_secret(const private_element_type &old_secret,
                                                         const OldPublicSharesContainer &old_public_shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::UniqueAssociativeContainer<const OldPublicSharesContainer>));
                        BOOST_RANGE_CONCEPT_ASSERT((boost::PairAssociativeContainer<const OldPublicSharesContainer>));

                        return verify_old_secret(base_type::get_public_element(old_secret), old_public_shares);
                    }

                    template<typename OldPublicSharesContainer,
                             typename = typename std::enable_if<
                                 std::is_integral<typename OldPublicSharesContainer::key_type>::value &&
                                     std::is_same<public_element_type,
                                                  typename OldPublicSharesContainer::mapped_type>::value,
                                 bool>::type>
                    static inline bool verify_old_secret(const public_element_type &old_public_secret,
                                                         const OldPublicSharesContainer &old_public_shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::UniqueAssociativeContainer<const OldPublicSharesContainer>));
                        BOOST_RANGE_CONCEPT_ASSERT((boost::PairAssociativeContainer<const OldPublicSharesContainer>));

                        std::size_t shares_len = std::distance(old_public_shares.begin(), old_public_shares.end());
                        public_element_type temp = public_element_type::zero();

                        for (const auto &[i, gs_i] : old_public_shares) {
                            temp = temp + gs_i * base_type::eval_basis_poly(shares_len, i);
                        }
                        return old_public_secret == temp;
                    }

                    //===========================================================================
                    // general functions

                    static inline private_elements_type get_new_poly(private_element_type old_share, std::size_t new_t,
                                                                     std::size_t new_n) {
                        assert(check_t(new_t, new_n));

                        return get_poly(new_t);
                    }

                    // TODO: add custom random generation
                    static inline private_elements_type get_new_poly(const private_element_type &old_share,
                                                                     std::size_t new_t) {
                        assert(new_t > 0);

                        private_elements_type coeffs;

                        coeffs.emplace_back(old_share);
                        for (std::size_t i = 1; i < new_t; i++) {
                            coeffs.emplace_back(algebra::random_element<scalar_field_type>());
                        }
                        return coeffs;
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif
