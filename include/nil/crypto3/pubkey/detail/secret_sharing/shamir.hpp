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

#ifndef CRYPTO3_PUBKEY_SHAMIR_SSS_HPP
#define CRYPTO3_PUBKEY_SHAMIR_SSS_HPP

#include <vector>
#include <type_traits>
#include <unordered_map>

#include <boost/concept_check.hpp>
#include <boost/range/concepts.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Group>
                struct shamir_sss {
                    typedef Group group_type;
                    typedef typename group_type::policy_type::base_field_type base_field_type;
                    typedef typename group_type::policy_type::scalar_field_type scalar_field_type;

                    typedef typename group_type::value_type group_value_type;
                    typedef typename base_field_type::value_type base_field_value_type;
                    typedef typename scalar_field_type::value_type scalar_field_value_type;

                    typedef scalar_field_value_type share_type;
                    typedef scalar_field_value_type coeff_type;
                    typedef group_value_type public_coeff_type;
                    typedef group_value_type public_share_type;
                    typedef std::vector<scalar_field_value_type> coeffs_type;
                    typedef std::vector<group_value_type> public_coeffs_type;
                    typedef coeffs_type shares_type;
                    typedef public_coeffs_type public_shares_type;
                    typedef std::unordered_map<std::size_t, scalar_field_value_type> indexed_shares_type;

                    //===========================================================================
                    // implicitly ordered in/out

                    template<typename CoeffsRange,
                             typename std::enable_if<
                                 std::is_same<scalar_field_value_type, typename CoeffsRange::value_type>::value,
                                 bool>::type = true>
                    static inline coeffs_type get_shares(const CoeffsRange &coeffs, std::size_t n) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));

                        std::size_t t = std::distance(coeffs.begin(), coeffs.end());
                        assert(check_t(t, n));

                        coeffs_type shares;
                        for (std::size_t i = 1; i <= n; i++) {
                            shares.emplace_back(get_share(coeffs, i));
                        }
                        return shares;
                    }

                    template<typename SharesRange,
                             typename std::enable_if<
                                 std::is_same<scalar_field_value_type, typename SharesRange::value_type>::value,
                                 bool>::type = true>
                    static inline scalar_field_value_type recover_secret(std::size_t t, const SharesRange &shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SharesRange>));

                        std::size_t shares_len = std::distance(shares.begin(), shares.end());
                        assert(shares_len >= t);

                        return recover_secret(shares);
                    }

                    template<typename SharesRange,
                             typename std::enable_if<
                                 std::is_same<scalar_field_value_type, typename SharesRange::value_type>::value,
                                 bool>::type = true>
                    static inline scalar_field_value_type recover_secret(const SharesRange &shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SharesRange>));

                        std::size_t shares_len = std::distance(shares.begin(), shares.end());
                        scalar_field_value_type result = scalar_field_value_type::zero();
                        std::size_t i = 1;

                        for (const auto &s_i : shares) {
                            result = result + s_i * eval_basis_poly(shares_len, i++);
                        }
                        return result;
                    }

                    //===========================================================================
                    // explicitly ordered in/out

                    template<typename CoeffsRange,
                             typename std::enable_if<
                                 std::is_same<scalar_field_value_type, typename CoeffsRange::value_type>::value,
                                 bool>::type = true>
                    static inline indexed_shares_type get_indexed_shares(const CoeffsRange &coeffs, std::size_t n) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));

                        std::size_t t = std::distance(coeffs.begin(), coeffs.end());
                        assert(check_t(t, n));

                        indexed_shares_type shares;
                        for (std::size_t i = 1; i <= n; i++) {
                            assert(shares.emplace(i, get_share(coeffs, i)).second);
                        }
                        return shares;
                    }

                    template<typename SharesContainer,
                             typename std::enable_if<std::is_integral<typename SharesContainer::key_type>::value &&
                                                         std::is_same<scalar_field_value_type,
                                                                      typename SharesContainer::mapped_type>::value,
                                                     bool>::type = true>
                    static inline scalar_field_value_type recover_secret(std::size_t t, const SharesContainer &shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::UniqueAssociativeContainer<const SharesContainer>));
                        BOOST_RANGE_CONCEPT_ASSERT((boost::PairAssociativeContainer<const SharesContainer>));

                        std::size_t shares_len = std::distance(shares.begin(), shares.end());
                        assert(shares_len >= t);

                        return recover_secret(shares);
                    }

                    template<typename SharesContainer,
                             typename std::enable_if<std::is_integral<typename SharesContainer::key_type>::value &&
                                                         std::is_same<scalar_field_value_type,
                                                                      typename SharesContainer::mapped_type>::value,
                                                     bool>::type = true>
                    static inline scalar_field_value_type recover_secret(const SharesContainer &shares) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::UniqueAssociativeContainer<const SharesContainer>));
                        BOOST_RANGE_CONCEPT_ASSERT((boost::PairAssociativeContainer<const SharesContainer>));

                        std::size_t shares_len = std::distance(shares.begin(), shares.end());
                        scalar_field_value_type result = scalar_field_value_type::zero();

                        for (const auto &[i, s_i] : shares) {
                            result = result + s_i * eval_basis_poly(shares_len, i);
                        }
                        return result;
                    }

                    //===========================================================================
                    // general functions

                    static inline coeffs_type get_poly(const std::size_t &t, const std::size_t &n) {
                        assert(check_t(t, n));

                        return get_poly(t);
                    }

                    // TODO: add custom random generation
                    static inline coeffs_type get_poly(const std::size_t &t) {
                        assert(t > 0);

                        coeffs_type coeffs;

                        for (std::size_t i = 0; i < t; i++) {
                            coeffs.emplace_back(algebra::random_element<scalar_field_type>());
                        }
                        return coeffs;
                    }

                    template<typename CoeffsRange,
                             typename std::enable_if<
                                 std::is_same<scalar_field_value_type, typename CoeffsRange::value_type>::value,
                                 bool>::type = true>
                    static inline public_coeffs_type get_public_poly(const CoeffsRange &coeffs) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));

                        public_coeffs_type public_coeffs;

                        for (const auto &c : coeffs) {
                            public_coeffs.emplace_back(get_public_share(c));
                        }
                        return public_coeffs;
                    }

                    template<typename CoeffsRange,
                             typename std::enable_if<
                                 std::is_same<scalar_field_value_type, typename CoeffsRange::value_type>::value,
                                 bool>::type = true>
                    static inline scalar_field_value_type get_share(const CoeffsRange &coeffs, std::size_t i) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));

                        scalar_field_value_type e_i(i);
                        scalar_field_value_type temp = scalar_field_value_type::one();
                        scalar_field_value_type share = scalar_field_value_type::zero();

                        for (const auto &c : coeffs) {
                            share = share + c * temp;
                            temp = temp * e_i;
                        }
                        return share;
                    }

                    static inline group_value_type get_public_share(const scalar_field_value_type &s_i) {
                        return s_i * group_value_type::one();
                    }

                    static inline scalar_field_value_type eval_basis_poly(std::size_t n, std::size_t i) {
                        assert(n > 0);
                        assert(i > 0 && i <= n);

                        scalar_field_value_type e_n(n), e_i(i);
                        scalar_field_value_type result = scalar_field_value_type::one();

                        for (scalar_field_value_type j = 1; j < e_i; j++) {
                            result = result * (j / (j - e_i));
                        }
                        for (scalar_field_value_type j = i + 1; j <= e_n; j++) {
                            result = result * (j / (j - e_i));
                        }
                        return result;
                    }

                    static inline bool check_t(std::size_t t, std::size_t n) {
                        return n > 0 && t > 0 && n >= 2 * t - 1;
                    }

                    static inline std::size_t get_minimum_t(std::size_t n) {
                        assert(n > 0);

                        return (n + 1) / 2;
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SHAMIR_SSS_HPP
