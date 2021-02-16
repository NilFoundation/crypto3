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

#ifndef CRYPTO3_PUBKEY_SHAMIR_SCHEME_HPP
#define CRYPTO3_PUBKEY_SHAMIR_SCHEME_HPP

#include <vector>
#include <type_traits>

#include <boost/concept_check.hpp>
#include <boost/range/concepts.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Group>
                struct shamir_scheme {
                    typedef Group group_type;

                    typedef typename group_type::policy_type::base_field_type base_field_type;
                    typedef typename group_type::policy_type::scalar_field_type scalar_field_type;

                    typedef typename group_type::value_type group_value_type;
                    typedef typename base_field_type::value_type base_field_value_type;
                    typedef typename scalar_field_type::value_type scalar_field_value_type;

                    typedef std::vector<scalar_field_value_type> coeffs_type;
                    typedef std::vector<group_value_type> public_coeffs_type;
                    typedef std::vector<scalar_field_value_type> shares_type;

                    template<typename CoeffsRange, typename Number,
                             std::enable_if<std::is_same<scalar_field_type, typename CoeffsRange::value_type>::value,
                                            bool>::type = true>
                    static inline scalar_field_value_type get_share(const CoeffsRange &coeffs, const Number &i) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));

                        scalar_field_value_type in(i);
                        scalar_field_value_type temp = scalar_field_value_type::one();
                        scalar_field_value_type share = scalar_field_value_type::zero();

                        for (const auto &c : coeffs) {
                            share = share + c * temp;
                            temp = temp * in;
                        }
                        return share;
                    }

                    static inline group_value_type get_public_share(const scalar_field_value_type &s_i) {
                        return s_i * group_value_type::one();
                    }

                    template<typename Number1, typename Number2>
                    static inline scalar_field_value_type eval_basis_poly(const Number1 &n, const Number2 &i) {
                        assert(n > 0);
                        assert(i > 0 && i <= n);

                        scalar_field_value_type e_n(n), e_i(i);
                        scalar_field_value_type result = scalar_field_value_type::one();

                        for (scalar_field_value_type j = 1; j < e_i; j++) {
                            result = result * (j / (j - e_i));
                        }
                        for (scalar_field_value_type j = e_i + 1; j <= e_n; j++) {
                            result = result * (j / (j - e_i));
                        }
                        return result;
                    }

                    template<typename SharesRange, typename Number1, typename Number2,
                             std::enable_if<std::is_same<scalar_field_type, typename SharesRange::value_type>::value,
                                            bool>::type = true>
                    static inline scalar_field_value_type recover_secret(const SharesRange &shares, const Number1 &t,
                                                                         const Number2 &n) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                        auto shares_len = std::distance(shares.begin(), shares.end());
                        assert(shares_len >= t);
                        assert(check_t(t, n));

                        return recover_secret(shares, n);
                    }

                    template<typename SharesRange, typename Number,
                             std::enable_if<std::is_same<scalar_field_type, typename SharesRange::value_type>::value,
                                            bool>::type = true>
                    static inline scalar_field_value_type recover_secret(const SharesRange &shares, const Number &n) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SharesRange>));

                        auto shares_len = std::distance(shares.begin(), shares.end());
                        assert(shares_len <= n);

                        scalar_field_value_type result = scalar_field_value_type::zero();
                        Number i = 1;

                        for (const auto &s_i : shares) {
                            result = result + s_i * eval_basis_poly(n, i++);
                        }
                        return result;
                    }

                    template<typename CoeffsRange,
                             std::enable_if<std::is_same<scalar_field_type, typename CoeffsRange::value_type>::value,
                                            bool>::type = true>
                    static inline scalar_field_value_type get_secret(const CoeffsRange &coeffs) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));

                        return get_share(coeffs, 0);
                    }

                    template<typename CoeffsRange, typename Number,
                             std::enable_if<std::is_same<scalar_field_type, typename CoeffsRange::value_type>::value,
                                            bool>::type = true>
                    static inline shares_type get_shares(const CoeffsRange &coeffs, const Number &n) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));

                        assert(n > 0);
                        assert(check_t(coeffs.size(), n));

                        shares_type shares;
                        for (Number i = 1; i <= n; i++) {
                            shares.emplace_back(get_share(coeffs, i));
                        }
                        return shares;
                    }

                    template<typename Number>
                    static inline coeffs_type get_poly(const Number &t) {
                        coeffs_type coeffs;

                        for (Number i = 0; i < t; i++) {
                            coeffs.emplace_back(algebra::random_element<scalar_field_type>());
                        }
                        return coeffs;
                    }

                    // TODO: add custom random generation
                    // template<typename RandomDistribution, typename RandomGenerator, typename Number>
                    // static inline coeffs_type get_poly(const Number &t) {
                    //     coeffs_type coeffs;
                    //
                    //     for (Number i = 0; i < t; i++) {
                    //         coeffs.emplace_back(
                    //             algebra::random_element<scalar_field_type, RandomDistribution, RandomGenerator>());
                    //     }
                    //     return coeffs;
                    // }

                    template<typename CoeffsRange,
                             std::enable_if<std::is_same<scalar_field_type, typename CoeffsRange::value_type>::value,
                                            bool>::type = true>
                    static inline public_coeffs_type get_public_poly(const CoeffsRange &coeffs) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));

                        public_coeffs_type public_coeffs;

                        for (const auto &c : coeffs) {
                            public_coeffs.emplace_back(c * group_value_type::one());
                        }
                        return public_coeffs;
                    }

                    template<typename Number1, typename Number2>
                    static inline bool check_t(const Number1 &t, const Number2 &n) {
                        return n >= 2 * t - 1;
                    }

                    template<typename Number>
                    static inline std::size_t get_minimum_t(const Number &n) {
                        assert(n > 0);

                        return (n + 1) / 2;
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SHAMIR_SCHEME_HPP
