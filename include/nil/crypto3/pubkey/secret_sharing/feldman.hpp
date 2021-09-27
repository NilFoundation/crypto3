//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_FELDMAN_SSS_HPP
#define CRYPTO3_PUBKEY_FELDMAN_SSS_HPP

#include <nil/crypto3/pubkey/secret_sharing/shamir.hpp>

#include <nil/crypto3/pubkey/operations/verify_share_op.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Group>
            struct feldman_sss : shamir_sss<Group> {
                typedef shamir_sss<Group> base_type;
                typedef typename base_type::group_type group_type;
                typedef typename base_type::basic_policy basic_policy;

                //
                //  partial computing of verification value
                //
                static inline typename basic_policy::public_share_type partial_eval_verification_value(
                    const typename basic_policy::public_coeff_type &public_coeff, std::size_t exp,
                    const typename basic_policy::public_share_type &init_verification_value) {
                    assert(basic_policy::check_participant_index(init_verification_value.first));
                    assert(basic_policy::check_exp(exp));

                    return typename basic_policy::public_share_type(
                        init_verification_value.first,
                        init_verification_value.second +
                            typename basic_policy::private_element_type(init_verification_value.first).pow(exp) *
                                public_coeff);
                }
            };

            template<typename Group>
            struct public_share_sss<feldman_sss<Group>> : public virtual public_share_sss<shamir_sss<Group>> {
                typedef public_share_sss<shamir_sss<Group>> base_type;
                typedef feldman_sss<Group> scheme_type;

                public_share_sss() = default;

                public_share_sss(const typename base_type::public_share_type &in_public_share) :
                    public_share_sss<shamir_sss<Group>>(in_public_share) {
                }

                public_share_sss(typename base_type::public_share_type::first_type i,
                                 const typename base_type::public_share_type::second_type &ps) :
                    base_type(i, ps) {
                }
            };

            template<typename Group>
            struct share_sss<feldman_sss<Group>> : public virtual public_share_sss<feldman_sss<Group>>,
                                                   public virtual share_sss<shamir_sss<Group>> {
                typedef public_share_sss<shamir_sss<Group>> base_type1;
                typedef public_share_sss<feldman_sss<Group>> base_type2;
                typedef share_sss<shamir_sss<Group>> base_type3;
                typedef feldman_sss<Group> scheme_type;
                typedef typename base_type3::share_type share_type;

                share_sss(const share_type &in_share) : share_sss(in_share.first, in_share.second) {
                }

                share_sss(typename share_type::first_type i, const typename share_type::second_type &s) :
                    base_type1(i, s * base_type2::public_share_type::second_type::one()),
                    /// no need to initialize base_type2 as it virtually derived from base_type1
                    base_type2(), base_type3(i, s) {
                }
            };

            template<typename Group>
            struct secret_sss<feldman_sss<Group>> : public secret_sss<shamir_sss<Group>> {
                typedef secret_sss<shamir_sss<Group>> base_type;
                typedef feldman_sss<Group> scheme_type;

                template<typename Shares>
                secret_sss(const Shares &shares, const typename base_type::indexes_type &indexes,
                           std::size_t id_i = 0) :
                    secret_sss(std::cbegin(shares), std::cend(shares), indexes, id_i) {
                }

                template<typename ShareIt>
                secret_sss(ShareIt first, ShareIt last, const typename base_type::indexes_type &indexes,
                           std::size_t id_i = 0) :
                    base_type(first, last, indexes, id_i) {
                }
            };

            template<typename Group>
            struct deal_shares_op<feldman_sss<Group>> : public deal_shares_op<shamir_sss<Group>> {
                typedef deal_shares_op<shamir_sss<Group>> base_type;
                typedef feldman_sss<Group> scheme_type;
                typedef share_sss<scheme_type> share_type;
                typedef std::vector<share_type> shares_type;
                typedef std::vector<typename share_type::share_type> internal_accumulator_type;

                static inline void init_accumulator(internal_accumulator_type &acc, std::size_t n, std::size_t t) {
                    base_type::template _init_accumulator<share_type>(acc, n, t);
                }

                static inline void update(internal_accumulator_type &acc, std::size_t exp,
                                          const typename scheme_type::coeff_type &coeff) {
                    base_type::_update(acc, exp, coeff);
                }

                static inline shares_type process(internal_accumulator_type &acc) {
                    return base_type::template _process<shares_type>(acc);
                }
            };

            template<typename Group>
            struct verify_share_op<feldman_sss<Group>> {
                typedef feldman_sss<Group> scheme_type;
                typedef public_share_sss<scheme_type> public_share_type;
                typedef typename public_share_type::public_share_type internal_accumulator_type;

            protected:
                template<typename PublicShare, typename InternalAccumulator>
                static inline void _init_accumulator(InternalAccumulator &acc, std::size_t i) {
                    acc = internal_accumulator_type(i, PublicShare::public_share_type::second_type::zero());
                }

                template<typename InternalAccumulator>
                static inline void _update(InternalAccumulator &acc, std::size_t exp,
                                           const typename scheme_type::public_coeff_type &public_coeff) {
                    acc.second = scheme_type::partial_eval_verification_value(public_coeff, exp, acc).second;
                }

                template<typename PublicShare, typename InternalAccumulator>
                static inline bool _process(const InternalAccumulator &acc, const PublicShare &verified_public_share) {
                    return acc.first == verified_public_share.get_index() &&
                           acc.second == verified_public_share.get_value();
                }

            public:
                static inline void init_accumulator(internal_accumulator_type &acc, std::size_t i) {
                    _init_accumulator<public_share_type>(acc, i);
                }

                static inline void update(internal_accumulator_type &acc, std::size_t exp,
                                          const typename scheme_type::public_coeff_type &public_coeff) {
                    _update(acc, exp, public_coeff);
                }

                static inline bool process(const internal_accumulator_type &acc,
                                           const public_share_type &verified_public_share) {
                    return _process<public_share_type>(acc, verified_public_share);
                }
            };

            template<typename Group>
            struct reconstruct_secret_op<feldman_sss<Group>> : public reconstruct_secret_op<shamir_sss<Group>> {
                typedef reconstruct_secret_op<shamir_sss<Group>> base_type;
                typedef feldman_sss<Group> scheme_type;
                typedef share_sss<scheme_type> share_type;
                typedef secret_sss<scheme_type> secret_type;
                typedef std::pair<typename scheme_type::indexes_type, std::vector<share_type>>
                    internal_accumulator_type;

            public:
                static inline void init_accumulator() {
                }

                static inline void update(internal_accumulator_type &acc, const share_type &share) {
                    base_type::_update(acc, share);
                }

                static inline secret_type process(internal_accumulator_type &acc) {
                    return base_type::template _process<secret_type>(acc);
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_FELDMAN_SSS_HPP
