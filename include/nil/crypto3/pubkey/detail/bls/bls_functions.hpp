//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_BLS_FUNCTIONS_HPP
#define CRYPTO3_PUBKEY_BLS_FUNCTIONS_HPP

#include <nil/crypto3/algebra/curves/detail/subgroup_check.hpp>

#include <boost/multiprecision/cpp_int.hpp>

#include <boost/concept/assert.hpp>

#include <cstdint>
#include <array>
#include <type_traits>
#include <iterator>

template<typename Fp2CurveGroupElement>
void print_fp2_curve_group_element(std::ostream &os, const Fp2CurveGroupElement &e);

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                using namespace boost::multiprecision;
                using namespace nil::crypto3::algebra::curves::detail;

                template<typename bls_key_policy>
                struct bls_functions : bls_key_policy {
                    using typename bls_key_policy::private_key_type;
                    using typename bls_key_policy::public_key_type;
                    using typename bls_key_policy::signature_type;
                    using typename bls_key_policy::gt_value_type;
                    using typename bls_key_policy::hash_type;
                    using typename bls_key_policy::number_type;

                    using bls_key_policy::hash_to_point;
                    using bls_key_policy::pairing;

                    using bls_key_policy::private_key_bits;

                    constexpr static std::size_t L = static_cast<std::size_t>((3 * private_key_bits) / 16) +
                                                     static_cast<std::size_t>((3 * private_key_bits) % 16 != 0);
                    static_assert(L < 0x10000, "L is required to fit in 2 octets");
                    constexpr static std::array<std::uint8_t, 2> L_os = {static_cast<std::uint8_t>(L >> 8u),
                                                                         static_cast<std::uint8_t>(L % 0x100)};

                    // template<typename IkmType, typename KeyInfoType,
                    //          typename = typename std::enable_if<
                    //              std::is_same<std::uint8_t, typename IkmType::value_type>::value &&
                    //              std::is_same<std::uint8_t, typename KeyInfoType::value_type>::value>::type>
                    // static inline private_key_type key_gen(const IkmType &ikm,
                    //                                        const KeyInfoType &key_info) {
                    //     BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<IkmType>));
                    //     BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<KeyInfoType>));
                    //
                    //     assert(std::distance(ikm.begin(), ikm.end()) >= 32);
                    //
                    //     // "BLS-SIG-KEYGEN-SALT-"
                    //     std::array<std::uint8_t, 20> salt = {66, 76, 83, 45, 83,
                    //                                          73, 71, 45, 75, 69,
                    //                                          89, 71, 69, 78, 45,
                    //                                          83, 65, 76, 84, 45};
                    //     number_type sk(0);
                    //     cpp_int e;
                    //
                    //     // TODO: use accumulators when they will be fixed
                    //     std::vector<std::uint8_t> ikm_zero = ikm;
                    //     ikm_zero.insert(ikm_zero.end(), static_cast<std::uint8_t>(0));
                    //     // TODO: use accumulators when they will be fixed
                    //     std::vector<std::uint8_t> key_info_L_os = key_info;
                    //     key_info_L_os.insert(key_info_L_os.end(), L_os.begin(), L_os.end());
                    //
                    //     while (e % bls_key_policy::r == 0) {
                    //         salt = hash<hash_type>(salt);
                    //         // TODO: will work when hkdf finished
                    //         auto prk = hkdf_extract<hash_type>(salt, ikm_zero);
                    //         auto okm = hkdf_expand<hash_type>(prk, key_info_L_os, L);
                    //         import_bits(e, okm.begin(),okm.end());
                    //     }
                    //     // TODO: via modular type
                    //     return private_key_type(static_cast<number_type>(e));
                    // }

                    static inline bool private_key_validate(const private_key_type &sk) {
                        return !sk.is_zero();
                    }

                    static inline public_key_type sk_to_pk(const private_key_type &sk) {
                        assert(!private_key_validate(sk));

                        return sk * public_key_type::one();
                    }

                    static inline bool public_key_validate(const public_key_type &pk) {
                        if (pk.is_zero()) {
                            return false;
                        }
                        // TODO: subgroup_check should be reimplemented as class method
                        if (!subgroup_check(pk)) {
                            return false;
                        }
                        return true;
                    }

                    template<typename MsgType, typename DstType,
                             typename = typename std::enable_if<
                                 std::is_same<std::uint8_t, typename MsgType::value_type>::value &&
                                 std::is_same<std::uint8_t, typename DstType::value_type>::value>::type>
                    static inline signature_type core_sign(const private_key_type &sk, const MsgType &msg,
                                                           const DstType &dst) {
                        assert(!private_key_validate(sk));

                        signature_type Q = hash_to_point(msg, dst);
                        print_fp2_curve_group_element(std::cout, Q);
                        return sk * Q;
                    }

                    template<typename MsgType, typename DstType,
                             typename = typename std::enable_if<
                                 std::is_same<std::uint8_t, typename MsgType::value_type>::value &&
                                 std::is_same<std::uint8_t, typename DstType::value_type>::value>::type>
                    static inline bool core_verify(const public_key_type &pk, const MsgType &msg,
                                                   const DstType &dst, const signature_type &sig) {
                        // TODO: subgroup_check should be reimplemented as class method
                        if (!subgroup_check(sig)) {
                            return false;
                        }
                        if (!key_validate(pk)) {
                            return false;
                        }
                        signature_type Q = hash_to_point(msg, dst);
                        auto C1 = pairing(Q, pk);
                        auto C2 = pairing(sig, public_key_type::one());
                        return C1 == C2;
                    }

                    template<typename SignatureRangeType, typename = typename std::enable_if<
                        std::is_same<signature_type, typename SignatureRangeType::value_type>::value>::type>
                    static inline signature_type aggregate(const SignatureRangeType &sig_n) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SignatureRangeType>));

                        assert(std::distance(sig_n.begin(), sig_n.end()) > 0);

                        auto sig_n_iter = sig_n.begin();
                        signature_type aggregate_p = *sig_n_iter++;
                        while (sig_n_iter != sig_n.end()) {
                            signature_type next_p = *sig_n_iter++;
                            aggregate_p = aggregate_p + next_p;
                        }
                        return aggregate_p;
                    }

                    template<typename PubkeyRangeType, typename MsgRangeType, typename DstType,
                             typename = typename std::enable_if<
                                 std::is_same<public_key_type, typename PubkeyRangeType::value_type>::value &&
                                 std::is_same<std::uint8_t, typename MsgRangeType::value_type::value_type>::value &&
                                 std::is_same<std::uint8_t, typename DstType::value_type>::value>::type>
                    static inline bool core_aggregate_verify(const PubkeyRangeType &pk_n,
                                                             const MsgRangeType &msg_n,
                                                             const DstType &dst, const signature_type &sig) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<PubkeyRangeType>));
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<MsgRangeType>));

                        assert(std::distance(pk_n.begin(), pk_n.end()) > 0 &&
                               std::distance(pk_n.begin(), pk_n.end()) == std::distance(msg_n.begin(), msg_n.end()));

                        // TODO: subgroup_check should be reimplemented as class method
                        if (!subgroup_check(sig)) {
                            return false;
                        }

                        auto pk_n_iter = pk_n.begin();
                        auto msg_n_iter = msg_n.begin();
                        gt_value_type C1 = gt_value_type::zero();
                        while (pk_n_iter != pk_n.end() && msg_n_iter != msg_n.end()) {
                            if (!key_validate(*pk_n_iter)) {
                                return false;
                            }
                            signature_type Q = hash_to_point(*msg_n_iter++, dst);
                            C1 = C1 * pairing(Q, *pk_n_iter++);
                        }
                        return C1 == pairing(sig, public_key_type::one());
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif // CRYPTO3_PUBKEY_BLS_FUNCTIONS_HPP
