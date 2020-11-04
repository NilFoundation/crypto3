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

#include <boost/multiprecision/cpp_int.hpp>

#include <boost/concept/assert.hpp>

#include <cstdint>
#include <array>
#include <type_traits>
#include <iterator>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                using namespace boost::multiprecision;

                template<typename bls_key_policy>
                struct bls_functions {
                    typedef typename bls_key_policy::private_key_type private_key_type;
                    typedef typename bls_key_policy::public_key_type public_key_type;
                    typedef typename bls_key_policy::signature_type signature_type;
                    typedef typename bls_key_policy::gt_value_type gt_value_type;
                    typedef typename bls_key_policy::hash_type hash_type;
                    typedef typename bls_key_policy::number_type number_type;

                    using bls_key_policy::hash_to_point;
                    using bls_key_policy::pairing;

                    constexpr static std::size_t private_key_bits = bls_key_policy::private_key_bits;
                    /*constexpr*/ static inline const public_key_type pk_bp = bls_key_policy::pk_bp;
                    /*constexpr*/ static inline const signature_type sig_bp = bls_key_policy::sig_bp;

                    constexpr static std::size_t L = static_cast<std::size_t>((3 * bls_key_policy::private_key_bits) / 16) +
                                                     static_cast<std::size_t>((3 * bls_key_policy::private_key_bits) % 16 != 0);
                    static_assert(L < 0x10000, "L requires more than 2 octets");
                    constexpr static std::array<std::uint8_t, 2> L_os = {static_cast<std::uint8_t>(L >> 8u),
                                                                         static_cast<std::uint8_t>(L % 0x100)};

                    template<typename IkmType, typename KeyInfoType,
                             typename = typename std::enable_if<
                                 std::is_same<std::uint8_t, typename IkmType::value_type>::value &&
                                 std::is_same<std::uint8_t, typename KeyInfoType::value_type>::value>::type>
                    static inline private_key_type key_gen(const IkmType &ikm,
                                                                const KeyInfoType &key_info =
                                                                    std::array<std::uint8_t, 0> {}) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<IkmType>));
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<KeyInfoType>));

                        assert(std::distance(ikm.begin(), ikm.end()) >= 32);

                        // "BLS-SIG-KEYGEN-SALT-"
                        std::array<std::uint8_t, 20> salt = {66, 76, 83, 45, 83,
                                                             73, 71, 45, 75, 69,
                                                             89, 71, 69, 78, 45,
                                                             83, 65, 76, 84, 45};
                        number_type sk(0);
                        cpp_int e;

                        // TODO: use accumulators when they will be fixed
                        std::vector<std::uint8_t> ikm_zero = ikm;
                        ikm_zero.insert(ikm_zero.end(), static_cast<std::uint8_t>(0));
                        // TODO: use accumulators when they will be fixed
                        std::vector<std::uint8_t> key_info_L_os = key_info;
                        key_info_L_os.insert(key_info_L_os.end(), L_os.begin(), L_os.end());

                        while (e % bls_key_policy::r == 0) {
                            salt = hash<hash_type>(salt);
                            // TODO: will work when hkdf finished
                            auto prk = hkdf_extract<hash_type>(salt, ikm_zero);
                            auto okm = hkdf_expand<hash_type>(prk, key_info_L_os, L);
                            import_bits(e, okm.begin(),okm.end());
                        }

                        return private_key_type(static_cast<number_type>(e));
                    }

                    template<typename PubkeyType, typename = typename std::enable_if<
                        std::is_same<std::uint8_t, typename PubkeyType::value_type>::value>::type>
                    static inline PubkeyType sk_to_pk(const private_key_type &sk) {
                        // TODO: implement such method
                        return (sk * pk_bp).to_octets();
                    }

                    template<typename PubkeyType, typename = typename std::enable_if<
                        std::is_same<std::uint8_t, typename PubkeyType::value_type>::value>::type>
                    static inline bool key_validate(const PubkeyType &pk_os) {
                        // TODO: somehow treat assertion during creating pubkey point
                        // TODO: implement such method
                        public_key_type pk = public_key_type::from_octet_string(pk_os);
                        if (pk.is_one()) {
                            return false;
                        }
                        // TODO: will work when is_in_subgroup finished
                        if (!pk.is_in_subgroup()) {
                            return false;
                        }
                        return true;
                    }

                    template<typename MsgType, typename DstType, typename SigType,
                             typename = typename std::enable_if<
                                 std::is_same<std::uint8_t, typename MsgType::value_type>::value &&
                                 std::is_same<std::uint8_t, typename DstType::value_type>::value &&
                                 std::is_same<std::uint8_t, typename SigType::value_type>::value>::type>
                    static inline SigType core_sign(const private_key_type &sk, const MsgType &msg, const DstType &dst) {
                        signature_type Q = hash_to_point(msg, dst);
                        // TODO: implement such method
                        return (sk * Q).to_octets();
                    }

                    template<typename PubkeyType, typename MsgType, typename DstType, typename SigType,
                             typename = typename std::enable_if<
                                 std::is_same<std::uint8_t, typename PubkeyType::value_type>::value &&
                                 std::is_same<std::uint8_t, typename MsgType::value_type>::value &&
                                 std::is_same<std::uint8_t, typename DstType::value_type>::value &&
                                 std::is_same<std::uint8_t, typename SigType::value_type>::value>::type>
                    static inline bool core_verify(const PubkeyType &pk_os, const MsgType &msg,
                                                   const DstType &dst, const SigType &sig_os) {
                        // TODO: somehow treat assertion during creating sig point
                        // TODO: implement such method
                        signature_type R = signature_type::from_octet_string(sig_os);
                        // TODO: will work when is_in_subgroup finished
                        if (!R.is_in_subgroup()) {
                            return false;
                        }
                        if (!key_validate(pk_os)) {
                            return false;
                        }
                        // TODO: somehow treat assertion during creating pubkey point
                        // TODO: implement such method
                        public_key_type pk = public_key_type::from_octet_string(pk_os);
                        signature_type Q = hash_to_point(msg, dst);
                        auto C1 = pairing(Q, pk);
                        auto C2 = pairing(R, pk_bp);
                        return C1 == C2;
                    }

                    template<typename SigTypeIn, typename SigTypeOut,
                             typename = typename std::enable_if<
                                 std::is_same<std::uint8_t, typename SigTypeIn::value_type>::value &&
                                 std::is_same<std::uint8_t, typename SigTypeOut::value_type>::value>::type>
                    // TODO: generalize std::vector
                    static inline SigTypeOut aggregate(const std::vector<SigTypeIn> &sig_os_n) {
                        assert(sig_os_n.size() > 0);

                        // TODO: somehow treat assertion during creating sig point
                        // TODO: implement such method
                        signature_type aggregate_p = signature_type::from_octet_string(sig_os_n[0]);
                        for (std::size_t i = 1; i < sig_os_n.size(); i++) {
                            // TODO: somehow treat assertion during creating sig point
                            // TODO: implement such method
                            signature_type next_p = signature_type::from_octet_string(sig_os_n[i]);
                            aggregate_p = aggregate_p + next_p;
                        }
                        return aggregate_p.to_octets();
                    }

                    template<typename PubkeyType, typename MsgType, typename DstType, typename SigType,
                             typename = typename std::enable_if<
                                 std::is_same<std::uint8_t, typename PubkeyType::value_type>::value &&
                                 std::is_same<std::uint8_t, typename MsgType::value_type>::value &&
                                 std::is_same<std::uint8_t, typename DstType::value_type>::value &&
                                 std::is_same<std::uint8_t, typename SigType::value_type>::value>::type>
                    static inline bool core_aggregate_verify(const std::vector<PubkeyType> &pk_os_n,
                                                             const std::vector<MsgType> &msg_n,
                                                             const DstType &dst, const SigType &sig_os) {
                        assert(pk_os_n.size() > 0 && pk_os_n.size() == msg_n.size());

                        // TODO: somehow treat assertion during creating sig point
                        // TODO: implement such method
                        signature_type R = signature_type::from_octet_string(sig_os);
                        // TODO: will work when is_in_subgroup finished
                        if (!R.is_in_subgroup()) {
                            return false;
                        }
                        gt_value_type C1 = gt_value_type::one();
                        for (std::size_t i = 0; i < pk_os_n.size(); i++) {
                            if (!key_validate(pk_os_n[i])) {
                                return false;
                            }
                            // TODO: somehow treat assertion during creating pubkey point
                            // TODO: implement such method
                            public_key_type pk = public_key_type::from_octet_string(pk_os_n[i]);
                            signature_type Q = hash_to_point(msg_n[i], dst);
                            C1 = C1 * pairing(Q, pk);
                        }
                        return C1 == pairing(R, pk_bp);
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif // CRYPTO3_PUBKEY_BLS_FUNCTIONS_HPP
