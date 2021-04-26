//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_ECKCDSA_KEY_HPP
#define CRYPTO3_PUBKEY_ECKCDSA_KEY_HPP

#include <nil/crypto3/pubkey/ecc_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                template<typename Scheme, typename Hash>
                struct emsa1;
            }

            template<typename CurveType>
            struct eckcdsa_public_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;

                inline static bool verify(const signature_type &val, const key_schedule_type &key) {
                    pk_operations::Verification_with_EMSA(emsa), m_group(eckcdsa.domain()),
                        m_public_point(eckcdsa.public_point()),
                        m_prefix()

                        //-----------------
                        const nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>
                            public_point_x = m_public_point.get_affine_x();
                    const nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> public_point_y =
                        m_public_point.get_affine_y();

                    m_prefix.resize(public_point_x.bytes() + public_point_y.bytes());
                    public_point_x.binary_encode(&m_prefix[0]);
                    public_point_y.binary_encode(&m_prefix[public_point_x.bytes()]);
                    m_prefix.resize(HashFunction::create(hash_for_signature())
                                        ->hash_block_size());    // use only the "hash input block size" leftmost bits

                    //-----------------

                    const std::unique_ptr<HashFunction> hash = HashFunction::create(hash_for_signature());
                    // calculate size of r

                    const size_t order_bytes = m_group.get_order_bytes();

                    const size_t size_r = std::min(hash->output_length(), order_bytes);
                    if (sig_len != size_r + order_bytes) {
                        return false;
                    }

                    secure_vector<uint8_t> r(sig, sig + size_r);

                    // check that 0 < s < q
                    const nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> s(sig + size_r,
                                                                                               order_bytes);

                    if (s <= 0 || s >= m_group.get_order()) {
                        return false;
                    }

                    secure_vector<uint8_t> r_xor_e(r);
                    xor_buf(r_xor_e, msg, r.size());
                    nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> w(r_xor_e.data(),
                                                                                         r_xor_e.size());
                    w = m_group.mod_order(w);

                    const point_gfp q = m_group.point_multiply(w, m_public_point, s);
                    const nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> q_x = q.get_affine_x();
                    secure_vector<uint8_t> c(q_x.bytes());
                    q_x.binary_encode(c.data());
                    std::unique_ptr<emsa> emsa = this->clone_emsa();
                    emsa->update(c.data(), c.size());
                    secure_vector<uint8_t> v = emsa->raw_data();
                    Null_RNG rng;
                    v = emsa->encoding_of(v, max_input_bits(), rng);

                    return (v == r);
                }
            };

            template<typename CurveType>
            struct eckcdsa_private_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;

                inline static bool sign(signature_type &res, const number_type &val, const key_schedule_type &key) {
                    const ec_group m_group;
                    const nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> &m_x;
                    secure_vector<uint8_t> m_prefix;
                    std::vector<nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>> m_ws;

                    //----------------

                    pk_operations::Signature_with_EMSA(emsa), m_group(eckcdsa.domain()), m_x(eckcdsa.private_value()),
                        m_prefix()

                        //-----------------
                        const nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>
                            public_point_x = eckcdsa.public_point().get_affine_x();
                    const nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> public_point_y =
                        eckcdsa.public_point().get_affine_y();

                    m_prefix.resize(public_point_x.bytes() + public_point_y.bytes());
                    public_point_x.binary_encode(m_prefix.data());
                    public_point_y.binary_encode(&m_prefix[public_point_x.bytes()]);
                    m_prefix.resize(HashFunction::create(hash_for_signature())
                                        ->hash_block_size());    // use only the "hash input block size" leftmost bits
                                                                 //---------------------

                    const nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> k =
                        m_group.random_scalar(rng);
                    const nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> k_times_P_x =
                        m_group.blinded_base_point_multiply_x(k, rng, m_ws);

                    secure_vector<uint8_t> to_be_hashed(k_times_P_x.bytes());
                    k_times_P_x.binary_encode(to_be_hashed.data());

                    std::unique_ptr<emsa> emsa = this->clone_emsa();
                    emsa->update(to_be_hashed.data(), to_be_hashed.size());
                    secure_vector<uint8_t> c = emsa->raw_data();
                    c = emsa->encoding_of(c, max_input_bits(), rng);

                    const nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> r(c.data(), c.size());

                    xor_buf(c, msg, c.size());
                    nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> w(c.data(), c.size());
                    w = m_group.mod_order(w);

                    const nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> s =
                        m_group.multiply_mod_order(m_x, k - w);
                    if (s.is_zero()) {
                        throw internal_error("During ECKCDSA signature generation created zero s");
                    }

                    secure_vector<uint8_t> output =
                        nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(r, c.size());
                    output += nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(
                        s, m_group.get_order_bytes());
                    return output;
                }
            };

            template<typename CurveType>
            struct eckcdsa {
                typedef CurveType curve_type;

                typedef eckcdsa_public_key<CurveType> public_key_type;
                typedef eckcdsa_private_key<CurveType> private_key_type;

                template<typename Hash>
                using padding_types = std::tuple<padding::emsa1<eckcdsa<CurveType>, Hash>>;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
