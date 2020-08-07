//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_SM2_KEY_HPP
#define CRYPTO3_PUBKEY_SM2_KEY_HPP

#include <cstdint>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Hash, typename CurveType>
                std::vector<uint8_t> sm2_compute_za(const std::string &user_id, const ec_group &domain,
                                                    const typename CurveType::value_type &pubkey) {
                    if (user_id.size() >= 8192) {
                        throw std::invalid_argument("SM2 user id too long to represent");
                    }

                    const uint16_t uid_len = static_cast<uint16_t>(8 * user_id.size());

                    hash.update(extract_uint_t<CHAR_BIT>(uid_len, 0));
                    hash.update(extract_uint_t<CHAR_BIT>(uid_len, 1));
                    hash.update(user_id);

                    const size_t p_bytes = domain.get_p_bytes();

                    hash.update(number<Backend, ExpressionTemplates>::encode_1363(domain.a(), p_bytes));
                    hash.update(number<Backend, ExpressionTemplates>::encode_1363(domain.b(), p_bytes));
                    hash.update(number<Backend, ExpressionTemplates>::encode_1363(domain.get_g_x(), p_bytes));
                    hash.update(number<Backend, ExpressionTemplates>::encode_1363(domain.get_g_y(), p_bytes));
                    hash.update(number<Backend, ExpressionTemplates>::encode_1363(pubkey.get_affine_x(), p_bytes));
                    hash.update(number<Backend, ExpressionTemplates>::encode_1363(pubkey.get_affine_y(), p_bytes));

                    std::vector<uint8_t> za(hash.output_length());
                    hash.final(za.data());

                    return za;
                }
            }

            template<typename CurveType>
            struct sm2_public_key {
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
                    m_group(sm2.domain()),
                        m_public_point(sm2.public_point()), m_hash(HashFunction::create_or_throw(hash))
                        // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
                        m_za = sm2_compute_za(*m_hash, ident, m_group, m_public_point);
                        m_hash->update(m_za);

                        //---------

                    const number<Backend, ExpressionTemplates> e =
                        number<Backend, ExpressionTemplates>::decode(m_hash->final());

                    // Update for next verification
                    m_hash->update(m_za);

                    if (sig_len != m_group.get_order().bytes() * 2) {
                        return false;
                    }

                    const number<Backend, ExpressionTemplates> r(sig, sig_len / 2);
                    const number<Backend, ExpressionTemplates> s(sig + sig_len / 2, sig_len / 2);

                    if (r <= 0 || r >= m_group.get_order() || s <= 0 || s >= m_group.get_order()) {
                        return false;
                    }

                    const number<Backend, ExpressionTemplates> t = m_group.mod_order(r + s);

                    if (t == 0) {
                        return false;
                    }

                    const point_gfp R = m_group.point_multiply(s, m_public_point, t);

                    // ???
                    if (R.is_zero()) {
                        return false;
                    }

                    return (m_group.mod_order(R.get_affine_x() + e) == r);
                }

                inline static bool encrypt(const signature_type &res, const number_type &val,
                                           const key_schedule_type &key) {

                    m_group(key.domain()), m_mul_public_point(key.public_point()), m_kdf_hash(kdf_hash)

//-----------

                    std::unique_ptr<HashFunction> hash = HashFunction::create_or_throw(m_kdf_hash);
                    std::unique_ptr<KDF> kdf = KDF::create_or_throw("KDF2(" + m_kdf_hash + ")");

                    const size_t p_bytes = m_group.get_p_bytes();

                    const boost::multiprecision::number<Backend, ExpressionTemplates> k =
                        m_group.random_scalar(rng);

                    const point_gfp C1 = m_group.blinded_base_point_multiply(k, rng, m_ws);
                    const boost::multiprecision::number<Backend, ExpressionTemplates> x1 = C1.get_affine_x();
                    const boost::multiprecision::number<Backend, ExpressionTemplates> y1 = C1.get_affine_y();
                    std::vector<uint8_t> x1_bytes(p_bytes);
                    std::vector<uint8_t> y1_bytes(p_bytes);
                    boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(
                        x1_bytes.data(), x1_bytes.size(), x1);
                    boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(
                        y1_bytes.data(), y1_bytes.size(), y1);

                    const point_gfp kPB = m_mul_public_point.mul(k, rng, m_group.get_order(), m_ws);

                    const boost::multiprecision::number<Backend, ExpressionTemplates> x2 = kPB.get_affine_x();
                    const boost::multiprecision::number<Backend, ExpressionTemplates> y2 = kPB.get_affine_y();
                    std::vector<uint8_t> x2_bytes(p_bytes);
                    std::vector<uint8_t> y2_bytes(p_bytes);
                    boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(
                        x2_bytes.data(), x2_bytes.size(), x2);
                    boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(
                        y2_bytes.data(), y2_bytes.size(), y2);

                    secure_vector<uint8_t> kdf_input;
                    kdf_input += x2_bytes;
                    kdf_input += y2_bytes;

                    const secure_vector<uint8_t> kdf_output =
                        kdf->derive_key(msg_len, kdf_input.data(), kdf_input.size());

                    secure_vector<uint8_t> masked_msg(msg_len);
                    xor_buf(masked_msg.data(), msg, kdf_output.data(), msg_len);

                    hash->update(x2_bytes);
                    hash->update(msg, msg_len);
                    hash->update(y2_bytes);
                    std::vector<uint8_t> C3(hash->output_length());
                    hash->final(C3.data());

                    return der_encoder()
                        .start_cons(SEQUENCE)
                        .encode(x1)
                        .encode(y1)
                        .encode(C3, OCTET_STRING)
                        .encode(masked_msg, OCTET_STRING)
                        .end_cons()
                        .get_contents();
                }
            };

            template<typename CurveType>
            struct sm2_private_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;

                template<typename NonceGenerator>
                inline static bool sign(signature_type &res, const number_type &val, const key_schedule_type &key) {
                    m_da_inv = inverse_mod(m_private_key + 1, domain().get_order());

                    //--------

                    m_group(sm2.domain()), m_x(sm2.private_value()), m_da_inv(sm2.get_da_inv()),
                        m_hash(HashFunction::create_or_throw(hash))
                        // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
                        m_za = sm2_compute_za(*m_hash, ident, m_group, sm2.public_point());
                        m_hash->update(m_za);

                        //--------

                        const number<Backend, ExpressionTemplates> e =
                            number<Backend, ExpressionTemplates>::decode(m_hash->final());

                        const number<Backend, ExpressionTemplates> k = m_group.random_scalar(rng);

                        const number<Backend, ExpressionTemplates> r =
                            m_group.mod_order(m_group.blinded_base_point_multiply_x(k, rng, m_ws) + e);
                        const number<Backend, ExpressionTemplates> s =
                            m_group.multiply_mod_order(m_da_inv, (k - r * m_x));

                        // prepend ZA for next signature if any
                        m_hash->update(m_za);

                        return number<Backend, ExpressionTemplates>::encode_fixed_length_int_pair(
                            r, s, m_group.get_order().bytes());
                    }

                    inline static bool decrypt(signature_type & res, const number_type &val,
                                               const key_schedule_type &key) {
                        m_key(key),
                            m_rng(rng), m_kdf_hash(kdf_hash)
                        //------------

                        const ec_group &group = m_key.domain();
                        const boost::multiprecision::number<Backend, ExpressionTemplates> &cofactor =
                            group.get_cofactor();
                        const size_t p_bytes = group.get_p_bytes();

                        valid_mask = 0x00;

                        std::unique_ptr<HashFunction> hash = HashFunction::create_or_throw(m_kdf_hash);
                        std::unique_ptr<KDF> kdf = KDF::create_or_throw("KDF2(" + m_kdf_hash + ")");

                        // Too short to be valid - no timing problem from early return
                        if (ciphertext_len < 1 + p_bytes * 2 + hash->output_length()) {
                            return secure_vector<uint8_t>();
                        }

                        boost::multiprecision::number<Backend, ExpressionTemplates> x1, y1;
                        secure_vector<uint8_t> C3, masked_msg;

                        ber_decoder(ciphertext, ciphertext_len)
                            .start_cons(SEQUENCE)
                            .decode(x1)
                            .decode(y1)
                            .decode(C3, OCTET_STRING)
                            .decode(masked_msg, OCTET_STRING)
                            .end_cons()
                            .verify_end();

                        point_gfp C1 = group.point(x1, y1);
                        C1.randomize_repr(m_rng);

                        if (!C1.on_the_curve()) {
                            return secure_vector<uint8_t>();
                        }

                        if (cofactor > 1 && (C1 * cofactor).is_zero()) {
                            return secure_vector<uint8_t>();
                        }

                        const point_gfp dbC1 =
                            group.blinded_var_point_multiply(C1, m_key.private_value(), m_rng, m_ws);

                        const boost::multiprecision::number<Backend, ExpressionTemplates> x2 = dbC1.get_affine_x();
                        const boost::multiprecision::number<Backend, ExpressionTemplates> y2 = dbC1.get_affine_y();

                        std::vector<uint8_t> x2_bytes(p_bytes);
                        std::vector<uint8_t> y2_bytes(p_bytes);
                        boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(
                            x2_bytes.data(), x2_bytes.size(), x2);
                        boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(
                            y2_bytes.data(), y2_bytes.size(), y2);

                        secure_vector<uint8_t> kdf_input;
                        kdf_input += x2_bytes;
                        kdf_input += y2_bytes;

                        const secure_vector<uint8_t> kdf_output =
                            kdf->derive_key(masked_msg.size(), kdf_input.data(), kdf_input.size());

                        xor_buf(masked_msg.data(), kdf_output.data(), kdf_output.size());

                        hash->update(x2_bytes);
                        hash->update(masked_msg);
                        hash->update(y2_bytes);
                        secure_vector<uint8_t> u = hash->final();

                        if (constant_time_compare(u.data(), C3.data(), hash->output_length()) == false) {
                            return secure_vector<uint8_t>();
                        }

                        valid_mask = 0xFF;
                        return masked_msg;
                    }
                };

                template<typename CurveType>
                struct sm2 {
                    typedef CurveType curve_type;

                    typedef sm2_public_key<CurveType> public_key_type;
                    typedef sm2_private_key<CurveType> private_key_type;
                };
            }    // namespace pubkey
        }        // namespace crypto3
    }            // namespace nil

#endif
