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

#ifndef CRYPTO3_PUBKEY_MCELIECE_INTERNAL_HPP
#define CRYPTO3_PUBKEY_MCELIECE_INTERNAL_HPP

#include <nil/crypto3/utilities/secmem.hpp>
#include <nil/crypto3/utilities/types.hpp>

#include <nil/crypto3/pubkey/pk_operations.hpp>
#include <nil/crypto3/pubkey/mceliece.hpp>

namespace nil {
    namespace crypto3 {
        namespace {

            void matrix_arr_mul(std::vector<uint32_t> matrix, uint32_t numo_rows, uint32_t words_per_row,
                                const uint8_t *input_vec, uint32_t *output_vec, uint32_t output_vec_len) {
                for (size_t j = 0; j < numo_rows; j++) {
                    if ((input_vec[j / 8] >> (j % 8)) & 1) {
                        for (size_t i = 0; i < output_vec_len; i++) {
                            output_vec[i] ^= matrix[j * (words_per_row) + i];
                        }
                    }
                }
            }

            /**
             * returns the error vector to the syndrome
             */
            secure_vector<gf2m> goppa_decode(const polyn_gf2m &syndrom_polyn, const polyn_gf2m &g,
                                             const std::vector<polyn_gf2m> &sqrtmod, const std::vector<gf2m> &Linv) {
                gf2m a;
                uint32_t code_length = Linv.size();
                uint32_t t = g.get_degree();

                std::shared_ptr<gf2m_field> sp_field = g.get_sp_field();

                std::pair<polyn_gf2m, polyn_gf2m> h_aux = polyn_gf2m::eea_with_coefficients(syndrom_polyn, g, 1);
                polyn_gf2m &h = h_aux.first;
                polyn_gf2m &aux = h_aux.second;
                a = sp_field->gf_inv(aux.get_coef(0));
                gf2m log_a = sp_field->gf_log(a);
                for (int i = 0; i <= h.get_degree(); ++i) {
                    h.set_coef(i, sp_field->gf_mul_zrz(log_a, h.get_coef(i)));
                }

                //  compute h(z) += z
                h.add_to_coef(1, 1);
                // compute S square root of h (using sqrtmod)
                polyn_gf2m S(t - 1, g.get_sp_field());

                for (uint32_t i = 0; i < t; i++) {
                    a = sp_field->gf_sqrt(h.get_coef(i));

                    if (i & 1) {
                        for (uint32_t j = 0; j < t; j++) {
                            S.add_to_coef(j, sp_field->gf_mul(a, sqrtmod[i / 2].get_coef(j)));
                        }
                    } else {
                        S.add_to_coef(i / 2, a);
                    }
                } /* end for loop (i) */

                S.get_degree();

                std::pair<polyn_gf2m, polyn_gf2m> v_u = polyn_gf2m::eea_with_coefficients(S, g, t / 2 + 1);
                polyn_gf2m &u = v_u.second;
                polyn_gf2m &v = v_u.first;

                // sigma = u^2+z*v^2
                polyn_gf2m sigma(t, g.get_sp_field());

                const size_t u_deg = u.get_degree();
                for (size_t i = 0; i <= u_deg; ++i) {
                    sigma.set_coef(2 * i, sp_field->gf_square(u.get_coef(i)));
                }

                const int v_deg = v.get_degree();
                BOOST_ASSERT_MSG(v_deg > 0, "Valid degree");
                for (int i = 0; i <= v_deg; ++i) {
                    sigma.set_coef(2 * i + 1, sp_field->gf_square(v.get_coef(i)));
                }

                secure_vector<gf2m> res = find_roots_gf2m_decomp(sigma, code_length);
                size_t d = res.size();

                secure_vector<gf2m> result(d);
                for (uint32_t i = 0; i < d; ++i) {
                    gf2m current = res[i];

                    gf2m tmp;
                    tmp = gray_to_lex(current);
                    if (tmp >= code_length) /* invalid root */
                    {
                        result[i] = i;
                    }
                    result[i] = Linv[tmp];
                }

                return result;
            }
        }    // namespace

        void mceliece_decrypt(secure_vector<uint8_t> &plaintext_out, secure_vector<uint8_t> &error_mask_out,
                              const uint8_t ciphertext[], size_t ciphertext_len, const mceliece_private_key &key) {
            mceliece_decrypt(plaintext_out, error_mask_out, ciphertext.data(), ciphertext.size(), key);
        }

        void mceliece_decrypt(secure_vector<uint8_t> &plaintext_out, secure_vector<uint8_t> &error_mask_out,
                              const secure_vector<uint8_t> &ciphertext, const mceliece_private_key &key) {
            secure_vector<gf2m> error_pos;
            plaintext = mceliece_decrypt(error_pos, ciphertext, ciphertext_len, key);

            const size_t code_length = key.get_code_length();
            secure_vector<uint8_t> result((code_length + 7) / 8);
            for (auto &&pos : error_pos) {
                if (pos > code_length) {
                    throw std::invalid_argument("error position larger than code size");
                }
                result[pos / 8] |= (1 << (pos % 8));
            }

            error_mask = result;
        }

        /**
         * @p p_err_pos_len must point to the available length of @p error_pos on input, the
         * function will set it to the actual number of errors returned in the @p error_pos
         * array */
        secure_vector<uint8_t> mceliece_decrypt(secure_vector<gf2m> &error_pos, const uint8_t *ciphertext,
                                                uint32_t ciphertext_len, const mceliece_private_key &key) {

            uint32_t dimension = key.get_dimension();
            uint32_t codimension = key.get_codimension();
            uint32_t t = key.get_goppa_polyn().get_degree();
            polyn_gf2m syndrome_polyn(key.get_goppa_polyn().get_sp_field());    // init as zero polyn
            const unsigned unused_pt_bits = dimension % 8;
            const uint8_t unused_pt_bits_mask = (1 << unused_pt_bits) - 1;

            if (ciphertext_len != (key.get_code_length() + 7) / 8) {
                throw std::invalid_argument("wrong size of McEliece ciphertext");
            }
            uint32_t cleartext_len = (key.get_message_word_bit_length() + 7) / 8;

            if (cleartext_len != bit_size_to_byte_size(dimension)) {
                throw std::invalid_argument("mceliece-decryption: wrong length of cleartext buffer");
            }

            secure_vector<uint32_t> syndrome_vec(bit_size_to_32bit_size(codimension));
            matrix_arr_mul(key.get_H_coeffs(), key.get_code_length(), bit_size_to_32bit_size(codimension), ciphertext,
                           syndrome_vec.data(), syndrome_vec.size());

            secure_vector<uint8_t> syndrome_byte_vec(bit_size_to_byte_size(codimension));
            uint32_t syndrome_byte_vec_size = syndrome_byte_vec.size();
            for (uint32_t i = 0; i < syndrome_byte_vec_size; i++) {
                syndrome_byte_vec[i] = syndrome_vec[i / 4] >> (8 * (i % 4));
            }

            syndrome_polyn = polyn_gf2m(t - 1, syndrome_byte_vec.data(), bit_size_to_byte_size(codimension),
                                        key.get_goppa_polyn().get_sp_field());

            syndrome_polyn.get_degree();
            error_pos = goppa_decode(syndrome_polyn, key.get_goppa_polyn(), key.get_sqrtmod(), key.get_Linv());

            uint32_t nb_err = error_pos.size();

            secure_vector<uint8_t> cleartext(cleartext_len);
            copy_mem(cleartext.data(), ciphertext, cleartext_len);

            for (uint32_t i = 0; i < nb_err; i++) {
                gf2m current = error_pos[i];

                if (current >= cleartext_len * 8) {
                    // an invalid position, this shouldn't happen
                    continue;
                }
                cleartext[current / 8] ^= (1 << (current % 8));
            }

            if (unused_pt_bits) {
                cleartext[cleartext_len - 1] &= unused_pt_bits_mask;
            }

            return cleartext;
        }

        void mceliece_encrypt(secure_vector<uint8_t> &ciphertext_out, secure_vector<uint8_t> &error_mask_out,
                              const secure_vector<uint8_t> &plaintext, const McEliece_PublicKey &key,
                              random_number_generator &rng);

        mceliece_private_key generate_mceliece_key(random_number_generator &rng, uint32_t ext_deg, uint32_t code_length,
                                                   uint32_t t) {
            uint32_t i, j, k, l;
            std::unique_ptr<binary_matrix> R;

            uint32_t codimension = t * ext_deg;
            if (code_length <= codimension) {
                throw std::invalid_argument("invalid McEliece parameters");
            }
            std::shared_ptr<gf2m_field> sp_field(new gf2m_field(ext_deg));

            // pick the support.........
            std::vector<gf2m> L(code_length);

            for (i = 0; i < code_length; i++) {
                L[i] = i;
            }
            randomize_support(L, rng);
            polyn_gf2m g(sp_field);    // create as zero
            bool success = false;
            do {
                // create a random irreducible polynomial
                g = polyn_gf2m(t, rng, sp_field);

                try {
                    R = generate_R(L, &g, sp_field, code_length, t);
                    success = true;
                } catch (const Invalid_State &) {
                }
            } while (!success);

            std::vector<polyn_gf2m> sqrtmod = polyn_gf2m::sqrt_mod_init(g);
            std::vector<polyn_gf2m> F = syndrome_init(g, L, code_length);

            // Each F[i] is the (precomputed) syndrome of the error vector with
            // a single '1' in i-th position.
            // We do not store the F[i] as polynomials of degree t , but
            // as binary vectors of length ext_deg * t (this will
            // speed up the syndrome computation)
            //
            //
            std::vector<uint32_t> H(bit_size_to_32bit_size(codimension) * code_length);
            uint32_t *sk = H.data();
            for (i = 0; i < code_length; ++i) {
                for (l = 0; l < t; ++l) {
                    k = (l * ext_deg) / 32;
                    j = (l * ext_deg) % 32;
                    sk[k] ^= static_cast<uint32_t>(F[i].get_coef(l)) << j;
                    if (j + ext_deg > 32) {
                        sk[k + 1] ^= F[i].get_coef(l) >> (32 - j);
                    }
                }
                sk += bit_size_to_32bit_size(codimension);
            }

            // We need the support L for decoding (decryption). In fact the
            // inverse is needed

            std::vector<gf2m> Linv(code_length);
            for (i = 0; i < code_length; ++i) {
                Linv[L[i]] = i;
            }
            std::vector<uint8_t> pubmat(R->m_elem.size() * 4);
            for (i = 0; i < R->m_elem.size(); i++) {
                store_le(R->m_elem[i], &pubmat[i * 4]);
            }

            return mceliece_private_key(g, H, sqrtmod, Linv, pubmat);
        }
    }    // namespace crypto3
}    // namespace nil

#endif
