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

#ifndef CRYPTO3_PUBKEY_CODE_BASED_UTIL_HPP
#define CRYPTO3_PUBKEY_CODE_BASED_UTIL_HPP

#include <nil/crypto3/pubkey/detail/mceliece/gf2m_small_m.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace {

                class binary_matrix final {
                public:
                    binary_matrix(uint32_t m_rown, uint32_t m_coln);

                    void row_xor(uint32_t a, uint32_t b);

                    secure_vector<int> row_reduced_echelon_form();

                    /**
                     * return the coefficient out of F_2
                     */
                    uint32_t coef(uint32_t i, uint32_t j) {
                        return (m_elem[(i)*m_rwdcnt + (j) / 32] >> (j % 32)) & 1;
                    }

                    void set_coef_to_one(uint32_t i, uint32_t j) {
                        m_elem[(i)*m_rwdcnt + (j) / 32] |= (static_cast<uint32_t>(1) << ((j) % 32));
                    }

                    void toggle_coeff(uint32_t i, uint32_t j) {
                        m_elem[(i)*m_rwdcnt + (j) / 32] ^= (static_cast<uint32_t>(1) << ((j) % 32));
                    }

                    // private:
                    uint32_t m_rown;      // number of rows.
                    uint32_t m_coln;      // number of columns.
                    uint32_t m_rwdcnt;    // number of words in a row
                    std::vector<uint32_t> m_elem;
                };

                binary_matrix::binary_matrix(uint32_t rown, uint32_t coln) {
                    m_coln = coln;
                    m_rown = rown;
                    m_rwdcnt = 1 + ((m_coln - 1) / 32);
                    m_elem = std::vector<uint32_t>(m_rown * m_rwdcnt);
                }

                void binary_matrix::row_xor(uint32_t a, uint32_t b) {
                    uint32_t i;
                    for (i = 0; i < m_rwdcnt; i++) {
                        m_elem[a * m_rwdcnt + i] ^= m_elem[b * m_rwdcnt + i];
                    }
                }

                // the matrix is reduced from LSB...(from right)
                secure_vector<int> binary_matrix::row_reduced_echelon_form() {
                    uint32_t i, failcnt, findrow, max = m_coln - 1;

                    secure_vector<int> perm(m_coln);
                    for (i = 0; i < m_coln; i++) {
                        perm[i] = i;    // initialize permutation.
                    }
                    failcnt = 0;

                    for (i = 0; i < m_rown; i++, max--) {
                        findrow = 0;
                        for (uint32_t j = i; j < m_rown; j++) {
                            if (coef(j, max)) {
                                if (i != j) {    // not needed as ith row is 0 and jth row is 1.
                                    row_xor(i, j);
                                }    // xor to the row.(swap)?
                                findrow = 1;
                                break;
                            }    // largest value found (end if)
                        }

                        if (!findrow)    // if no row with a 1 found then swap last column and the column with no 1
                                         // down.
                        {
                            perm[m_coln - m_rown - 1 - failcnt] = max;
                            failcnt++;
                            if (!max) {
                                // CSEC_FREE_MEM_CHK_SET_NULL(*p_perm);
                                // CSEC_THR_RETURN();
                                perm.resize(0);
                            }
                            i--;
                        } else {
                            perm[i + m_coln - m_rown] = max;
                            for (uint32_t j = i + 1; j < m_rown; j++)    // fill the column downwards with 0's
                            {
                                if (coef(j, (max))) {
                                    row_xor(j, i);    // check the arg. order.
                                }
                            }

                            for (int j = i - 1; j >= 0; j--)    // fill the column with 0's upwards too.
                            {
                                if (coef(j, (max))) {
                                    row_xor(j, i);
                                }
                            }
                        }
                    }    // end for(i)
                    return perm;
                }

                void randomize_support(std::vector<gf2m> &L, RandomNumberGenerator &rng) {
                    for (uint32_t i = 0; i != L.size(); ++i) {
                        gf2m rnd = random_gf2m(rng);

                        // no rejection sampling, but for useful code-based parameters with n <= 13 this seem tolerable
                        std::swap(L[i], L[rnd % L.size()]);
                    }
                }

                std::unique_ptr<binary_matrix> generate_R(std::vector<gf2m> &L, polyn_gf2m *g,
                                                          std::shared_ptr<gf2m_field> sp_field, uint32_t code_length,
                                                          uint32_t t) {
                    // L- Support
                    // t- Number of errors
                    // n- Length of the Goppa code
                    // m- The extension degree of the GF
                    // g- The generator polynomial.
                    gf2m x, y;
                    uint32_t i, j, k, r, n;
                    std::vector<int> Laux(code_length);
                    n = code_length;
                    r = t * sp_field->get_extension_degree();

                    binary_matrix H(r, n);

                    for (i = 0; i < n; i++) {
                        x = g->eval(lex_to_gray(L[i]));    // evaluate the polynomial at the point L[i].
                        x = sp_field->gf_inv(x);
                        y = x;
                        for (j = 0; j < t; j++) {
                            for (k = 0; k < sp_field->get_extension_degree(); k++) {
                                if (y & (1 << k)) {
                                    // the co-eff. are set in 2^0,...,2^11 ; 2^0,...,2^11 format along the rows/cols?
                                    H.set_coef_to_one(j * sp_field->get_extension_degree() + k, i);
                                }
                            }
                            y = sp_field->gf_mul(y, lex_to_gray(L[i]));
                        }
                    }    // The H matrix is fed.

                    secure_vector<int> perm = H.row_reduced_echelon_form();
                    if (perm.size() == 0) {
                        // result still is NULL
                        throw Invalid_State("could not bring matrix in row reduced echelon form");
                    }

                    std::unique_ptr<binary_matrix> result(new binary_matrix(n - r, r));
                    for (i = 0; i < (*result).m_rown; ++i) {
                        for (j = 0; j < (*result).m_coln; ++j) {
                            if (H.coef(j, perm[i])) {
                                result->toggle_coeff(i, j);
                            }
                        }
                    }
                    for (i = 0; i < code_length; ++i) {
                        Laux[i] = L[perm[i]];
                    }
                    for (i = 0; i < code_length; ++i) {
                        L[i] = Laux[i];
                    }
                    return result;
                }
            }    // namespace

            /**
             * Expand an input to a bit mask depending on it being being zero or non-zero
             * @param tst the input
             * @return the mask 0xFFFF if tst is non-zero and 0 otherwise
             */
            template<typename T>
            uint16_t expand_mask_16bit(T tst) {
                const uint16_t result = (tst != 0);
                return ~(result - 1);
            }

            inline gf2m gray_to_lex(gf2m gray) {
                gf2m result = gray ^ (gray >> 8);
                result ^= (result >> 4);
                result ^= (result >> 2);
                result ^= (result >> 1);
                return result;
            }

            inline gf2m lex_to_gray(gf2m lex) {
                return (lex >> 1) ^ lex;
            }

            inline uint32_t bit_size_to_byte_size(uint32_t bit_size) {
                return (bit_size - 1) / 8 + 1;
            }

            inline uint32_t bit_size_to_32bit_size(uint32_t bit_size) {
                return (bit_size - 1) / 32 + 1;
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
