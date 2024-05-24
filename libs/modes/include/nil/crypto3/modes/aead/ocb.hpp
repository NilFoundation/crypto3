//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MODE_AEAD_OCB_HPP
#define CRYPTO3_MODE_AEAD_OCB_HPP

#include <nil/crypto3/modes/aead/aead.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace modes {
                namespace detail {
                    template<typename BlockCipher>
                    class L_computer {
                    public:
                        explicit L_computer(const BlockCipher &cipher) :
                            m_BS(cipher.block_size()), m_max_blocks(cipher.parallel_bytes() / m_BS) {
                            m_L_star.resize(m_BS);
                            cipher.encrypt(m_L_star);
                            m_L_dollar = poly_double(star());
                            m_L.push_back(poly_double(dollar()));

                            while (m_L.size() < 8) {
                                m_L.push_back(poly_double(m_L.back()));
                            }

                            m_offset_buf.resize(m_BS * m_max_blocks);
                        }

                        void init(const secure_vector<uint8_t> &offset) {
                            m_offset = offset;
                        }

                        const secure_vector<uint8_t> &star() const {
                            return m_L_star;
                        }

                        const secure_vector<uint8_t> &dollar() const {
                            return m_L_dollar;
                        }

                        const secure_vector<uint8_t> &offset() const {
                            return m_offset;
                        }

                        const secure_vector<uint8_t> &get(size_t i) const {
                            while (m_L.size() <= i) {
                                m_L.push_back(poly_double(m_L.back()));
                            }

                            return m_L[i];
                        }

                        const uint8_t *compute_offsets(size_t block_index, size_t blocks) {
                            BOOST_ASSERT_MSG(blocks <= m_max_blocks, "OCB offsets");

                            uint8_t *offsets = m_offset_buf.data();

                            if (block_index % 4 == 0) {
                                const secure_vector<uint8_t> &L0 = get(0);
                                const secure_vector<uint8_t> &L1 = get(1);

                                while (blocks >= 4) {
                                    // ntz(4*i+1) == 0
                                    // ntz(4*i+2) == 1
                                    // ntz(4*i+3) == 0
                                    block_index += 4;
                                    const size_t ntz4 = ctz<uint32_t>(block_index);

                                    xor_buf(offsets, m_offset.data(), L0.data(), m_BS);
                                    offsets += m_BS;

                                    xor_buf(offsets, offsets - m_BS, L1.data(), m_BS);
                                    offsets += m_BS;

                                    xor_buf(m_offset.data(), L1.data(), m_BS);
                                    copy_mem(offsets, m_offset.data(), m_BS);
                                    offsets += m_BS;

                                    xor_buf(m_offset.data(), get(ntz4).data(), m_BS);
                                    copy_mem(offsets, m_offset.data(), m_BS);
                                    offsets += m_BS;

                                    blocks -= 4;
                                }
                            }

                            for (size_t i = 0; i != blocks; ++i) {    // could be done in parallel
                                const size_t ntz = ctz<uint32_t>(block_index + i + 1);
                                xor_buf(m_offset.data(), get(ntz).data(), m_BS);
                                copy_mem(offsets, m_offset.data(), m_BS);
                                offsets += m_BS;
                            }

                            return m_offset_buf.data();
                        }

                    private:
                        secure_vector<uint8_t> poly_double(const secure_vector<uint8_t> &in) const {
                            secure_vector<uint8_t> out(in.size());
                            poly_double_n(out.data(), in.data(), out.size());
                            return out;
                        }

                        const size_t m_BS, m_max_blocks;
                        secure_vector<uint8_t> m_L_dollar, m_L_star;
                        secure_vector<uint8_t> m_offset;
                        mutable std::vector<secure_vector<uint8_t>> m_L;
                        secure_vector<uint8_t> m_offset_buf;
                    };

                    template<typename BlockCipher,
                             typename Padding,
                             std::size_t TagBits,
                             template<typename> class Allocator = std::allocator>
                    struct ocb_policy {
                        typedef BlockCipher cipher_type;
                        typedef Padding padding_type;

                        template<typename T>
                        using allocator_type = Allocator<T>;

                        constexpr static const std::size_t tag_bits = TagBits;

                        BOOST_STATIC_ASSERT(tag_bits % 4 == 0);
                        BOOST_STATIC_ASSERT(tag_bits >= CHAR_BIT && tag_bits <= 32);

                        constexpr static const std::size_t block_bits = cipher_type::block_bits;
                        constexpr static const std::size_t block_words = cipher_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        BOOST_STATIC_ASSERT(block_bits == 128 || block_bits == 192 || block_bits == 256 ||
                                            block_bits == 512);
                        BOOST_STATIC_ASSERT(tag_bits <= block_bits);

                        typedef std::vector<boost::uint_t<CHAR_BIT>, allocator_type<boost::uint_t<CHAR_BIT>>>
                            associated_data_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            BOOST_ASSERT_MSG(m_L, "A key was set");

                            m_L->init(update_nonce(nonce, nonce_len));
                            zeroise(m_checksum);
                            m_block_index = 0;

                            return cipher.encrypt(block);
                        }

                        void update_nonce(const uint8_t nonce[], size_t nonce_len) {
                            const size_t BS = block_size();

                            const size_t MASKLEN = (BS == 16 ? 6 : ((BS == 24) ? 7 : 8));

                            const uint8_t BOTTOM_MASK = static_cast<uint8_t>((static_cast<uint16_t>(1) << MASKLEN) - 1);

                            secure_vector<uint8_t> nonce_buf(BS);

                            copy_mem(&nonce_buf[BS - nonce_len], nonce, nonce_len);
                            nonce_buf[0] = static_cast<uint8_t>(((tag_size() * 8) % (BS * 8)) << (BS <= 16 ? 1 : 0));

                            nonce_buf[BS - nonce_len - 1] ^= 1;

                            const uint8_t bottom = nonce_buf[BS - 1] & BOTTOM_MASK;
                            nonce_buf[BS - 1] &= ~BOTTOM_MASK;

                            const bool need_new_stretch = (m_last_nonce != nonce_buf);

                            if (need_new_stretch) {
                                m_last_nonce = nonce_buf;

                                m_cipher->encrypt(nonce_buf);

                                /*
                                The loop bounds (BS vs BS/2) are derived from the relation
                                between the block size and the MASKLEN. Using the terminology
                                of draft-krovetz-ocb-wide, we have to derive enough bits in
                                ShiftedKtop to read up to BLOCKLEN+bottom bits from Stretch.

                                           +----------+---------+-------+---------+
                                           | BLOCKLEN | RESIDUE | SHIFT | MASKLEN |
                                           +----------+---------+-------+---------+
                                           |       32 |     141 |    17 |    4    |
                                           |       64 |      27 |    25 |    5    |
                                           |       96 |    1601 |    33 |    6    |
                                           |      128 |     135 |     8 |    6    |
                                           |      192 |     135 |    40 |    7    |
                                           |      256 |    1061 |     1 |    8    |
                                           |      384 |    4109 |    80 |    8    |
                                           |      512 |     293 |   176 |    8    |
                                           |     1024 |  524355 |   352 |    9    |
                                           +----------+---------+-------+---------+
                                */
                                if (BS == 16) {
                                    for (size_t i = 0; i != BS / 2; ++i) {
                                        nonce_buf.push_back(nonce_buf[i] ^ nonce_buf[i + 1]);
                                    }
                                } else if (BS == 24) {
                                    for (size_t i = 0; i != 16; ++i) {
                                        nonce_buf.push_back(nonce_buf[i] ^ nonce_buf[i + 5]);
                                    }
                                } else if (BS == 32) {
                                    for (size_t i = 0; i != BS; ++i) {
                                        nonce_buf.push_back(nonce_buf[i] ^ (nonce_buf[i] << 1) ^
                                                            (nonce_buf[i + 1] >> 7));
                                    }
                                } else if (BS == 64) {
                                    for (size_t i = 0; i != BS / 2; ++i) {
                                        nonce_buf.push_back(nonce_buf[i] ^ nonce_buf[i + 22]);
                                    }
                                }

                                m_stretch = nonce_buf;
                            }

                            // now set the offset from stretch and bottom
                            const size_t shift_bytes = bottom / 8;
                            const size_t shift_bits = bottom % 8;

                            BOOST_ASSERT_MSG(m_stretch.size() >= BS + shift_bytes + 1, "KeyBits ok");

                            secure_vector<uint8_t> offset(BS);
                            for (size_t i = 0; i != BS; ++i) {
                                offset[i] = (m_stretch[i + shift_bytes] << shift_bits);
                                offset[i] |= (m_stretch[i + shift_bytes + 1] >> (8 - shift_bits));
                            }

                            return offset;
                        }

                        static secure_vector<uint8_t> hash(const L_computer<cipher_type> &L,
                                                           const cipher_type &cipher,
                                                           const associated_data_type &ad) {
                            const size_t BS = cipher.block_size();
                            secure_vector<uint8_t> sum(BS);
                            secure_vector<uint8_t> offset(BS);

                            secure_vector<uint8_t> buf(BS);

                            const size_t ad_blocks = (ad.size() / BS);
                            const size_t ad_remainder = (ad.size() % BS);

                            for (size_t i = 0; i != ad_blocks; ++i) {
                                // this loop could run in parallel
                                offset ^= L.get(ctz<uint32_t>(i + 1));
                                buf = offset;
                                xor_buf(buf.data(), &ad[BS * i], BS);
                                cipher.encrypt(buf);
                                sum ^= buf;
                            }

                            if (ad_remainder) {
                                offset ^= L.star();
                                buf = offset;
                                xor_buf(buf.data(), &ad[BS * ad_blocks], ad_remainder);
                                buf[ad_remainder] ^= 0x80;
                                cipher.encrypt(buf);
                                sum ^= buf;
                            }

                            return sum;
                        }
                    };

                    template<typename BlockCipher,
                             typename Padding,
                             std::size_t TagBits,
                             template<typename> class Allocator = std::allocator>
                    class ocb_encryption_policy : public ocb_policy<BlockCipher, Padding, TagBits, Allocator> {
                        typedef ocb_policy<BlockCipher, Padding, TagBits, Allocator> policy_type;

                    public:
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        template<typename T>
                        using allocator_type = typename policy_type::template allocator_type<T>;

                        constexpr static const std::size_t tag_bits = policy_type::tag_bits;

                        typedef typename policy_type::associated_data_type associated_data_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename policy_type::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return policy_type::begin_message(cipher, plaintext);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            BOOST_ASSERT_MSG(sz % update_granularity() == 0, "Invalid OCB input size");
                            encrypt(buf, sz / block_size());

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = {0};

                            const size_t BS = block_size();

                            BOOST_ASSERT_MSG(buffer.size() >= offset, "Offset is sane");
                            const size_t sz = buffer.size() - offset;
                            uint8_t *buf = buffer.data() + offset;

                            secure_vector<uint8_t> mac(BS);

                            if (sz) {
                                const size_t final_full_blocks = sz / BS;
                                const size_t remainder_bytes = sz - (final_full_blocks * BS);

                                encrypt(buf, final_full_blocks);
                                mac = m_L->offset();

                                if (remainder_bytes) {
                                    BOOST_ASSERT_MSG(remainder_bytes < BS, "Only a partial block left");
                                    uint8_t *remainder = &buf[sz - remainder_bytes];

                                    xor_buf(m_checksum.data(), remainder, remainder_bytes);
                                    m_checksum[remainder_bytes] ^= 0x80;

                                    // Offset_*
                                    mac ^= m_L->star();

                                    secure_vector<uint8_t> pad(BS);
                                    m_cipher->encrypt(mac, pad);
                                    xor_buf(remainder, pad.data(), remainder_bytes);
                                }
                            } else {
                                mac = m_L->offset();
                            }

                            // now compute the tag

                            // fold checksum
                            for (size_t i = 0; i != m_checksum.size(); i += BS) {
                                xor_buf(mac.data(), m_checksum.data() + i, BS);
                            }

                            xor_buf(mac.data(), m_L->dollar().data(), BS);
                            m_cipher->encrypt(mac);
                            xor_buf(mac.data(), m_ad_hash.data(), BS);

                            buffer += std::make_pair(mac.data(), tag_size());

                            zeroise(m_checksum);
                            m_block_index = 0;

                            return result;
                        }

                    protected:
                        void encrypt(uint8_t buffer[], size_t blocks) {
                            const size_t BS = block_size();

                            BOOST_ASSERT_MSG(m_L, "A key was set");

                            while (blocks) {
                                const size_t proc_blocks = std::min(blocks, par_blocks());
                                const size_t proc_bytes = proc_blocks * BS;

                                const uint8_t *offsets = m_L->compute_offsets(m_block_index, proc_blocks);

                                xor_buf(m_checksum.data(), buffer, proc_bytes);

                                m_cipher->encrypt_n_xex(buffer, offsets, proc_blocks);

                                buffer += proc_bytes;
                                blocks -= proc_blocks;
                                m_block_index += proc_blocks;
                            }
                        }
                    };

                    template<typename BlockCipher,
                             typename Padding,
                             std::size_t TagBits,
                             template<typename> class Allocator = std::allocator>
                    class ocb_decryption_policy : public ocb_policy<BlockCipher, Padding, TagBits, Allocator> {
                        typedef ocb_policy<BlockCipher, Padding, TagBits, Allocator> policy_type;

                    public:
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        template<typename T>
                        using allocator_type = typename policy_type::template allocator_type<T>;

                        typedef typename policy_type::associated_data_type associated_data_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename policy_type::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return policy_type::begin_message(cipher, plaintext);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            BOOST_ASSERT_MSG(sz % update_granularity() == 0, "Invalid OCB input size");
                            decrypt(buf, sz / block_size());

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = {0};

                            const size_t BS = block_size();

                            BOOST_ASSERT_MSG(buffer.size() >= offset, "Offset is sane");
                            const size_t sz = buffer.size() - offset;
                            uint8_t *buf = buffer.data() + offset;

                            BOOST_ASSERT_MSG(sz >= tag_size(), "We have the tag");

                            const size_t remaining = sz - tag_size();

                            secure_vector<uint8_t> mac(BS);

                            if (remaining) {
                                const size_t final_full_blocks = remaining / BS;
                                const size_t final_bytes = remaining - (final_full_blocks * BS);

                                decrypt(buf, final_full_blocks);
                                mac ^= m_L->offset();

                                if (final_bytes) {
                                    BOOST_ASSERT_MSG(final_bytes < BS, "Only a partial block left");

                                    uint8_t *remainder = &buf[remaining - final_bytes];

                                    mac ^= m_L->star();
                                    secure_vector<uint8_t> pad(BS);
                                    m_cipher->encrypt(mac, pad);    // P_*
                                    xor_buf(remainder, pad.data(), final_bytes);

                                    xor_buf(m_checksum.data(), remainder, final_bytes);
                                    m_checksum[final_bytes] ^= 0x80;
                                }
                            } else {
                                mac = m_L->offset();
                            }

                            // compute the mac

                            // fold checksum
                            for (size_t i = 0; i != m_checksum.size(); i += BS) {
                                xor_buf(mac.data(), m_checksum.data() + i, BS);
                            }

                            mac ^= m_L->dollar();
                            m_cipher->encrypt(mac);
                            mac ^= m_ad_hash;

                            // reset state
                            zeroise(m_checksum);
                            m_block_index = 0;

                            // compare mac
                            const uint8_t *included_tag = &buf[remaining];

                            if (!constant_time_compare(mac.data(), included_tag, tag_size())) {
                                throw integrity_failure("OCB tag check failed");
                            }

                            // remove tag from end of message
                            buffer.resize(remaining + offset);

                            return result;
                        }

                    protected:
                        void decrypt(uint8_t buffer[], size_t blocks) {
                            const size_t BS = block_size();

                            while (blocks) {
                                const size_t proc_blocks = std::min(blocks, par_blocks());
                                const size_t proc_bytes = proc_blocks * BS;

                                const uint8_t *offsets = m_L->compute_offsets(m_block_index, proc_blocks);

                                m_cipher->decrypt_n_xex(buffer, offsets, proc_blocks);

                                xor_buf(m_checksum.data(), buffer, proc_bytes);

                                buffer += proc_bytes;
                                blocks -= proc_blocks;
                                m_block_index += proc_blocks;
                            }
                        }
                    };

                    template<typename Policy>
                    class ocb {
                        typedef Policy policy_type;

                    public:
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        typedef typename cipher_type::key_type key_type;
                        typedef typename policy_type::associated_data_type associated_data_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        template<typename AssociatedDataContainer>
                        ocb(const cipher_type &cipher, const AssociatedDataContainer &associated_data) :
                            cipher(cipher) {
                            schedule_associated_data(associated_data);
                        }

                        block_type begin_message(const block_type &plaintext) {
                            return policy_type::begin_message(cipher, plaintext, ad);
                        }

                        block_type process_block(const block_type &plaintext) {
                            return policy_type::process_block(cipher, plaintext, ad);
                        }

                        block_type end_message(const block_type &plaintext) {
                            return policy_type::end_message(cipher, plaintext, ad);
                        }

                        inline static std::size_t required_output_size(std::size_t inputlen) {
                            return padding_type::required_output_size(inputlen);
                        }

                    protected:
                        template<typename AssociatedDataContainer>
                        inline void schedule_associated_data(const AssociatedDataContainer &iad) {
                            m_ad_hash = policy_type::hash(*m_L, *m_cipher, iad);
                        }

                        associated_data_type ad;

                        cipher_type cipher;
                    };
                }    // namespace detail

                /*!
                 *
                 * OCB Block Cipher Mode Note that OCB is patented, but is freely licensed in some
                 * circumstances.
                 *
                 * @see "The OCB Authenticated-Encryption Algorithm" RFC 7253
                 *      https://tools.ietf.org/html/rfc7253
                 * @see "OCB For Block Ciphers Without 128-Bit Blocks"
                 *      (draft-krovetz-ocb-wide-d3) for the extension of OCB to
                 *      block ciphers with larger block sizes.
                 * @see Free Licenses http://www.cs.ucdavis.edu/~rogaway/ocb/license.htm
                 * @see OCB home page http://www.cs.ucdavis.edu/~rogaway/ocb
                 *
                 *
                 * @tparam Cipher
                 * @tparam Padding
                 */
                template<typename Cipher,
                         template<typename>
                         class Padding,
                         std::size_t TagBits = 16 * CHAR_BIT,
                         template<typename> class Allocator = std::allocator>
                struct ocb {
                    typedef Cipher cipher_type;
                    typedef Padding<Cipher> padding_type;

                    template<typename T>
                    using allocator_type = Allocator<T>;

                    typedef detail::ocb_encryption_policy<cipher_type, padding_type, TagBits, allocator_type>
                        encryption_policy;
                    typedef detail::ocb_decryption_policy<cipher_type, padding_type, TagBits, allocator_type>
                        decryption_policy;

                    template<template<typename, typename, std::size_t, template<typename> class> class Policy>
                    struct bind {
                        typedef detail::ocb<Policy<cipher_type, padding_type, TagBits, allocator_type>> type;
                    };
                };
            }    // namespace modes
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif
