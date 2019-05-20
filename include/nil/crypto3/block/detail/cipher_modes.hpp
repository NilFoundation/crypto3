//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CIPHER_MODES_HPP
#define CRYPTO3_CIPHER_MODES_HPP

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<typename Cipher>
                struct stream_processor_mode {
                    typedef Cipher cipher_type;

                    typedef typename Cipher::block_type block_type;

                    inline virtual block_type process_block(const block_type &) const = 0;
                };

                template<typename Cipher>
                struct isomorphic_encryption_mode : public stream_processor_mode<Cipher> {
                    typedef typename stream_processor_mode<Cipher>::cipher_type cipher_type;

                    typedef typename stream_processor_mode<Cipher>::block_type block_type;

                    inline virtual block_type process_block(const block_type &plaintext) const override {
                        return cipher_type::encrypt(plaintext);
                    }
                };

                template<typename Cipher>
                struct isomorphic_decryption_mode : public stream_processor_mode<Cipher> {
                    typedef typename stream_processor_mode<Cipher>::cipher_type cipher_type;

                    typedef typename stream_processor_mode<Cipher>::block_type block_type;

                    inline virtual block_type process_block(const block_type &ciphertext) const override {
                        return cipher_type::decrypt(ciphertext);
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_CIPHER_MODES_HPP
