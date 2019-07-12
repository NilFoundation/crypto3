#ifndef CRYPTO3_X509_PUBLIC_KEY_H_
#define CRYPTO3_X509_PUBLIC_KEY_H_

#include <nil/crypto3/pubkey/pk_keys.hpp>
#include <nil/crypto3/utilities/types.hpp>

#include <string>
#include <vector>

namespace nil {
    namespace crypto3 {

        class random_number_generator;

        class data_source;

/**
* The two types of X509 encoding supported by Botan.
* This enum is not used anymore, and will be removed in a future major release.
*/
        enum x509_encoding {
            RAW_BER, PEM
        };

/**
* This namespace contains functions for handling X.509 public keys
*/
        namespace x509 {

/**
* BER encode a key
* @param key the public key to encode
* @return BER encoding of this key
*/


            std::vector<uint8_t> ber_encode(const public_key_policy &key);

/**
* PEM encode a public key into a string.
* @param key the key to encode
* @return PEM encoded key
*/


            std::string pem_encode(const public_key_policy &key);

/**
* Create a public key from a data source.
* @param source the source providing the DER or PEM encoded key
* @return new public key object
*/


            public_key_policy *load_key(data_source &source);

#if defined(CRYPTO3_TARGET_OS_HAS_FILESYSTEM)
            /**
            * Create a public key from a file
            * @param filename pathname to the file to load
            * @return new public key object
            */
             public_key_policy* load_key(const std::string& filename);
#endif

/**
* Create a public key from a memory region.
* @param enc the memory region containing the DER or PEM encoded key
* @return new public key object
*/


            public_key_policy *load_key(const std::vector<uint8_t> &enc);

/**
* Copy a key.
* @param key the public key to copy
* @return new public key object
*/


            public_key_policy *copy_key(const public_key_policy &key);

        }
    }
}

#endif
