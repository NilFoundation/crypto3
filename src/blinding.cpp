#include <nil/crypto3/pubkey/blinding.hpp>

namespace nil {
    namespace crypto3 {

        blinder::blinder(const cpp_int &modulus, random_number_generator &rng,
                         std::function<cpp_int(const cpp_int &)> fwd, std::function<cpp_int(const cpp_int &)> inv)
                : m_reducer(modulus), m_rng(rng), m_fwd_fn(fwd), m_inv_fn(inv), m_modulus_bits(modulus.bits()), m_e{},
                m_d{}, m_counter{} {
            const cpp_int k = blinding_nonce();
            m_e = m_fwd_fn(k);
            m_d = m_inv_fn(k);
        }

        cpp_int blinder::blinding_nonce() const {
            return cpp_int(m_rng, m_modulus_bits - 1);
        }

        cpp_int blinder::blind(const cpp_int &i) const {
            if (!m_reducer.initialized()) {
                throw Exception("blinder not initialized, cannot blind");
            }

            ++m_counter;

            if ((CRYPTO3_BLINDING_REINIT_INTERVAL > 0) && (m_counter > CRYPTO3_BLINDING_REINIT_INTERVAL)) {
                const cpp_int k = blinding_nonce();
                m_e = m_fwd_fn(k);
                m_d = m_inv_fn(k);
                m_counter = 0;
            } else {
                m_e = m_reducer.square(m_e);
                m_d = m_reducer.square(m_d);
            }

            return m_reducer.multiply(i, m_e);
        }

        cpp_int blinder::unblind(const cpp_int &i) const {
            if (!m_reducer.initialized()) {
                throw Exception("blinder not initialized, cannot unblind");
            }

            return m_reducer.multiply(i, m_d);
        }
    }
}
