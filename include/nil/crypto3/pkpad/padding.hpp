#ifndef CRYPTO3_PADDING_HPP
#define CRYPTO3_PADDING_HPP

#include <nil/crypto3/build.hpp>

#include <string>
#include <vector>

namespace nil {
    namespace crypto3 {

        /**
         * Returns the allowed padding schemes when using the given
         * algorithm (key type) for creating digital signatures.
         *
         * @param algo the algorithm for which to look up supported padding schemes
         * @return a vector of supported padding schemes
         */
        CRYPTO3_TEST_API const std::vector<std::string> get_sig_paddings(const std::string &algo);

        /**
         * Returns true iff the given padding scheme is valid for the given
         * signature algorithm (key type).
         *
         * @param algo the signature algorithm to be used
         * @param padding the padding scheme to be used
         */
        bool sig_algo_and_pad_ok(const std::string &algo, const std::string &padding);

        const std::map<const std::string, std::vector<std::string>> allowed_signature_paddings = {
            {"DSA", {"EMSA1"}},     {"ECDSA", {"EMSA1"}},      {"ECGDSA", {"EMSA1"}},
            {"ECKCDSA", {"EMSA1"}}, {"GOST-34.10", {"EMSA1"}}, {"RSA", {"EMSA4", "EMSA3"}},
        };

        const std::vector<std::string> get_sig_paddings(const std::string &algo) {
            if (allowed_signature_paddings.count(algo) > 0) {
                return allowed_signature_paddings.at(algo);
            }
            return {};
        }

        bool sig_algo_and_pad_ok(const std::string &algo, const std::string &padding) {
            std::vector<std::string> pads = get_sig_paddings(algo);
            return std::find(pads.begin(), pads.end(), padding) != pads.end();
        }
    }    // namespace crypto3
}    // namespace nil

#endif
