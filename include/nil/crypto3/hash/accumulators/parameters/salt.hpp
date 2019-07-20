#ifndef CRYPTO3_HASH_ACCUMULATOR_PARAMETERS_SALT_HPP
#define CRYPTO3_HASH_ACCUMULATOR_PARAMETERS_SALT_HPP

#include <boost/parameter/keyword.hpp>

#include <boost/accumulators/accumulators_fwd.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            BOOST_PARAMETER_KEYWORD(tag, salt)
            BOOST_ACCUMULATORS_IGNORE_GLOBAL(salt)
        }
    }
}

#endif //CRYPTO3_PARAMETERS_HPP
