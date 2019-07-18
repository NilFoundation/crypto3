#ifndef CRYPTO3_HASH_ACCUMULATOR_PARAMETERS_HPP
#define CRYPTO3_HASH_ACCUMULATOR_PARAMETERS_HPP

#include <boost/parameter/keyword.hpp>

#include <boost/accumulators/accumulators_fwd.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            BOOST_PARAMETER_KEYWORD(tag, bits)
            BOOST_ACCUMULATORS_IGNORE_GLOBAL(bits)
        }
    }
}

#endif //CRYPTO3_PARAMETERS_HPP
