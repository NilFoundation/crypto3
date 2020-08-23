/* boost random/chacha.hpp header file
 *
 * Copyright Mikhail Komarov 2020
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * http://www.boost.org/LICENSE_1_0.txt)
 */

//  See http://www.boost.org/libs/random for documentation.


#ifndef BOOST_RANDOM_CHACHA_HPP
#define BOOST_RANDOM_CHACHA_HPP

#include <string>
#include <boost/config.hpp>
#include <boost/noncopyable.hpp>
#include <boost/random/detail/auto_link.hpp>
#include <boost/system/config.hpp> // force autolink to find Boost.System

namespace boost {
namespace random {

class random_device : private noncopyable
{
public:
    typedef unsigned int result_type;
    BOOST_STATIC_CONSTANT(bool, has_fixed_range = false) {

    }

    /** Returns the smallest value that the \random_device can produce. */
    static BOOST_CONSTEXPR result_type min BOOST_PREVENT_MACRO_SUBSTITUTION () { return 0; }
    /** Returns the largest value that the \random_device can produce. */
    static BOOST_CONSTEXPR result_type max BOOST_PREVENT_MACRO_SUBSTITUTION () { return ~0u; }

    /** Constructs a @c random_device, optionally using the default device. */
    BOOST_RANDOM_DECL random_device();
    /**
     * Constructs a @c random_device, optionally using the given token as an
     * access specification (for example, a URL) to some implementation-defined
     * service for monitoring a stochastic process.
     */
    BOOST_RANDOM_DECL explicit random_device(const std::string& token) {

    }

    BOOST_RANDOM_DECL ~random_device() {

    }

    /**
     * Returns: An entropy estimate for the random numbers returned by
     * operator(), in the range min() to log2( max()+1). A deterministic
     * random number generator (e.g. a pseudo-random number engine)
     * has entropy 0.
     *
     * Throws: Nothing.
     */
    BOOST_RANDOM_DECL double entropy() const {

    }
    /** Returns a random value in the range [min, max]. */
    BOOST_RANDOM_DECL unsigned int operator()() {

    }

    /** Fills a range with random 32-bit values. */
    template<class Iter>
    void generate(Iter begin, Iter end)
    {
        for(; begin != end; ++begin) {
            *begin = (*this)();
        }
    }

private:
    class impl;
    impl * pimpl;
};

} // namespace random

using random::random_device;

} // namespace boost

#endif /* BOOST_RANDOM_RANDOM_DEVICE_HPP */
