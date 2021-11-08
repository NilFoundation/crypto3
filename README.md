=nil; Foundation's Multiprecision Library
============================

 The Multiprecision Library provides integer, rational, floating-point, complex and interval number types in C++ that have more range and 
 precision than C++'s ordinary built-in types. The big number types in Multiprecision can be used with a wide selection of basic 
 mathematical operations, elementary transcendental functions as well as the functions in Boost.Math. The Multiprecision types can 
 also interoperate with the built-in types in C++ using clearly defined conversion rules. This allows Boost.Multiprecision to be 
 used for all kinds of mathematical calculations involving integer, rational and floating-point types requiring extended range and precision.

Multiprecision consists of a generic interface to the mathematics of large numbers as well as a selection of big number back ends, with 
support for integer, rational and floating-point types. Multiprecision provides a selection of back ends provided off-the-rack in 
including interfaces to GMP, MPFR, MPIR, TomMath as well as its own collection of Boost-licensed, header-only back ends for integers, 
rationals, floats and complex. In addition, user-defined back ends can be created and used with the interface of Multiprecision
, provided the class implementation adheres to the necessary concepts.

Depending upon the number type, precision may be arbitrarily large (limited only by available memory), fixed at compile time 
(for example 50 or 100 decimal digits), or a variable controlled at run-time by member functions. The types are expression-template-enabled 
for better performance than naive user-defined types. 

Multiprecision also features Fp finite fields operations available in runtime and compile-time as well.

The full documentation is available on [boost.org](http://www.boost.org/doc/libs/release/libs/multiprecision/index.html).

## Support, bugs and feature requests ##

Bugs and feature requests can be reported through the [Gitub issue tracker](https://github.com/nilfoundation/crypto3-multiprecision/issues).

You can submit your changes through a [pull request](https://github.com/nilfoundation/crypto3-multiprecision/pulls).


## Development ##

Clone the module repository project:

    git clone https://github.com/nilfoundation/crypto3-multiprecision
    cd crypto3-multiprecision
    git submodule update --init
    mkdir build && cmake ..

### Running tests ###
First, make sure you are in `libs/multiprecision/test`. 
You can either run all the tests listed in `Jamfile.v2` or run a single test:

    ../../../b2                        <- run all tests
    ../../../b2 test_complex           <- single test

## Dependencies

### External
* [Boost](https://boost.org) (>= 1.73). Because boost::config doesn't have BOOST_IF_CONSTEXPR definition before 1.73 version.
