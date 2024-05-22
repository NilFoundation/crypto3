=nil; Foundation's Multiprecision Library
============================

 The Multiprecision Library provides optimal arithmetic operations over a finite field, using Montgomery and Barret reductions.

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

## Dependencies

### External
* [Boost](https://boost.org) (>= 1.73). Because boost::config doesn't have BOOST_IF_CONSTEXPR definition before 1.73 version.
