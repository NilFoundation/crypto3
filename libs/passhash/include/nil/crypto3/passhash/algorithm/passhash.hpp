//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PASSHASH_HPP
#define CRYPTO3_PASSHASH_HPP

namespace nil {
    namespace crypto3 {
        namespace passhash {

            /*!
             * @defgroup passhash Password Hashing Functions
             *
             * @brief Storing passwords for user authentication purposes in plaintext is the
             * simplest but least secure method; when an attacker compromises the
             * database in which the passwords are stored, they immediately gain
             * access to all of them. Often passwords are reused among multiple
             * services or machines, meaning once a password to a single service is
             * known an attacker has a substantial head start on attacking other
             * machines.
             *
             * The general approach is to store, instead of the password, the output
             * of a one way function of the password. Upon receiving an
             * authentication request, the authenticator can recompute the one way
             * function and compare the value just computed with the one that was
             * stored. If they match, then the authentication request succeeds. But
             * when an attacker gains access to the database, they only have the
             * output of the one way function, not the original password.
             *
             * Common hash functions such as SHA2-256 are one way, but used alone they
             * have problems for this purpose. What an attacker can do, upon gaining
             * access to such a stored password database, is hash common dictionary
             * words and other possible passwords, storing them in a list. Then he
             * can search through his list; if a stored hash and an entry in his list
             * match, then he has found the password. Even worse, this can happen
             * *offline*: an attacker can begin hashing common passwords days,
             * months, or years before ever gaining access to the database. In
             * addition, if two users choose the same password, the one way function
             * output will be the same for both of them, which will be visible upon
             * inspection of the database.
             *
             * There are two solutions to these problems: salting and
             * iteration. Salting refers to including, along with the password, a
             * randomly chosen value which perturbs the one way function. Salting can
             * reduce the effectiveness of offline dictionary generation, because for
             * each potential password, an attacker would have to compute the one way
             * function output for all possible salts. It also prevents the same
             * password from producing the same output, as long as the salts do not
             * collide. Choosing n-bit salts randomly, salt collisions become likely
             * only after about 2\ :sup:\ `(n/2)` salts have been generated. Choosing a
             * large salt (say 80 to 128 bits) ensures this is very unlikely. Note
             * that in password hashing salt collisions are unfortunate, but not
             * fatal - it simply allows the attacker to attack those two passwords in
             * parallel easier than they would otherwise be able to.
             *
             * The other approach, iteration, refers to the general technique of
             * forcing multiple one way function evaluations when computing the
             * output, to slow down the operation. For instance if hashing a single
             * password requires running SHA2-256 100,000 times instead of just once,
             * that will slow down user authentication by a factor of 100,000, but
             * user authentication happens quite rarely, and usually there are more
             * expensive operations that need to occur anyway (network and database
             * I/O, etc). On the other hand, an attacker who is attempting to break a
             * database full of stolen password hashes will be seriously
             * inconvenienced by a factor of 100,000 slowdown; they will be able to
             * only test at a rate of .0001% of what they would without iterations
             * (or, equivalently, will require 100,000 times as many zombie botnet
             * hosts).
             *
             * Memory usage while checking a password is also a consideration; if the
             * computation requires using a certain minimum amount of memory, then an
             * attacker can become memory-bound, which may in particular make
             * customized cracking hardware more expensive. Some password hashing
             * designs, such as scrypt, explicitly attempt to provide this. The
             * bcrypt approach requires over 4 KiB of RAM (for the Blowfish key
             * round_constants_words) and may also make some hardware attacks more expensive.
             *
             * @defgroup passhash_algorithms Algorithms
             * @ingroup passhash
             * @brief Algorithms are meant to provide password hashing.
             */
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PASSHASH_HPP
