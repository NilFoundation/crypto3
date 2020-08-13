//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_ECOP_HPP
#define ALGEBRA_CURVES_ECOP_HPP

#include <stdexcept>
#include <vector>

namespace nil {
    namespace algebra {
        namespace curve {
            namespace detail {


                    template<class Fp>
                    void FrobEndOnTwist_1(Fp2T<Fp> *Q, const Fp2T<Fp> *P) {
                        typedef Fp2T<Fp> Fp2;
                        typedef ParamT<Fp2> Param;
                        // applying Q[0] <- P[0]^q

                        Q[0].a_ = P[0].a_;
                        Q[0].b_ = -P[0].b_;

                        // Q[0] *= xi^((p-1)/3)
                        Q[0] *= Param::gammar[1];

                        // applying Q[1] <- P[1]^q
                        Q[1].a_ = P[1].a_;
                        Q[1].b_ = -P[1].b_;

                        // Q[1] *= xi^((p-1)/2)
                        Q[1] *= Param::gammar[2];

                    }

                    template<class Fp>
                    void FrobEndOnTwist_2(Fp2T<Fp> *Q, const Fp2T<Fp> *P) {

                        Fp2T<Fp> scratch[2];
                        FrobEndOnTwist_1(scratch, P);
                        FrobEndOnTwist_1(Q, scratch);

                    }

                    template<class Fp>
                    void FrobEndOnTwist_8(Fp2T<Fp> *Q, const Fp2T<Fp> *P) {

                        Fp2T<Fp> scratch2[2], scratch4[2], scratch6[2];
                        FrobEndOnTwist_2(scratch2, P);
                        FrobEndOnTwist_2(scratch4, scratch2);
                        FrobEndOnTwist_2(scratch6, scratch4);
                        FrobEndOnTwist_2(Q, scratch6);

                    }

            }   // namespace detail 
        }   //  namespace curve
    }   //  namespace algebra
}   //  namespace nil

#endif    // ALGEBRA_CURVES_ECOP_HPP
