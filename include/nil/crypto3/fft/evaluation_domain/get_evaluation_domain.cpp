//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef GET_EVALUATION_DOMAIN_TCC_
#define GET_EVALUATION_DOMAIN_TCC_

#include <libfqfft/evaluation_domain/domains/arithmetic_sequence_domain.hpp>
#include <libfqfft/evaluation_domain/domains/basic_radix2_domain.hpp>
#include <libfqfft/evaluation_domain/domains/extended_radix2_domain.hpp>
#include <libfqfft/evaluation_domain/domains/geometric_sequence_domain.hpp>
#include <libfqfft/evaluation_domain/domains/step_radix2_domain.hpp>
#include <libfqfft/evaluation_domain/evaluation_domain.hpp>
#include <libfqfft/tools/exceptions.hpp>

namespace libfqfft {

    template<typename FieldT>
    std::shared_ptr<evaluation_domain<FieldT>> get_evaluation_domain(const size_t min_size) {
        std::shared_ptr<evaluation_domain<FieldT>> result;

        const size_t big = 1ul << (libff::log2(min_size) - 1);
        const size_t small = min_size - big;
        const size_t rounded_small = (1ul << libff::log2(small));

        try {
            result.reset(new basic_radix2_domain<FieldT>(min_size));
        } catch (...) {
            try {
                result.reset(new extended_radix2_domain<FieldT>(min_size));
            } catch (...) {
                try {
                    result.reset(new step_radix2_domain<FieldT>(min_size));
                } catch (...) {
                    try {
                        result.reset(new basic_radix2_domain<FieldT>(big + rounded_small));
                    } catch (...) {
                        try {
                            result.reset(new extended_radix2_domain<FieldT>(big + rounded_small));
                        } catch (...) {
                            try {
                                result.reset(new step_radix2_domain<FieldT>(big + rounded_small));
                            } catch (...) {
                                try {
                                    result.reset(new geometric_sequence_domain<FieldT>(min_size));
                                } catch (...) {
                                    try {
                                        result.reset(new arithmetic_sequence_domain<FieldT>(min_size));
                                    } catch (...) {
                                        throw DomainSizeException("get_evaluation_domain: no matching domain");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return result;
    }

}    // namespace libfqfft

#endif    // GET_EVALUATION_DOMAIN_TCC_
