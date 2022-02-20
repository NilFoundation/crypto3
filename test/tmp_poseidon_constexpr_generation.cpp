
#include <iostream>
#include <array>
#include <bitset>

#include <boost/multiprecision/cpp_int.hpp>


using namespace boost::multiprecision::literals;
using boost::multiprecision::number;
using boost::multiprecision::backends::cpp_int_backend;
using boost::multiprecision::cpp_integer_type;
using boost::multiprecision::cpp_int_check_type;

using std::cout;

#define BLS12_381_MODULUS_LEN 255
#define GRAIN_LFSR_STATE_LEN 80


BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(BLS12_381_MODULUS_LEN);
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(GRAIN_LFSR_STATE_LEN);


template<std::size_t t, std::size_t full_rounds, std::size_t part_rounds>
struct round_constants_generator {
    constexpr static std::size_t modulus_bits = BLS12_381_MODULUS_LEN;
    constexpr static std::size_t state_bits = GRAIN_LFSR_STATE_LEN;

    typedef number<cpp_int_backend<modulus_bits, modulus_bits, cpp_integer_type::unsigned_magnitude, cpp_int_check_type::unchecked, void>>
        integral_type;
    typedef number<cpp_int_backend<state_bits, state_bits, cpp_integer_type::unsigned_magnitude, cpp_int_check_type::unchecked, void>>
        state_type;

    constexpr static integral_type mod = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_cppui255;


    constexpr void generate_round_constants() {
        integral_type constant = 0x0_cppui255;
        state_type lfsr_state = get_lfsr_init_state();

        for (std::size_t i = 0; i < (full_rounds + part_rounds) * t; i++) {
            while (true) {
                constant = 0x0_cppui255;
                for (std::size_t i = 0; i < modulus_bits; i++) {
                    lfsr_state = update_state(lfsr_state);
                    constant = set_new_bit<integral_type>(constant, get_state_bit(lfsr_state, state_bits - 1));
                }
                if (constant < 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_cppui255) {
                    constants[i] = constant;
                    break;
                }
            }
        }
    }

    constexpr void generate_round_constants_unfolded() {
        integral_type constant = 0x0_cppui255;
        bool new_bit = false;
        state_type lfsr_state = get_lfsr_init_state();

        for (std::size_t i = 0; i < (full_rounds + part_rounds) * t; i++) {
            while (true) {
                constant = 0x0_cppui255;
                for (std::size_t i = 0; i < modulus_bits; i++) {
                    while (true) {
                        new_bit = ((lfsr_state & (0x1_cppui80 << (state_bits - 1))) != 0) !=
                                  ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 13))) != 0) !=
                                  ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 23))) != 0) !=
                                  ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 38))) != 0) !=
                                  ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 51))) != 0) !=
                                  ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 62))) != 0);
                        lfsr_state = (lfsr_state << 1) | (new_bit ? 1 : 0);
                        if (new_bit)
                            break;
                        else {
                            new_bit = ((lfsr_state & (0x1_cppui80 << (state_bits - 1))) != 0) !=
                                      ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 13))) != 0) !=
                                      ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 23))) != 0) !=
                                      ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 38))) != 0) !=
                                      ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 51))) != 0) !=
                                      ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 62))) != 0);
                            lfsr_state = (lfsr_state << 1) | (new_bit ? 1 : 0);
                        }
                    }
                    new_bit = ((lfsr_state & (0x1_cppui80 << (state_bits - 1))) != 0) !=
                              ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 13))) != 0) !=
                              ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 23))) != 0) !=
                              ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 38))) != 0) !=
                              ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 51))) != 0) !=
                              ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 62))) != 0);
                    lfsr_state = (lfsr_state << 1) | (new_bit ? 1 : 0);
                    constant = (constant << 1) | (lfsr_state & 1);
                }
                if (constant < 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_cppui255) {
                    constants[i] = constant;
                    break;
                }
            }
        }
    }

    constexpr static integral_type get_round_constant(std::size_t constant_number) {
        integral_type constant = 0x0_cppui255;

        state_type lfsr_state = get_lfsr_init_state();

        // previous constants
        for (std::size_t i = 0; i < constant_number; i++) {
            constant = 0x0_cppui255;
            while (true) {
                constant = 0x0_cppui255;
                for (std::size_t i = 0; i < modulus_bits; i++) {
                    lfsr_state = update_state(lfsr_state);
                    constant = set_new_bit<integral_type>(constant, get_state_bit(lfsr_state, state_bits - 1));
                }
                if (constant < 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_cppui255)
                    break;
            }
        }

        // requested constant
        while (true) {
            constant = 0x0_cppui255;
            for (std::size_t i = 0; i < modulus_bits; i++) {
                lfsr_state = update_state(lfsr_state);
                constant = set_new_bit<integral_type>(constant, get_state_bit(lfsr_state, state_bits - 1));
            }
            if (constant < 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_cppui255)
                break;
        }

        return constant;
    }

    constexpr static state_type get_lfsr_init_state() {
        state_type state = 0x0_cppui80;
        int i = 0;
        for (i = 1; i >= 0; i--)
            state = set_new_bit(state, (1 >> i) & 1); // field - as in filecoin
        for (i = 3; i >= 0; i--)
            state = set_new_bit(state, (1 >> i) & 1); // s-box - as in filecoin
        for (i = 11; i >= 0; i--)
            state = set_new_bit(state, (modulus_bits >> i) & 1);
        for (i = 11; i >= 0; i--)
            state = set_new_bit(state, (t >> i) & 1);
        for (i = 9; i >= 0; i--)
            state = set_new_bit(state, (full_rounds >> i) & 1);
        for (i = 9; i >= 0; i--)
            state = set_new_bit(state, (part_rounds >> i) & 1);
        for (i = 29; i >= 0; i--)
            state = set_new_bit(state, 1);
        // idling
        for (i = 0; i < 160; i++)
            state = update_state_raw(state);
        return state;
    }

    constexpr static state_type update_state(state_type state) {
        while (true) {
            state = update_state_raw(state);
            if (get_state_bit(state, state_bits - 1))
                break;
            else
                state = update_state_raw(state);
        }
        return update_state_raw(state);
    }

    constexpr static state_type update_state_raw(state_type state) {
        bool new_bit = get_state_bit(state, 0) != get_state_bit(state, 13) != get_state_bit(state, 23) !=
                       get_state_bit(state, 38) != get_state_bit(state, 51) != get_state_bit(state, 62);
        return set_new_bit(state, new_bit);
    }

    constexpr static bool get_state_bit(state_type state, std::size_t pos) {
        state_type bit_getter = 0x1_cppui80;
        bit_getter <<= (state_bits - 1 - pos);
        return (state & bit_getter) ? true : false;
    }

    template<typename T>
    constexpr static T set_new_bit(T var, bool new_bit) {
        return (var << 1) | (new_bit ? 1 : 0);
    }

    constexpr round_constants_generator() : constants() {
        // generate_round_constants();
        generate_round_constants_unfolded();
        
    }

    integral_type constants[(full_rounds + part_rounds) * t];

};


int main() {
    constexpr std::size_t width = 4;
    constexpr std::size_t full_rounds = 8;
    constexpr std::size_t part_rounds = 56;
    typedef round_constants_generator<width, full_rounds, part_rounds> rcg;
    
    // Add option -fconstexpr-ops-limit=4294967296 to compiler
    constexpr rcg gen;
    for (std::size_t i = 0; i < (8 + 56) * 4; i++)
        cout << gen.constants[i] << '\n';

    return 0;
}
