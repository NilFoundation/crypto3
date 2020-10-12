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

#ifndef CRYPTO3_PUBKEY_POLYN_GF2M_HPP
#define CRYPTO3_PUBKEY_POLYN_GF2M_HPP

#include <nil/crypto3/utilities/secmem.hpp>

#include <nil/crypto3/pubkey/detail/mceliece/gf2m_small_m.hpp>
#include <nil/crypto3/pubkey/detail/mceliece/code_based_util.hpp>

#include <utility>

namespace nil {
    namespace crypto3 {
        namespace {

            uint32_t patch_root_array(gf2m *res_root_arr, uint32_t res_root_arr_len, uint32_t root_pos) {
                volatile uint32_t i;
                volatile gf2m patch_elem = 0x01;
                volatile gf2m cond_mask = (root_pos == res_root_arr_len);
                cond_mask = expand_mask_16bit(cond_mask);
                cond_mask = ~cond_mask; /* now cond = 1 if not enough roots */
                patch_elem &= cond_mask;
                for (i = 0; i < res_root_arr_len; i++) {

                    gf2m masked_patch_elem = (patch_elem++) & cond_mask;
                    res_root_arr[i] ^= masked_patch_elem++;
                }
                return res_root_arr_len;
            }

            class gf2m_decomp_rootfind_state {
            public:
                gf2m_decomp_rootfind_state(const polyn_gf2m &p_polyn, uint32_t code_length);

                void calc_LiK(const polyn_gf2m &sigma);

                gf2m calc_Fxj_j_neq_0(const polyn_gf2m &sigma, gf2m j_gray);

                void calc_next_Aij();

                void calc_Ai_zero(const polyn_gf2m &sigma);

                secure_vector<gf2m> find_roots(const polyn_gf2m &sigma);

                uint32_t get_code_length() const {
                    return code_length;
                }

                uint32_t code_length;
                secure_vector<gf2m> m_Lik;    // size is outer_summands * m
                secure_vector<gf2m> m_Aij;    // ...
                uint32_t m_outer_summands;
                gf2m m_j;
                gf2m m_j_gray;
                gf2m m_sigma_3_l;
                gf2m m_sigma_3_neq_0_mask;
            };

/*
 * !! Attention: assumes gf2m is 16bit !!
 */
#if 0
            gf2m brootf_decomp_gray_to_lex(gf2m gray)
               {
               static_assert(sizeof(gf2m) == 2, "Expected size");
               gf2m result = gray ^ (gray>>8);
               result ^= (result >> 4);
               result ^= (result >> 2);
               result ^= (result >> 1);
               return result;
               }
#endif

            /**
             * calculates ceil((t-4)/5) = outer_summands - 1
             */
            uint32_t brootf_decomp_calc_sum_limit(uint32_t t) {
                uint32_t result;
                if (t < 4) {
                    return 0;
                }
                result = t - 4;
                result += 4;
                result /= 5;
                return result;
            }

            gf2m_decomp_rootfind_state::gf2m_decomp_rootfind_state(const polyn_gf2m &polyn, uint32_t the_code_length) :
                code_length(the_code_length), m_j(0), m_j_gray(0) {
                gf2m coeff_3;
                gf2m coeff_head;
                std::shared_ptr<gf2m_field> sp_field = polyn.get_sp_field();
                int deg_sigma = polyn.get_degree();
                if (deg_sigma <= 3) {
                    throw internal_error("Unexpected degree in gf2m_decomp_rootfind_state");
                }

                coeff_3 = polyn.get_coef(3);
                coeff_head = polyn.get_coef(deg_sigma); /* dummy value for SCA CM */
                if (coeff_3 != 0) {
                    this->m_sigma_3_l = sp_field->gf_l_from_n(coeff_3);
                    this->m_sigma_3_neq_0_mask = 0xFFFF;
                } else {
                    // dummy value needed for timing countermeasure
                    this->m_sigma_3_l = sp_field->gf_l_from_n(coeff_head);
                    this->m_sigma_3_neq_0_mask = 0;
                }

                this->m_outer_summands = 1 + brootf_decomp_calc_sum_limit(deg_sigma);
                this->m_Lik.resize(this->m_outer_summands * sp_field->get_extension_degree());
                this->m_Aij.resize(this->m_outer_summands);
            }

            void gf2m_decomp_rootfind_state::calc_Ai_zero(const polyn_gf2m &sigma) {
                uint32_t i;
                /*
                 * this function assumes this the first gray code element is zero
                 */
                for (i = 0; i < this->m_outer_summands; i++) {
                    this->m_Aij[i] = sigma.get_coef(5 * i);
                }
                this->m_j = 0;
                this->m_j_gray = 0;
            }

            void gf2m_decomp_rootfind_state::calc_next_Aij() {
                /*
                 * upon function entry, we have in the state j, Aij.
                 * first thing, we declare Aij Aij_minusone and increase j.
                 * Case j=0 upon function entry also included, then Aij contains A_{i,j=0}.
                 */
                uint32_t i;
                gf2m diff, new_j_gray;
                uint32_t Lik_pos_base;

                this->m_j++;

                new_j_gray = lex_to_gray(this->m_j);

                if (this->m_j & 1) /* half of the times */
                {
                    Lik_pos_base = 0;
                } else if (this->m_j & 2) /* one quarter of the times */
                {
                    Lik_pos_base = this->m_outer_summands;
                } else if (this->m_j & 4) /* one eighth of the times */
                {
                    Lik_pos_base = this->m_outer_summands * 2;
                } else if (this->m_j & 8) /* one sixteenth of the times */
                {
                    Lik_pos_base = this->m_outer_summands * 3;
                } else if (this->m_j & 16) /* ... */
                {
                    Lik_pos_base = this->m_outer_summands * 4;
                } else {
                    gf2m delta_offs = 5;
                    diff = this->m_j_gray ^ new_j_gray;
                    while (((static_cast<gf2m>(1) << delta_offs) & diff) == 0) {
                        delta_offs++;
                    }
                    Lik_pos_base = delta_offs * this->m_outer_summands;
                }
                this->m_j_gray = new_j_gray;

                i = 0;
                for (; i < this->m_outer_summands; i++) {
                    this->m_Aij[i] ^= this->m_Lik[Lik_pos_base + i];
                }
            }

            void gf2m_decomp_rootfind_state::calc_LiK(const polyn_gf2m &sigma) {
                std::shared_ptr<gf2m_field> sp_field = sigma.get_sp_field();
                uint32_t i, k, d;
                d = sigma.get_degree();
                for (k = 0; k < sp_field->get_extension_degree(); k++) {
                    uint32_t Lik_pos_base = k * this->m_outer_summands;
                    gf2m alpha_l_k_tt2_ttj[4];
                    alpha_l_k_tt2_ttj[0] = sp_field->gf_l_from_n(static_cast<gf2m>(1) << k);
                    alpha_l_k_tt2_ttj[1] = sp_field->gf_mul_rrr(alpha_l_k_tt2_ttj[0], alpha_l_k_tt2_ttj[0]);
                    alpha_l_k_tt2_ttj[2] = sp_field->gf_mul_rrr(alpha_l_k_tt2_ttj[1], alpha_l_k_tt2_ttj[1]);

                    alpha_l_k_tt2_ttj[3] = sp_field->gf_mul_rrr(alpha_l_k_tt2_ttj[2], alpha_l_k_tt2_ttj[2]);
                    for (i = 0; i < this->m_outer_summands; i++) {
                        uint32_t j;
                        uint32_t five_i = 5 * i;
                        uint32_t Lik_pos = Lik_pos_base + i;
                        this->m_Lik[Lik_pos] = 0;
                        for (j = 0; j <= 3; j++) {
                            gf2m f, x;
                            uint32_t f_ind = five_i + (static_cast<uint32_t>(1) << j);
                            if (f_ind > d) {
                                break;
                            }
                            f = sigma.get_coef(f_ind);

                            x = sp_field->gf_mul_zrz(alpha_l_k_tt2_ttj[j], f);
                            this->m_Lik[Lik_pos] ^= x;
                        }
                    }
                }
            }

            gf2m gf2m_decomp_rootfind_state::calc_Fxj_j_neq_0(const polyn_gf2m &sigma, gf2m j_gray) {
                // needs the A_{ij} to compute F(x)_j
                gf2m sum = 0;
                uint32_t i;
                std::shared_ptr<gf2m_field> sp_field = sigma.get_sp_field();
                const gf2m jl_gray = sp_field->gf_l_from_n(j_gray);
                gf2m xl_j_tt_5 = sp_field->gf_square_rr(jl_gray);
                gf2m xl_gray_tt_3 = sp_field->gf_mul_rrr(xl_j_tt_5, jl_gray);
                xl_j_tt_5 = sp_field->gf_mul_rrr(xl_j_tt_5, xl_gray_tt_3);

                sum = sp_field->gf_mul_nrr(xl_gray_tt_3, this->m_sigma_3_l);
                sum &= this->m_sigma_3_neq_0_mask;
                /* here, we rely on compiler to be unable to optimize
                 * for the state->sigma_3_neq_0_mask value
                 */
                /* treat i = 0 special: */
                sum ^= this->m_Aij[0];
                /* treat i = 1 special also */

                if (this->m_outer_summands > 1) {
                    gf2m x;
                    x = sp_field->gf_mul_zrz(xl_j_tt_5, this->m_Aij[1]); /* x_j^{5i} A_i^j */
                    sum ^= x;
                }

                gf2m xl_j_tt_5i = xl_j_tt_5;

                for (i = 2; i < this->m_outer_summands; i++) {
                    gf2m x;
                    xl_j_tt_5i = sp_field->gf_mul_rrr(xl_j_tt_5i, xl_j_tt_5);
                    // now x_j_tt_5i lives up to its name
                    x = sp_field->gf_mul_zrz(xl_j_tt_5i, this->m_Aij[i]); /* x_j^{5i} A_i^(j) */
                    sum ^= x;
                }
                return sum;
            }

            secure_vector<gf2m> gf2m_decomp_rootfind_state::find_roots(const polyn_gf2m &sigma) {
                const int sigma_degree = sigma.get_degree();
                BOOST_ASSERT_MSG(sigma_degree > 0, "Valid sigma");
                secure_vector<gf2m> result(sigma_degree);
                uint32_t root_pos = 0;

                this->calc_Ai_zero(sigma);
                this->calc_LiK(sigma);
                do {
                    gf2m eval_result;
                    if (this->m_j_gray == 0) {
                        eval_result = sigma.get_coef(0);
                    } else {
                        eval_result = this->calc_Fxj_j_neq_0(sigma, this->m_j_gray);
                    }

                    if (eval_result == 0) {

                        result[root_pos] = this->m_j_gray;
                        root_pos++;
                    }
                    if (this->m_j + static_cast<uint32_t>(1) == this->get_code_length()) {
                        break;
                    }
                    this->calc_next_Aij();
                } while (1);

                // side channel / fault attack countermeasure:
                root_pos = patch_root_array(result.data(), result.size(), root_pos);
                result.resize(root_pos);
                return result;
            }

        }    // end anonymous namespace

        class random_number_generator;

        class polyn_gf2m {
        public:
            /**
             * create a zero polynomial:
             */
            explicit polyn_gf2m(std::shared_ptr<gf2m_field> sp_field);

            polyn_gf2m() : m_deg(-1) {
            }

            polyn_gf2m(const secure_vector<uint8_t> &encoded, std::shared_ptr<gf2m_field> sp_field);

            polyn_gf2m &operator=(const polyn_gf2m &) = default;

            bool operator==(const polyn_gf2m &other) const;

            bool operator!=(const polyn_gf2m &other) const {
                return !(*this == other);
            }

            polyn_gf2m(polyn_gf2m &&other) {
                this->swap(other);
            }

            polyn_gf2m &operator=(polyn_gf2m &&other) {
                if (this != &other) {
                    this->swap(other);
                }
                return *this;
            }

            void swap(polyn_gf2m &other);

            secure_vector<uint8_t> encode() const;

            /**
             * create zero polynomial with reservation of space for a degree d polynomial
             */
            polyn_gf2m(int d, std::shared_ptr<gf2m_field> sp_field);

            polyn_gf2m(polyn_gf2m const &other);
            /**
             * create zero polynomial with allocated size determined by specified degree d:
             */

            /**
             * random irreducible polynomial of degree t
             */
            polyn_gf2m(int t, random_number_generator &rng, std::shared_ptr<gf2m_field> sp_field);

            std::shared_ptr<gf2m_field> get_sp_field() const {
                return msp_field;
            }

            gf2m &operator[](size_t i) {
                return coeff[i];
            }

            gf2m operator[](size_t i) const {
                return coeff[i];
            }

            gf2m get_lead_coef() const {
                return coeff[m_deg];
            }

            gf2m get_coef(uint32_t i) const {
                return coeff[i];
            }

            inline void set_coef(uint32_t i, gf2m v) {
                coeff[i] = v;
            }

            inline void add_to_coef(uint32_t i, gf2m v) {
                coeff[i] = coeff[i] ^ v;
            }

            std::string to_string() const;

            /** decode a polynomial from memory: **/
            polyn_gf2m(const uint8_t *mem, uint32_t mem_len, std::shared_ptr<gf2m_field> sp_field);
            // remove one! ^v!
            /**
             *  create a polynomial from memory area (encoded)
             */
            polyn_gf2m(int degree, const unsigned char *mem, uint32_t mem_byte_len,
                       std::shared_ptr<gf2m_field> sp_field);

            void encode(uint32_t min_numo_coeffs, uint8_t *mem, uint32_t mem_len) const;

            int get_degree() const;

            /**
             * determine the degree in a timing secure manner. the timing of this function
             * only depends on the number of allocated coefficients, not on the actual
             * degree
             */
            int calc_degree_secure() const;

            void degppf(const polyn_gf2m &g, int *p_result);

            static std::vector<polyn_gf2m> sqmod_init(const polyn_gf2m &g);

            static std::vector<polyn_gf2m> sqrt_mod_init(const polyn_gf2m &g);

            polyn_gf2m sqmod(const std::vector<polyn_gf2m> &sq, int d);

            void set_to_zero();

            gf2m eval(gf2m a);

            static std::pair<polyn_gf2m, polyn_gf2m> eea_with_coefficients(const polyn_gf2m &p, const polyn_gf2m &g,
                                                                           int break_deg);

            void patchup_deg_secure(uint32_t trgt_deg, volatile gf2m patch_elem);

        private:
            void set_degree(int d) {
                m_deg = d;
            }

            void poly_shiftmod(const polyn_gf2m &g);

            void realloc(uint32_t new_size);

            static polyn_gf2m gcd(polyn_gf2m const &p1, polyn_gf2m const &p2);

            /**
             * destructive:
             */
            static void remainder(polyn_gf2m &p, const polyn_gf2m &g);

            static polyn_gf2m gcd_aux(polyn_gf2m &p1, polyn_gf2m &p2);

        public:
            // public member variable:
            int m_deg;

            // public member variable:
            secure_vector<gf2m> coeff;

            // public member variable:
            std::shared_ptr<gf2m_field> msp_field;
        };

        gf2m random_gf2m(random_number_generator &rng);

        gf2m random_code_element(unsigned code_length, random_number_generator &rng);

        std::vector<polyn_gf2m> syndrome_init(polyn_gf2m const &generator, std::vector<gf2m> const &support, int n);

        /**
         * Find the roots of a polynomial over GF(2^m) using the method by Federenko
         * et al.
         */
        secure_vector<gf2m> find_roots_gf2m_decomp(const polyn_gf2m &polyn, uint32_t code_length) {
            gf2m_decomp_rootfind_state state(polyn, code_length);
            return state.find_roots(polyn);
        }

        namespace {

            gf2m generate_gf2m_mask(gf2m a) {
                gf2m result = (a != 0);
                return ~(result - 1);
            }

            /**
             * number of leading zeros
             */
            unsigned nlz_16bit(uint16_t x) {
                unsigned n;
                if (x == 0) {
                    return 16;
                }
                n = 0;
                if (x <= 0x00FF) {
                    n = n + 8;
                    x = x << 8;
                }
                if (x <= 0x0FFF) {
                    n = n + 4;
                    x = x << 4;
                }
                if (x <= 0x3FFF) {
                    n = n + 2;
                    x = x << 2;
                }
                if (x <= 0x7FFF) {
                    n = n + 1;
                }
                return n;
            }
        }    // namespace

        int polyn_gf2m::calc_degree_secure() const {
            int i = this->coeff.size() - 1;
            int result = 0;
            uint32_t found_mask = 0;
            uint32_t tracker_mask = 0xffff;
            for (; i >= 0; i--) {
                found_mask = expand_mask_16bit(this->coeff[i]);
                result |= i & found_mask & tracker_mask;
                // tracker mask shall become zero once found mask is set
                // it shall remain zero from then on
                tracker_mask = tracker_mask & ~found_mask;
            }
            const_cast<polyn_gf2m *>(this)->m_deg = result;
            return result;
        }

        gf2m random_gf2m(RandomNumberGenerator &rng) {
            uint8_t b[2];
            rng.randomize(b, sizeof(b));
            return make_uint_t<16>(b[1], b[0]);
        }

        gf2m random_code_element(unsigned code_length, RandomNumberGenerator &rng) {
            if (code_length == 0) {
                throw std::invalid_argument("random_code_element() was supplied a code length of zero");
            }
            const unsigned nlz = nlz_16bit(code_length - 1);
            const gf2m mask = (1 << (16 - nlz)) - 1;

            gf2m result;

            do {
                result = random_gf2m(rng);
                result &= mask;
            } while (result >= code_length);    // rejection sampling

            return result;
        }

        polyn_gf2m::polyn_gf2m(polyn_gf2m const &other) :
            m_deg(other.m_deg), coeff(other.coeff), msp_field(other.msp_field) {
        }

        polyn_gf2m::polyn_gf2m(int d, std::shared_ptr<gf2m_field> sp_field) :
            m_deg(-1), coeff(d + 1), msp_field(sp_field) {
        }

        std::string polyn_gf2m::to_string() const {
            int d = get_degree();
            std::string result;
            for (int i = 0; i <= d; i++) {
                result += std::to_string(this->coeff[i]);
                if (i != d) {
                    result += ", ";
                }
            }
            return result;
        }

        /**
         * doesn't save coefficients:
         */
        void polyn_gf2m::realloc(uint32_t new_size) {
            this->coeff = secure_vector<gf2m>(new_size);
        }

        polyn_gf2m::polyn_gf2m(const uint8_t *mem, uint32_t mem_len, std::shared_ptr<gf2m_field> sp_field) :
            msp_field(sp_field) {
            if (mem_len % sizeof(gf2m)) {
                throw nil::crypto3::decoding_error("illegal length of memory to decode ");
            }

            uint32_t size = (mem_len / sizeof(this->coeff[0]));
            this->coeff = secure_vector<gf2m>(size);
            this->m_deg = -1;
            for (uint32_t i = 0; i < size; i++) {
                this->coeff[i] = decode_gf2m(mem);
                mem += sizeof(this->coeff[0]);
            }
            for (uint32_t i = 0; i < size; i++) {
                if (this->coeff[i] >= (1 << sp_field->get_extension_degree())) {
                    throw nil::crypto3::decoding_error("error decoding polynomial");
                }
            }
            this->get_degree();
        }

        polyn_gf2m::polyn_gf2m(std::shared_ptr<gf2m_field> sp_field) : m_deg(-1), coeff(1), msp_field(sp_field) {
        }

        polyn_gf2m::polyn_gf2m(int degree, const unsigned char *mem, uint32_t mem_byte_len,
                               std::shared_ptr<gf2m_field> sp_field) :
            msp_field(sp_field) {
            uint32_t j, k, l;
            gf2m a;
            uint32_t polyn_size;
            polyn_size = degree + 1;
            if (polyn_size * sp_field->get_extension_degree() > 8 * mem_byte_len) {
                throw nil::crypto3::decoding_error("memory vector for polynomial has wrong size");
            }
            this->coeff = secure_vector<gf2m>(degree + 1);
            gf2m ext_deg = this->msp_field->get_extension_degree();
            for (l = 0; l < polyn_size; l++) {
                k = (l * ext_deg) / 8;

                j = (l * ext_deg) % 8;
                a = mem[k] >> j;
                if (j + ext_deg > 8) {
                    a ^= mem[k + 1] << (8 - j);
                }
                if (j + ext_deg > 16) {
                    a ^= mem[k + 2] << (16 - j);
                }
                a &= ((1 << ext_deg) - 1);
                (*this).set_coef(l, a);
            }

            this->get_degree();
        }

#if 0
        void polyn_gf2m::encode(uint32_t min_numo_coeffs, uint8_t* mem, uint32_t mem_len) const
           {
           uint32_t i;
           uint32_t numo_coeffs, needed_size;
           this->get_degree();
           numo_coeffs = (min_numo_coeffs > static_cast<uint32_t>(this->m_deg+1)) ? min_numo_coeffs : this->m_deg+1;
           needed_size = sizeof(this->coeff[0]) * numo_coeffs;
           if(mem_len < needed_size)
              {
              std::invalid_argument("provided memory too small to encode polynomial");
              }

           for(i = 0; i < numo_coeffs; i++)
              {
              gf2m to_enc;
              if(i >= static_cast<uint32_t>(this->m_deg+1))
                 {
                 /* encode a zero */
                 to_enc = 0;
                 }
              else
                 {
                 to_enc = this->coeff[i];
                 }
              mem += encode_gf2m(to_enc, mem);
              }
           }
#endif

        void polyn_gf2m::set_to_zero() {
            clear_mem(&this->coeff[0], this->coeff.size());
            this->m_deg = -1;
        }

        int polyn_gf2m::get_degree() const {
            int d = this->coeff.size() - 1;
            while ((d >= 0) && (this->coeff[d] == 0)) {
                --d;
            }
            const_cast<polyn_gf2m *>(this)->m_deg = d;
            return d;
        }

        static gf2m eval_aux(const gf2m * /*restrict*/ coeff, gf2m a, int d, std::shared_ptr<gf2m_field> sp_field) {
            gf2m b;
            b = coeff[d--];
            for (; d >= 0; --d) {
                if (b != 0) {
                    b = sp_field->gf_mul(b, a) ^ coeff[d];
                } else {
                    b = coeff[d];
                }
            }
            return b;
        }

        gf2m polyn_gf2m::eval(gf2m a) {
            return eval_aux(&this->coeff[0], a, this->m_deg, this->msp_field);
        }

        // p will contain it's remainder modulo g
        void polyn_gf2m::remainder(polyn_gf2m &p, const polyn_gf2m &g) {
            int i, j, d;
            std::shared_ptr<gf2m_field> msp_field = g.msp_field;
            d = p.get_degree() - g.get_degree();
            if (d >= 0) {
                gf2m la = msp_field->gf_inv_rn(g.get_lead_coef());

                const int p_degree = p.get_degree();

                BOOST_ASSERT_MSG(p_degree > 0, "Valid polynomial");

                for (i = p_degree; d >= 0; --i, --d) {
                    if (p[i] != 0) {
                        gf2m lb = msp_field->gf_mul_rrn(la, p[i]);
                        for (j = 0; j < g.get_degree(); ++j) {
                            p[j + d] ^= msp_field->gf_mul_zrz(lb, g[j]);
                        }
                        (*&p).set_coef(i, 0);
                    }
                }
                p.set_degree(g.get_degree() - 1);
                while ((p.get_degree() >= 0) && (p[p.get_degree()] == 0)) {
                    p.set_degree(p.get_degree() - 1);
                }
            }
        }

        std::vector<polyn_gf2m> polyn_gf2m::sqmod_init(const polyn_gf2m &g) {
            std::vector<polyn_gf2m> sq;
            const int signed_deg = g.get_degree();
            if (signed_deg <= 0) {
                throw std::invalid_argument("cannot compute sqmod for such low degree");
            }

            const uint32_t d = static_cast<uint32_t>(signed_deg);
            uint32_t t = g.m_deg;
            // create t zero polynomials
            uint32_t i;
            for (i = 0; i < t; ++i) {
                sq.push_back(polyn_gf2m(t + 1, g.get_sp_field()));
            }
            for (i = 0; i < d / 2; ++i) {
                sq[i].set_degree(2 * i);
                (*&sq[i]).set_coef(2 * i, 1);
            }

            for (; i < d; ++i) {
                clear_mem(&sq[i].coeff[0], 2);
                copy_mem(&sq[i].coeff[0] + 2, &sq[i - 1].coeff[0], d);
                sq[i].set_degree(sq[i - 1].get_degree() + 2);
                polyn_gf2m::remainder(sq[i], g);
            }
            return sq;
        }

        /*Modulo p square of a certain polynomial g, sq[] contains the square
        Modulo g of the core canonical polynomials of degree < d, where d is
        the degree of g. The table sq[] will be calculated by polyn_gf2m_sqmod_init*/
        polyn_gf2m polyn_gf2m::sqmod(const std::vector<polyn_gf2m> &sq, int d) {
            int i, j;
            gf2m la;
            std::shared_ptr<gf2m_field> sp_field = this->msp_field;

            polyn_gf2m result(d - 1, sp_field);
            // terms of low degree
            for (i = 0; i < d / 2; ++i) {
                (*&result).set_coef(i * 2, sp_field->gf_square((*this)[i]));
            }

            // terms of high degree
            for (; i < d; ++i) {
                gf2m lpi = (*this)[i];
                if (lpi != 0) {
                    lpi = sp_field->gf_log(lpi);
                    la = sp_field->gf_mul_rrr(lpi, lpi);
                    for (j = 0; j < d; ++j) {
                        result[j] ^= sp_field->gf_mul_zrz(la, sq[i][j]);
                    }
                }
            }

            // Update degre
            result.set_degree(d - 1);
            while ((result.get_degree() >= 0) && (result[result.get_degree()] == 0)) {
                result.set_degree(result.get_degree() - 1);
            }
            return result;
        }

        // destructive
        polyn_gf2m polyn_gf2m::gcd_aux(polyn_gf2m &p1, polyn_gf2m &p2) {
            if (p2.get_degree() == -1) {
                return p1;
            } else {
                polyn_gf2m::remainder(p1, p2);
                return polyn_gf2m::gcd_aux(p2, p1);
            }
        }

        polyn_gf2m polyn_gf2m::gcd(polyn_gf2m const &p1, polyn_gf2m const &p2) {
            polyn_gf2m a(p1);
            polyn_gf2m b(p2);
            if (a.get_degree() < b.get_degree()) {
                return polyn_gf2m(polyn_gf2m::gcd_aux(b, a));
            } else {
                return polyn_gf2m(polyn_gf2m::gcd_aux(a, b));
            }
        }

        // Returns the degree of the smallest factor
        void polyn_gf2m::degppf(const polyn_gf2m &g, int *p_result) {
            int i, d;
            polyn_gf2m s(g.get_sp_field());

            d = g.get_degree();
            std::vector<polyn_gf2m> u = polyn_gf2m::sqmod_init(g);

            polyn_gf2m p(d - 1, g.msp_field);

            p.set_degree(1);
            (*&p).set_coef(1, 1);
            (*p_result) = d;
            for (i = 1; i <= (d / 2) * g.msp_field->get_extension_degree(); ++i) {
                polyn_gf2m r = p.sqmod(u, d);
                if ((i % g.msp_field->get_extension_degree()) == 0) {
                    r[1] ^= 1;
                    r.get_degree();    // The degree may change
                    s = polyn_gf2m::gcd(g, r);

                    if (s.get_degree() > 0) {
                        (*p_result) = i / g.msp_field->get_extension_degree();
                        break;
                    }
                    r[1] ^= 1;
                    r.get_degree();    // The degree may change
                }
                // No need for the exchange s
                s = p;
                p = r;
                r = s;
            }
        }

        void polyn_gf2m::patchup_deg_secure(uint32_t trgt_deg, volatile gf2m patch_elem) {
            uint32_t i;
            if (this->coeff.size() < trgt_deg) {
                return;
            }
            for (i = 0; i < this->coeff.size(); i++) {
                uint32_t equal, equal_mask;
                this->coeff[i] |= patch_elem;
                equal = (i == trgt_deg);
                equal_mask = expand_mask_16bit(equal);
                patch_elem &= ~equal_mask;
            }
            this->calc_degree_secure();
        }

        // We suppose m_deg(g) >= m_deg(p)
        // v is the problem
        std::pair<polyn_gf2m, polyn_gf2m> polyn_gf2m::eea_with_coefficients(const polyn_gf2m &p, const polyn_gf2m &g,
                                                                            int break_deg) {

            std::shared_ptr<gf2m_field> msp_field = g.msp_field;
            int i, j, dr, du, delta;
            gf2m a;
            polyn_gf2m aux;

            // initialisation of the local variables
            // r0 <- g, r1 <- p, u0 <- 0, u1 <- 1
            dr = g.get_degree();

            BOOST_ASSERT_MSG(dr > 3, "Valid polynomial");

            polyn_gf2m r0(dr, g.msp_field);
            polyn_gf2m r1(dr - 1, g.msp_field);
            polyn_gf2m u0(dr - 1, g.msp_field);
            polyn_gf2m u1(dr - 1, g.msp_field);

            r0 = g;
            r1 = p;
            u0.set_to_zero();
            u1.set_to_zero();
            (*&u1).set_coef(0, 1);
            u1.set_degree(0);

            // invariants:
            // r1 = u1 * p + v1 * g
            // r0 = u0 * p + v0 * g
            // and m_deg(u1) = m_deg(g) - m_deg(r0)
            // It stops when m_deg (r1) <t (m_deg (r0)> = t)
            // And therefore m_deg (u1) = m_deg (g) - m_deg (r0) <m_deg (g) - break_deg
            du = 0;
            dr = r1.get_degree();
            delta = r0.get_degree() - dr;

            while (dr >= break_deg) {

                for (j = delta; j >= 0; --j) {
                    a = msp_field->gf_div(r0[dr + j], r1[dr]);
                    if (a != 0) {
                        gf2m la = msp_field->gf_log(a);
                        // u0(z) <- u0(z) + a * u1(z) * z^j
                        for (i = 0; i <= du; ++i) {
                            u0[i + j] ^= msp_field->gf_mul_zrz(la, u1[i]);
                        }
                        // r0(z) <- r0(z) + a * r1(z) * z^j
                        for (i = 0; i <= dr; ++i) {
                            r0[i + j] ^= msp_field->gf_mul_zrz(la, r1[i]);
                        }
                    }
                }    // end loop over j

                if (break_deg != 1) /* key eq. solving */
                {
                    /* [ssms_icisc09] Countermeasure
                     * d_break from paper equals break_deg - 1
                     * */

                    volatile gf2m fake_elem = 0x01;
                    volatile gf2m cond1, cond2;
                    int trgt_deg = r1.get_degree() - 1;
                    r0.calc_degree_secure();
                    u0.calc_degree_secure();
                    if (!(g.get_degree() % 2)) {
                        /* t even */
                        cond1 = r0.get_degree() < break_deg - 1;
                    } else {
                        /* t odd */
                        cond1 = r0.get_degree() < break_deg;
                        cond2 = u0.get_degree() < break_deg - 1;
                        cond1 &= cond2;
                    }
                    /* expand cond1 to a full mask */
                    gf2m mask = generate_gf2m_mask(cond1);
                    fake_elem &= mask;
                    r0.patchup_deg_secure(trgt_deg, fake_elem);
                }
                if (break_deg == 1) /* syndrome inversion */
                {
                    volatile gf2m fake_elem = 0x00;
                    volatile uint32_t trgt_deg = 0;
                    r0.calc_degree_secure();
                    u0.calc_degree_secure();
                    /**
                     * countermeasure against the low weight attacks for w=4, w=6 and w=8.
                     * Higher values are not covered since for w=8 we already have a
                     * probability for a positive of 1/n^3 from random ciphertexts with the
                     * given weight. For w = 10 it would be 1/n^4 and so on. Thus attacks
                     * based on such high values of w are considered impractical.
                     *
                     * The outer test for the degree of u ( Omega in the paper ) needs not to
                     * be disguised. Each of the three is performed at most once per EEA
                     * (syndrome inversion) execution, the attacker knows this already when
                     * preparing the ciphertext with the given weight. Inside these three
                     * cases however, we must use timing neutral (branch free) operations to
                     * implement the condition detection and the counteractions.
                     *
                     */
                    if (u0.get_degree() == 4) {
                        uint32_t mask = 0;
                        /**
                         * Condition that the EEA would break now
                         */
                        int cond_r = r0.get_degree() == 0;
                        /**
                         * Now come the conditions for all odd coefficients of this sigma
                         * candiate. If they are all fulfilled, then we know that we have a low
                         * weight error vector, since the key-equation solving EEA is skipped if
                         * the degree of tau^2 is low (=m_deg(u0)) and all its odd cofficients are
                         * zero (they would cause "full-length" contributions from the square
                         * root computation).
                         */
                        // Condition for the coefficient to Y to be cancelled out by the
                        // addition of Y before the square root computation:
                        int cond_u1 = msp_field->gf_mul(u0.coeff[1], msp_field->gf_inv(r0.coeff[0])) == 1;

                        // Condition sigma_3 = 0:
                        int cond_u3 = u0.coeff[3] == 0;
                        // combine the conditions:
                        cond_r &= (cond_u1 & cond_u3);
                        // mask generation:
                        mask = expand_mask_16bit(cond_r);
                        trgt_deg = 2 & mask;
                        fake_elem = 1 & mask;
                    } else if (u0.get_degree() == 6) {
                        uint32_t mask = 0;
                        int cond_r = r0.get_degree() == 0;
                        int cond_u1 = msp_field->gf_mul(u0.coeff[1], msp_field->gf_inv(r0.coeff[0])) == 1;
                        int cond_u3 = u0.coeff[3] == 0;

                        int cond_u5 = u0.coeff[5] == 0;

                        cond_r &= (cond_u1 & cond_u3 & cond_u5);
                        mask = expand_mask_16bit(cond_r);
                        trgt_deg = 4 & mask;
                        fake_elem = 1 & mask;
                    } else if (u0.get_degree() == 8) {
                        uint32_t mask = 0;
                        int cond_r = r0.get_degree() == 0;
                        int cond_u1 = msp_field->gf_mul(u0[1], msp_field->gf_inv(r0[0])) == 1;
                        int cond_u3 = u0.coeff[3] == 0;

                        int cond_u5 = u0.coeff[5] == 0;

                        int cond_u7 = u0.coeff[7] == 0;

                        cond_r &= (cond_u1 & cond_u3 & cond_u5 & cond_u7);
                        mask = expand_mask_16bit(cond_r);
                        trgt_deg = 6 & mask;
                        fake_elem = 1 & mask;
                    }
                    r0.patchup_deg_secure(trgt_deg, fake_elem);
                }
                // exchange
                aux = r0;
                r0 = r1;
                r1 = aux;
                aux = u0;
                u0 = u1;
                u1 = aux;

                du = du + delta;
                delta = 1;
                while (r1[dr - delta] == 0) {
                    delta++;
                }

                dr -= delta;
            } /* end  while loop (dr >= break_deg) */

            u1.set_degree(du);
            r1.set_degree(dr);
            // return u1 and r1;
            return std::make_pair(u1, r1);    // coefficients u,v
        }

        polyn_gf2m::polyn_gf2m(int t, nil::crypto3::RandomNumberGenerator &rng, std::shared_ptr<gf2m_field> sp_field) :
            m_deg(t), coeff(t + 1), msp_field(sp_field) {
            (*this).set_coef(t, 1);
            int degree = 0;
            do {
                for (int i = 0; i < t; ++i) {
                    (*this).set_coef(i, random_code_element(sp_field->get_cardinality(), rng));
                }
                polyn_gf2m::degppf(*this, &degree);
            } while (degree < t);
        }

        void polyn_gf2m::poly_shiftmod(const polyn_gf2m &g) {
            if (g.get_degree() <= 1) {
                throw std::invalid_argument("shiftmod cannot be called on polynomials of degree 1 or less");
            }
            std::shared_ptr<gf2m_field> field = g.msp_field;

            int t = g.get_degree();
            gf2m a = field->gf_div(this->coeff[t - 1], g.coeff[t]);
            for (int i = t - 1; i > 0; --i) {
                this->coeff[i] = this->coeff[i - 1] ^ this->msp_field->gf_mul(a, g.coeff[i]);
            }
            this->coeff[0] = field->gf_mul(a, g.coeff[0]);
        }

        std::vector<polyn_gf2m> polyn_gf2m::sqrt_mod_init(const polyn_gf2m &g) {
            uint32_t i, t;
            uint32_t nb_polyn_sqrt_mat;
            std::shared_ptr<gf2m_field> msp_field = g.msp_field;
            std::vector<polyn_gf2m> result;
            t = g.get_degree();
            nb_polyn_sqrt_mat = t / 2;

            std::vector<polyn_gf2m> sq_aux = polyn_gf2m::sqmod_init(g);

            polyn_gf2m p(t - 1, g.get_sp_field());
            p.set_degree(1);

            (*&p).set_coef(1, 1);
            // q(z) = 0, p(z) = z
            for (i = 0; i < t * msp_field->get_extension_degree() - 1; ++i) {
                // q(z) <- p(z)^2 mod g(z)
                polyn_gf2m q = p.sqmod(sq_aux, t);
                // q(z) <-> p(z)
                polyn_gf2m aux = q;
                q = p;
                p = aux;
            }
            // p(z) = z^(2^(tm-1)) mod g(z) = sqrt(z) mod g(z)

            for (i = 0; i < nb_polyn_sqrt_mat; ++i) {
                result.push_back(polyn_gf2m(t - 1, g.get_sp_field()));
            }

            result[0] = p;
            result[0].get_degree();
            for (i = 1; i < nb_polyn_sqrt_mat; i++) {
                result[i] = result[i - 1];
                result[i].poly_shiftmod(g), result[i].get_degree();
            }

            return result;
        }

        std::vector<polyn_gf2m> syndrome_init(polyn_gf2m const &generator, std::vector<gf2m> const &support, int n) {
            int i, j, t;
            gf2m a;

            std::shared_ptr<gf2m_field> msp_field = generator.msp_field;

            std::vector<polyn_gf2m> result;
            t = generator.get_degree();

            // g(z)=g_t+g_(t-1).z^(t-1)+......+g_1.z+g_0
            // f(z)=f_(t-1).z^(t-1)+......+f_1.z+f_0

            for (j = 0; j < n; j++) {
                result.push_back(polyn_gf2m(t - 1, msp_field));

                (*&result[j]).set_coef(t - 1, 1);
                for (i = t - 2; i >= 0; i--) {
                    (*&result[j])
                        .set_coef(i, (generator)[i + 1] ^ msp_field->gf_mul(lex_to_gray(support[j]), result[j][i + 1]));
                }
                a = ((generator)[0] ^ msp_field->gf_mul(lex_to_gray(support[j]), result[j][0]));
                for (i = 0; i < t; i++) {
                    (*&result[j]).set_coef(i, msp_field->gf_div(result[j][i], a));
                }
            }
            return result;
        }

        polyn_gf2m::polyn_gf2m(const secure_vector<uint8_t> &encoded, std::shared_ptr<gf2m_field> sp_field) :
            msp_field(sp_field) {
            if (encoded.size() % 2) {
                throw decoding_error("encoded polynomial has odd length");
            }
            for (uint32_t i = 0; i < encoded.size(); i += 2) {
                gf2m el = (encoded[i] << 8) | encoded[i + 1];
                coeff.push_back(el);
            }
            get_degree();
        }

        secure_vector<uint8_t> polyn_gf2m::encode() const {
            secure_vector<uint8_t> result;

            if (m_deg < 1) {
                result.push_back(0);
                result.push_back(0);
                return result;
            }

            uint32_t len = m_deg + 1;
            for (unsigned i = 0; i < len; i++) {
                // "big endian" encoding of the GF(2^m) elements
                result.push_back(coeff[i] >> 8);
                result.push_back(coeff[i]);
            }
            return result;
        }

        void polyn_gf2m::swap(polyn_gf2m &other) {
            std::swap(this->m_deg, other.m_deg);
            std::swap(this->msp_field, other.msp_field);
            std::swap(this->coeff, other.coeff);
        }

        bool polyn_gf2m::operator==(const polyn_gf2m &other) const {
            if (m_deg != other.m_deg || coeff != other.coeff) {
                return false;
            }
            return true;
        }
    }    // namespace crypto3
}    // namespace nil

#endif
