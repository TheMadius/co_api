/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef INNER_H__
#define INNER_H__

#include <string.h>
#include <limits.h>

#include "config.h"
#include "bearssl.h"

/*
 * Maximum size for a RSA modulus (in bits). Allocated stack buffers
 * depend on that size, so this value should be kept small. Currently,
 * 2048-bit RSA keys offer adequate security, and should still do so for
 * the next few decades; however, a number of widespread PKI have
 * already set their root keys to RSA-4096, so we should be able to
 * process such keys.
 *
 * This value MUST be a multiple of 64.
 */
#define BR_MAX_RSA_SIZE   4096

/*
 * Maximum size for a RSA factor (in bits). This is for RSA private-key
 * operations. Default is to support factors up to a bit more than half
 * the maximum modulus size.
 *
 * This value MUST be a multiple of 32.
 */
#define BR_MAX_RSA_FACTOR   ((BR_MAX_RSA_SIZE + 64) >> 1)

/*
 * Maximum size for an EC curve (modulus or order), in bits. Size of
 * stack buffers depends on that parameter. This size MUST be a multiple
 * of 8 (so that decoding an integer with that many bytes does not
 * overflow).
 */
#define BR_MAX_EC_SIZE   528

/*
 * Some macros to recognize the current architecture. Right now, we are
 * interested into automatically recognizing architecture with efficient
 * 64-bit types so that we may automatically use implementations that
 * use 64-bit registers in that case. Future versions may detect, e.g.,
 * availability of SSE2 intrinsics.
 *
 * If 'unsigned long' is a 64-bit type, then we assume that 64-bit types
 * are efficient. Otherwise, we rely on macros that depend on compiler,
 * OS and architecture. In any case, failure to detect the architecture
 * as 64-bit means that the 32-bit code will be used, and that code
 * works also on 64-bit architectures (the 64-bit code may simply be
 * more efficient).
 *
 * The test on 'unsigned long' should already catch most cases, the one
 * notable exception being Windows code where 'unsigned long' is kept to
 * 32-bit for compatbility with all the legacy code that liberally uses
 * the 'DWORD' type for 32-bit values.
 *
 * Macro names are taken from: http://nadeausoftware.com/articles/2012/02/c_c_tip_how_detect_processor_type_using_compiler_predefined_macros
 */
#ifndef BR_64
#if ((ULONG_MAX >> 31) >> 31) == 3
#define BR_64   1
#elif defined(__ia64) || defined(__itanium__) || defined(_M_IA64)
#define BR_64   1
#elif defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__) \
	|| defined(__64BIT__) || defined(_LP64) || defined(__LP64__)
#define BR_64   1
#elif defined(__sparc64__)
#define BR_64   1
#elif defined(__x86_64__) || defined(_M_X64)
#define BR_64   1
#endif
#endif

/* ==================================================================== */
/*
 * Encoding/decoding functions.
 *
 * 32-bit and 64-bit decoding, both little-endian and big-endian, is
 * implemented with the inline functions below. These functions are
 * generic: they don't depend on the architecture natural endianness,
 * and they can handle unaligned accesses. Optimized versions for some
 * specific architectures may be implemented at a later time.
 */

static inline void
br_enc16le(void *dst, unsigned x)
{
	unsigned char *buf;

	buf = dst;
	buf[0] = (unsigned char)x;
	buf[1] = (unsigned char)(x >> 8);
}

static inline void
br_enc16be(void *dst, unsigned x)
{
	unsigned char *buf;

	buf = dst;
	buf[0] = (unsigned char)(x >> 8);
	buf[1] = (unsigned char)x;
}

static inline unsigned
br_dec16le(const void *src)
{
	const unsigned char *buf;

	buf = src;
	return (unsigned)buf[0] | ((unsigned)buf[1] << 8);
}

static inline unsigned
br_dec16be(const void *src)
{
	const unsigned char *buf;

	buf = src;
	return ((unsigned)buf[0] << 8) | (unsigned)buf[1];
}

static inline void
br_enc32le(void *dst, uint32_t x)
{
	unsigned char *buf;

	buf = dst;
	buf[0] = (unsigned char)x;
	buf[1] = (unsigned char)(x >> 8);
	buf[2] = (unsigned char)(x >> 16);
	buf[3] = (unsigned char)(x >> 24);
}

static inline void
br_enc32be(void *dst, uint32_t x)
{
	unsigned char *buf;

	buf = dst;
	buf[0] = (unsigned char)(x >> 24);
	buf[1] = (unsigned char)(x >> 16);
	buf[2] = (unsigned char)(x >> 8);
	buf[3] = (unsigned char)x;
}

static inline uint32_t
br_dec32le(const void *src)
{
	const unsigned char *buf;

	buf = src;
	return (uint32_t)buf[0]
		| ((uint32_t)buf[1] << 8)
		| ((uint32_t)buf[2] << 16)
		| ((uint32_t)buf[3] << 24);
}

static inline uint32_t
br_dec32be(const void *src)
{
	const unsigned char *buf;

	buf = src;
	return ((uint32_t)buf[0] << 24)
		| ((uint32_t)buf[1] << 16)
		| ((uint32_t)buf[2] << 8)
		| (uint32_t)buf[3];
}

static inline void
br_enc64le(void *dst, uint64_t x)
{
	unsigned char *buf;

	buf = dst;
	br_enc32le(buf, (uint32_t)x);
	br_enc32le(buf + 4, (uint32_t)(x >> 32));
}

static inline void
br_enc64be(void *dst, uint64_t x)
{
	unsigned char *buf;

	buf = dst;
	br_enc32be(buf, (uint32_t)(x >> 32));
	br_enc32be(buf + 4, (uint32_t)x);
}

static inline uint64_t
br_dec64le(const void *src)
{
	const unsigned char *buf;

	buf = src;
	return (uint64_t)br_dec32le(buf)
		| ((uint64_t)br_dec32le(buf + 4) << 32);
}

static inline uint64_t
br_dec64be(const void *src)
{
	const unsigned char *buf;

	buf = src;
	return ((uint64_t)br_dec32be(buf) << 32)
		| (uint64_t)br_dec32be(buf + 4);
}

/*
 * Range decoding and encoding (for several successive values).
 */
void br_range_dec16le(uint16_t *v, size_t num, const void *src);
void br_range_dec16be(uint16_t *v, size_t num, const void *src);
void br_range_enc16le(void *dst, const uint16_t *v, size_t num);
void br_range_enc16be(void *dst, const uint16_t *v, size_t num);

void br_range_dec32le(uint32_t *v, size_t num, const void *src);
void br_range_dec32be(uint32_t *v, size_t num, const void *src);
void br_range_enc32le(void *dst, const uint32_t *v, size_t num);
void br_range_enc32be(void *dst, const uint32_t *v, size_t num);

void br_range_dec64le(uint64_t *v, size_t num, const void *src);
void br_range_dec64be(uint64_t *v, size_t num, const void *src);
void br_range_enc64le(void *dst, const uint64_t *v, size_t num);
void br_range_enc64be(void *dst, const uint64_t *v, size_t num);

/*
 * Byte-swap a 32-bit integer.
 */
static inline uint32_t
br_swap32(uint32_t x)
{
	x = ((x & (uint32_t)0x00FF00FF) << 8)
		| ((x >> 8) & (uint32_t)0x00FF00FF);
	return (x << 16) | (x >> 16);
}

/* ==================================================================== */
/*
 * Support code for hash functions.
 */

/*
 * IV for MD5, SHA-1, SHA-224 and SHA-256.
 */
extern const uint32_t br_md5_IV[];
extern const uint32_t br_sha1_IV[];
extern const uint32_t br_sha224_IV[];
extern const uint32_t br_sha256_IV[];

/*
 * Round functions for MD5, SHA-1, SHA-224 and SHA-256 (SHA-224 and
 * SHA-256 use the same round function).
 */
void br_md5_round(const unsigned char *buf, uint32_t *val);
void br_sha1_round(const unsigned char *buf, uint32_t *val);
void br_sha2small_round(const unsigned char *buf, uint32_t *val);

/*
 * The core function for the TLS PRF. It computes
 * P_hash(secret, label + seed), and XORs the result into the dst buffer.
 */
void br_tls_phash(void *dst, size_t len,
	const br_hash_class *dig,
	const void *secret, size_t secret_len,
	const char *label, const void *seed, size_t seed_len);

/*
 * Copy all configured hash implementations from a multihash context
 * to another.
 */
static inline void
br_multihash_copyimpl(br_multihash_context *dst,
	const br_multihash_context *src)
{
	memcpy(dst->impl, src->impl, sizeof src->impl);
}

/* ==================================================================== */
/*
 * Constant-time primitives. These functions manipulate 32-bit values in
 * order to provide constant-time comparisons and multiplexers.
 *
 * Boolean values (the "ctl" bits) MUST have value 0 or 1.
 *
 * Implementation notes:
 * =====================
 *
 * The uintN_t types are unsigned and with width exactly N bits; the C
 * standard guarantees that computations are performed modulo 2^N, and
 * there can be no overflow. Negation (unary '-') works on unsigned types
 * as well.
 *
 * The intN_t types are guaranteed to have width exactly N bits, with no
 * padding bit, and using two's complement representation. Casting
 * intN_t to uintN_t really is conversion modulo 2^N. Beware that intN_t
 * types, being signed, trigger implementation-defined behaviour on
 * overflow (including raising some signal): with GCC, while modular
 * arithmetics are usually applied, the optimizer may assume that
 * overflows don't occur (unless the -fwrapv command-line option is
 * added); Clang has the additional -ftrapv option to explicitly trap on
 * integer overflow or underflow.
 */

/*
 * Negate a boolean.
 */
static inline uint32_t
NOT(uint32_t ctl)
{
	return ctl ^ 1;
}

/*
 * Multiplexer: returns x if ctl == 1, y if ctl == 0.
 */
static inline uint32_t
MUX(uint32_t ctl, uint32_t x, uint32_t y)
{
	return y ^ (-ctl & (x ^ y));
}

/*
 * Equality check: returns 1 if x == y, 0 otherwise.
 */
static inline uint32_t
EQ(uint32_t x, uint32_t y)
{
	uint32_t q;

	q = x ^ y;
	return NOT((q | -q) >> 31);
}

/*
 * Inequality check: returns 1 if x != y, 0 otherwise.
 */
static inline uint32_t
NEQ(uint32_t x, uint32_t y)
{
	uint32_t q;

	q = x ^ y;
	return (q | -q) >> 31;
}

/*
 * Comparison: returns 1 if x > y, 0 otherwise.
 */
static inline uint32_t
GT(uint32_t x, uint32_t y)
{
	/*
	 * If both x < 2^31 and x < 2^31, then y-x will have its high
	 * bit set if x > y, cleared otherwise.
	 *
	 * If either x >= 2^31 or y >= 2^31 (but not both), then the
	 * result is the high bit of x.
	 *
	 * If both x >= 2^31 and y >= 2^31, then we can virtually
	 * subtract 2^31 from both, and we are back to the first case.
	 * Since (y-2^31)-(x-2^31) = y-x, the subtraction is already
	 * fine.
	 */
	uint32_t z;

	z = y - x;
	return (z ^ ((x ^ y) & (x ^ z))) >> 31;
}

/*
 * Other comparisons (greater-or-equal, lower-than, lower-or-equal).
 */
#define GE(x, y)   NOT(GT(y, x))
#define LT(x, y)   GT(y, x)
#define LE(x, y)   NOT(GT(x, y))

/*
 * General comparison: returned value is -1, 0 or 1, depending on
 * whether x is lower than, equal to, or greater than y.
 */
static inline int32_t
CMP(uint32_t x, uint32_t y)
{
	return (int32_t)GT(x, y) | -(int32_t)GT(y, x);
}

/*
 * Returns 1 if x == 0, 0 otherwise. Take care that the operand is signed.
 */
static inline uint32_t
EQ0(int32_t x)
{
	uint32_t q;

	q = (uint32_t)x;
	return ~(q | -q) >> 31;
}

/*
 * Returns 1 if x > 0, 0 otherwise. Take care that the operand is signed.
 */
static inline uint32_t
GT0(int32_t x)
{
	/*
	 * High bit of -x is 0 if x == 0, but 1 if x > 0.
	 */
	uint32_t q;

	q = (uint32_t)x;
	return (~q & -q) >> 31;
}

/*
 * Returns 1 if x >= 0, 0 otherwise. Take care that the operand is signed.
 */
static inline uint32_t
GE0(int32_t x)
{
	return ~(uint32_t)x >> 31;
}

/*
 * Returns 1 if x < 0, 0 otherwise. Take care that the operand is signed.
 */
static inline uint32_t
LT0(int32_t x)
{
	return (uint32_t)x >> 31;
}

/*
 * Returns 1 if x <= 0, 0 otherwise. Take care that the operand is signed.
 */
static inline uint32_t
LE0(int32_t x)
{
	uint32_t q;

	/*
	 * ~-x has its high bit set if and only if -x is nonnegative (as
	 * a signed int), i.e. x is in the -(2^31-1) to 0 range. We must
	 * do an OR with x itself to account for x = -2^31.
	 */
	q = (uint32_t)x;
	return (q | ~-q) >> 31;
}

/*
 * Conditional copy: src[] is copied into dst[] if and only if ctl is 1.
 * dst[] and src[] may overlap completely (but not partially).
 */
void br_ccopy(uint32_t ctl, void *dst, const void *src, size_t len);

#define CCOPY   br_ccopy

/*
 * Compute the bit length of a 32-bit integer. Returned value is between 0
 * and 32 (inclusive).
 */
static inline uint32_t
BIT_LENGTH(uint32_t x)
{
	uint32_t k, c;

	k = NEQ(x, 0);
	c = GT(x, 0xFFFF); x = MUX(c, x >> 16, x); k += c << 4;
	c = GT(x, 0x00FF); x = MUX(c, x >>  8, x); k += c << 3;
	c = GT(x, 0x000F); x = MUX(c, x >>  4, x); k += c << 2;
	c = GT(x, 0x0003); x = MUX(c, x >>  2, x); k += c << 1;
	k += GT(x, 0x0001);
	return k;
}

/*
 * Compute the minimum of x and y.
 */
static inline uint32_t
MIN(uint32_t x, uint32_t y)
{
	return MUX(GT(x, y), y, x);
}

/*
 * Compute the maximum of x and y.
 */
static inline uint32_t
MAX(uint32_t x, uint32_t y)
{
	return MUX(GT(x, y), x, y);
}

/*
 * Multiply two 32-bit integers, with a 64-bit result. This default
 * implementation assumes that the basic multiplication operator
 * yields constant-time code.
 */
#define MUL(x, y)   ((uint64_t)(x) * (uint64_t)(y))

#if BR_CT_MUL31

/*
 * Alternate implementation of MUL31, that will be constant-time on some
 * (old) platforms where the default MUL31 is not. Unfortunately, it is
 * also substantially slower, and yields larger code, on more modern
 * platforms, which is why it is deactivated by default.
 *
 * MUL31_lo() must do some extra work because on some platforms, the
 * _signed_ multiplication may return early if the top bits are 1.
 * Simply truncating (casting) the output of MUL31() would not be
 * sufficient, because the compiler may notice that we keep only the low
 * word, and then replace automatically the unsigned multiplication with
 * a signed multiplication opcode.
 */
#define MUL31(x, y)   ((uint64_t)((x) | (uint32_t)0x80000000) \
                       * (uint64_t)((y) | (uint32_t)0x80000000) \
                       - ((uint64_t)(x) << 31) - ((uint64_t)(y) << 31) \
                       - ((uint64_t)1 << 62))
static inline uint32_t
MUL31_lo(uint32_t x, uint32_t y)
{
	uint32_t xl, xh;
	uint32_t yl, yh;

	xl = (x & 0xFFFF) | (uint32_t)0x80000000;
	xh = (x >> 16) | (uint32_t)0x80000000;
	yl = (y & 0xFFFF) | (uint32_t)0x80000000;
	yh = (y >> 16) | (uint32_t)0x80000000;
	return (xl * yl + ((xl * yh + xh * yl) << 16)) & (uint32_t)0x7FFFFFFF;
}

#else

/*
 * Multiply two 31-bit integers, with a 62-bit result. This default
 * implementation assumes that the basic multiplication operator
 * yields constant-time code.
 * The MUL31_lo() macro returns only the low 31 bits of the product.
 */
#define MUL31(x, y)     ((uint64_t)(x) * (uint64_t)(y))
#define MUL31_lo(x, y)  (((uint32_t)(x) * (uint32_t)(y)) & (uint32_t)0x7FFFFFFF)

#endif

/*
 * Multiply two words together; the sum of the lengths of the two
 * operands must not exceed 31 (for instance, one operand may use 16
 * bits if the other fits on 15). If BR_CT_MUL15 is non-zero, then the
 * macro will contain some extra operations that help in making the
 * operation constant-time on some platforms, where the basic 32-bit
 * multiplication is not constant-time.
 */
#if BR_CT_MUL15
#define MUL15(x, y)   (((uint32_t)(x) | (uint32_t)0x80000000) \
                       * ((uint32_t)(y) | (uint32_t)0x80000000) \
		       & (uint32_t)0x7FFFFFFF)
#else
#define MUL15(x, y)   ((uint32_t)(x) * (uint32_t)(y))
#endif

/*
 * Arithmetic right shift (sign bit is copied). What happens when
 * right-shifting a negative value is _implementation-defined_, so it
 * does not trigger undefined behaviour, but it is still up to each
 * compiler to define (and document) what it does. Most/all compilers
 * will do an arithmetic shift, the sign bit being used to fill the
 * holes; this is a native operation on the underlying CPU, and it would
 * make little sense for the compiler to do otherwise. GCC explicitly
 * documents that it follows that convention.
 *
 * Still, if BR_NO_ARITH_SHIFT is defined (and non-zero), then an
 * alternate version will be used, that does not rely on such
 * implementation-defined behaviour. Unfortunately, it is also slower
 * and yields bigger code, which is why it is deactivated by default.
 */
#if BR_NO_ARITH_SHIFT
#define ARSH(x, n)   (((uint32_t)(x) >> (n)) \
                      | ((-((uint32_t)(x) >> 31)) << (32 - (n))))
#else
#define ARSH(x, n)   ((*(int32_t *)&(x)) >> (n))
#endif

/*
 * Constant-time division. The dividend hi:lo is divided by the
 * divisor d; the quotient is returned and the remainder is written
 * in *r. If hi == d, then the quotient does not fit on 32 bits;
 * returned value is thus truncated. If hi > d, returned values are
 * indeterminate.
 */
uint32_t br_divrem(uint32_t hi, uint32_t lo, uint32_t d, uint32_t *r);

/*
 * Wrapper for br_divrem(); the remainder is returned, and the quotient
 * is discarded.
 */
static inline uint32_t
br_rem(uint32_t hi, uint32_t lo, uint32_t d)
{
	uint32_t r;

	br_divrem(hi, lo, d, &r);
	return r;
}

/*
 * Wrapper for br_divrem(); the quotient is returned, and the remainder
 * is discarded.
 */
static inline uint32_t
br_div(uint32_t hi, uint32_t lo, uint32_t d)
{
	uint32_t r;

	return br_divrem(hi, lo, d, &r);
}

/* ==================================================================== */

/*
 * Integers 'i32'
 * --------------
 *
 * The 'i32' functions implement computations on big integers using
 * an internal representation as an array of 32-bit integers. For
 * an array x[]:
 *  -- x[0] contains the "announced bit length" of the integer
 *  -- x[1], x[2]... contain the value in little-endian order (x[1]
 *     contains the least significant 32 bits)
 *
 * Multiplications rely on the elementary 32x32->64 multiplication.
 *
 * The announced bit length specifies the number of bits that are
 * significant in the subsequent 32-bit words. Unused bits in the
 * last (most significant) word are set to 0; subsequent words are
 * uninitialized and need not exist at all.
 *
 * The execution time and memory access patterns of all computations
 * depend on the announced bit length, but not on the actual word
 * values. For modular integers, the announced bit length of any integer
 * modulo n is equal to the actual bit length of n; thus, computations
 * on modular integers are "constant-time" (only the modulus length may
 * leak).
 */

/*
 * Compute the actual bit length of an integer. The argument x should
 * point to the first (least significant) value word of the integer.
 * The len 'xlen' contains the number of 32-bit words to access.
 *
 * CT: value or length of x does not leak.
 */
uint32_t br_i32_bit_length(uint32_t *x, size_t xlen);

/*
 * Decode an integer from its big-endian unsigned representation. The
 * "true" bit length of the integer is computed, but all words of x[]
 * corresponding to the full 'len' bytes of the source are set.
 *
 * CT: value or length of x does not leak.
 */
void br_i32_decode(uint32_t *x, const void *src, size_t len);

/*
 * Decode an integer from its big-endian unsigned representation. The
 * integer MUST be lower than m[]; the announced bit length written in
 * x[] will be equal to that of m[]. All 'len' bytes from the source are
 * read.
 *
 * Returned value is 1 if the decode value fits within the modulus, 0
 * otherwise. In the latter case, the x[] buffer will be set to 0 (but
 * still with the announced bit length of m[]).
 *
 * CT: value or length of x does not leak. Memory access pattern depends
 * only of 'len' and the announced bit length of m. Whether x fits or
 * not does not leak either.
 */
uint32_t br_i32_decode_mod(uint32_t *x,
	const void *src, size_t len, const uint32_t *m);

/*
 * Reduce an integer (a[]) modulo another (m[]). The result is written
 * in x[] and its announced bit length is set to be equal to that of m[].
 *
 * x[] MUST be distinct from a[] and m[].
 *
 * CT: only announced bit lengths leak, not values of x, a or m.
 */
void br_i32_reduce(uint32_t *x, const uint32_t *a, const uint32_t *m);

/*
 * Decode an integer from its big-endian unsigned representation, and
 * reduce it modulo the provided modulus m[]. The announced bit length
 * of the result is set to be equal to that of the modulus.
 *
 * x[] MUST be distinct from m[].
 */
void br_i32_decode_reduce(uint32_t *x,
	const void *src, size_t len, const uint32_t *m);

/*
 * Encode an integer into its big-endian unsigned representation. The
 * output length in bytes is provided (parameter 'len'); if the length
 * is too short then the integer is appropriately truncated; if it is
 * too long then the extra bytes are set to 0.
 */
void br_i32_encode(void *dst, size_t len, const uint32_t *x);

/*
 * Multiply x[] by 2^32 and then add integer z, modulo m[]. This
 * function assumes that x[] and m[] have the same announced bit
 * length, and the announced bit length of m[] matches its true
 * bit length.
 *
 * x[] and m[] MUST be distinct arrays.
 *
 * CT: only the common announced bit length of x and m leaks, not
 * the values of x, z or m.
 */
void br_i32_muladd_small(uint32_t *x, uint32_t z, const uint32_t *m);

/*
 * Extract one word from an integer. The offset is counted in bits.
 * The word MUST entirely fit within the word elements corresponding
 * to the announced bit length of a[].
 */
static inline uint32_t
br_i32_word(const uint32_t *a, uint32_t off)
{
	size_t u;
	unsigned j;

	u = (size_t)(off >> 5) + 1;
	j = (unsigned)off & 31;
	if (j == 0) {
		return a[u];
	} else {
		return (a[u] >> j) | (a[u + 1] << (32 - j));
	}
}

/*
 * Test whether an integer is zero.
 */
uint32_t br_i32_iszero(const uint32_t *x);

/*
 * Add b[] to a[] and return the carry (0 or 1). If ctl is 0, then a[]
 * is unmodified, but the carry is still computed and returned. The
 * arrays a[] and b[] MUST have the same announced bit length.
 *
 * a[] and b[] MAY be the same array, but partial overlap is not allowed.
 */
uint32_t br_i32_add(uint32_t *a, const uint32_t *b, uint32_t ctl);

/*
 * Subtract b[] from a[] and return the carry (0 or 1). If ctl is 0,
 * then a[] is unmodified, but the carry is still computed and returned.
 * The arrays a[] and b[] MUST have the same announced bit length.
 *
 * a[] and b[] MAY be the same array, but partial overlap is not allowed.
 */
uint32_t br_i32_sub(uint32_t *a, const uint32_t *b, uint32_t ctl);

/*
 * Compute d+a*b, result in d. The initial announced bit length of d[]
 * MUST match that of a[]. The d[] array MUST be large enough to
 * accommodate the full result, plus (possibly) an extra word. The
 * resulting announced bit length of d[] will be the sum of the announced
 * bit lengths of a[] and b[] (therefore, it may be larger than the actual
 * bit length of the numerical result).
 *
 * a[] and b[] may be the same array. d[] must be disjoint from both a[]
 * and b[].
 */
void br_i32_mulacc(uint32_t *d, const uint32_t *a, const uint32_t *b);

/*
 * Zeroize an integer. The announced bit length is set to the provided
 * value, and the corresponding words are set to 0.
 */
static inline void
br_i32_zero(uint32_t *x, uint32_t bit_len)
{
	*x ++ = bit_len;
	memset(x, 0, ((bit_len + 31) >> 5) * sizeof *x);
}

/*
 * Compute -(1/x) mod 2^32. If x is even, then this function returns 0.
 */
uint32_t br_i32_ninv32(uint32_t x);

/*
 * Convert a modular integer to Montgomery representation. The integer x[]
 * MUST be lower than m[], but with the same announced bit length.
 */
void br_i32_to_monty(uint32_t *x, const uint32_t *m);

/*
 * Convert a modular integer back from Montgomery representation. The
 * integer x[] MUST be lower than m[], but with the same announced bit
 * length. The "m0i" parameter is equal to -(1/m0) mod 2^32, where m0 is
 * the least significant value word of m[] (this works only if m[] is
 * an odd integer).
 */
void br_i32_from_monty(uint32_t *x, const uint32_t *m, uint32_t m0i);

/*
 * Compute a modular Montgomery multiplication. d[] is filled with the
 * value of x*y/R modulo m[] (where R is the Montgomery factor). The
 * array d[] MUST be distinct from x[], y[] and m[]. x[] and y[] MUST be
 * numerically lower than m[]. x[] and y[] MAY be the same array. The
 * "m0i" parameter is equal to -(1/m0) mod 2^32, where m0 is the least
 * significant value word of m[] (this works only if m[] is an odd
 * integer).
 */
void br_i32_montymul(uint32_t *d, const uint32_t *x, const uint32_t *y,
	const uint32_t *m, uint32_t m0i);

/*
 * Compute a modular exponentiation. x[] MUST be an integer modulo m[]
 * (same announced bit length, lower value). m[] MUST be odd. The
 * exponent is in big-endian unsigned notation, over 'elen' bytes. The
 * "m0i" parameter is equal to -(1/m0) mod 2^32, where m0 is the least
 * significant value word of m[] (this works only if m[] is an odd
 * integer). The t1[] and t2[] parameters must be temporary arrays,
 * each large enough to accommodate an integer with the same size as m[].
 */
void br_i32_modpow(uint32_t *x, const unsigned char *e, size_t elen,
	const uint32_t *m, uint32_t m0i, uint32_t *t1, uint32_t *t2);

/* ==================================================================== */

/*
 * Integers 'i31'
 * --------------
 *
 * The 'i31' functions implement computations on big integers using
 * an internal representation as an array of 32-bit integers. For
 * an array x[]:
 *  -- x[0] encodes the array length and the "announced bit length"
 *     of the integer: namely, if the announced bit length is k,
 *     then x[0] = ((k / 31) << 5) + (k % 31).
 *  -- x[1], x[2]... contain the value in little-endian order, 31
 *     bits per word (x[1] contains the least significant 31 bits).
 *     The upper bit of each word is 0.
 *
 * Multiplications rely on the elementary 32x32->64 multiplication.
 *
 * The announced bit length specifies the number of bits that are
 * significant in the subsequent 32-bit words. Unused bits in the
 * last (most significant) word are set to 0; subsequent words are
 * uninitialized and need not exist at all.
 *
 * The execution time and memory access patterns of all computations
 * depend on the announced bit length, but not on the actual word
 * values. For modular integers, the announced bit length of any integer
 * modulo n is equal to the actual bit length of n; thus, computations
 * on modular integers are "constant-time" (only the modulus length may
 * leak).
 */

/*
 * Test whether an integer is zero.
 */
uint32_t br_i31_iszero(const uint32_t *x);

/*
 * Add b[] to a[] and return the carry (0 or 1). If ctl is 0, then a[]
 * is unmodified, but the carry is still computed and returned. The
 * arrays a[] and b[] MUST have the same announced bit length.
 *
 * a[] and b[] MAY be the same array, but partial overlap is not allowed.
 */
uint32_t br_i31_add(uint32_t *a, const uint32_t *b, uint32_t ctl);

/*
 * Subtract b[] from a[] and return the carry (0 or 1). If ctl is 0,
 * then a[] is unmodified, but the carry is still computed and returned.
 * The arrays a[] and b[] MUST have the same announced bit length.
 *
 * a[] and b[] MAY be the same array, but partial overlap is not allowed.
 */
uint32_t br_i31_sub(uint32_t *a, const uint32_t *b, uint32_t ctl);

/*
 * Compute the ENCODED actual bit length of an integer. The argument x
 * should point to the first (least significant) value word of the
 * integer. The len 'xlen' contains the number of 32-bit words to
 * access. The upper bit of each value word MUST be 0.
 * Returned value is ((k / 31) << 5) + (k % 31) if the bit length is k.
 *
 * CT: value or length of x does not leak.
 */
uint32_t br_i31_bit_length(uint32_t *x, size_t xlen);

/*
 * Decode an integer from its big-endian unsigned representation. The
 * "true" bit length of the integer is computed and set in the encoded
 * announced bit length (x[0]), but all words of x[] corresponding to
 * the full 'len' bytes of the source are set.
 *
 * CT: value or length of x does not leak.
 */
void br_i31_decode(uint32_t *x, const void *src, size_t len);

/*
 * Decode an integer from its big-endian unsigned representation. The
 * integer MUST be lower than m[]; the (encoded) announced bit length
 * written in x[] will be equal to that of m[]. All 'len' bytes from the
 * source are read.
 *
 * Returned value is 1 if the decode value fits within the modulus, 0
 * otherwise. In the latter case, the x[] buffer will be set to 0 (but
 * still with the announced bit length of m[]).
 *
 * CT: value or length of x does not leak. Memory access pattern depends
 * only of 'len' and the announced bit length of m. Whether x fits or
 * not does not leak either.
 */
uint32_t br_i31_decode_mod(uint32_t *x,
	const void *src, size_t len, const uint32_t *m);

/*
 * Zeroize an integer. The announced bit length is set to the provided
 * value, and the corresponding words are set to 0. The ENCODED bit length
 * is expected here.
 */
static inline void
br_i31_zero(uint32_t *x, uint32_t bit_len)
{
	*x ++ = bit_len;
	memset(x, 0, ((bit_len + 31) >> 5) * sizeof *x);
}

/*
 * Right-shift an integer. The shift amount must be lower than 31
 * bits.
 */
void br_i31_rshift(uint32_t *x, int count);

/*
 * Reduce an integer (a[]) modulo another (m[]). The result is written
 * in x[] and its announced bit length is set to be equal to that of m[].
 *
 * x[] MUST be distinct from a[] and m[].
 *
 * CT: only announced bit lengths leak, not values of x, a or m.
 */
void br_i31_reduce(uint32_t *x, const uint32_t *a, const uint32_t *m);

/*
 * Decode an integer from its big-endian unsigned representation, and
 * reduce it modulo the provided modulus m[]. The announced bit length
 * of the result is set to be equal to that of the modulus.
 *
 * x[] MUST be distinct from m[].
 */
void br_i31_decode_reduce(uint32_t *x,
	const void *src, size_t len, const uint32_t *m);

/*
 * Multiply x[] by 2^31 and then add integer z, modulo m[]. This
 * function assumes that x[] and m[] have the same announced bit
 * length, the announced bit length of m[] matches its true
 * bit length.
 *
 * x[] and m[] MUST be distinct arrays. z MUST fit in 31 bits (upper
 * bit set to 0).
 *
 * CT: only the common announced bit length of x and m leaks, not
 * the values of x, z or m.
 */
void br_i31_muladd_small(uint32_t *x, uint32_t z, const uint32_t *m);

/*
 * Encode an integer into its big-endian unsigned representation. The
 * output length in bytes is provided (parameter 'len'); if the length
 * is too short then the integer is appropriately truncated; if it is
 * too long then the extra bytes are set to 0.
 */
void br_i31_encode(void *dst, size_t len, const uint32_t *x);

/*
 * Compute -(1/x) mod 2^31. If x is even, then this function returns 0.
 */
uint32_t br_i31_ninv31(uint32_t x);

/*
 * Compute a modular Montgomery multiplication. d[] is filled with the
 * value of x*y/R modulo m[] (where R is the Montgomery factor). The
 * array d[] MUST be distinct from x[], y[] and m[]. x[] and y[] MUST be
 * numerically lower than m[]. x[] and y[] MAY be the same array. The
 * "m0i" parameter is equal to -(1/m0) mod 2^31, where m0 is the least
 * significant value word of m[] (this works only if m[] is an odd
 * integer).
 */
void br_i31_montymul(uint32_t *d, const uint32_t *x, const uint32_t *y,
	const uint32_t *m, uint32_t m0i);

/*
 * Convert a modular integer to Montgomery representation. The integer x[]
 * MUST be lower than m[], but with the same announced bit length.
 */
void br_i31_to_monty(uint32_t *x, const uint32_t *m);

/*
 * Convert a modular integer back from Montgomery representation. The
 * integer x[] MUST be lower than m[], but with the same announced bit
 * length. The "m0i" parameter is equal to -(1/m0) mod 2^32, where m0 is
 * the least significant value word of m[] (this works only if m[] is
 * an odd integer).
 */
void br_i31_from_monty(uint32_t *x, const uint32_t *m, uint32_t m0i);

/*
 * Compute a modular exponentiation. x[] MUST be an integer modulo m[]
 * (same announced bit length, lower value). m[] MUST be odd. The
 * exponent is in big-endian unsigned notation, over 'elen' bytes. The
 * "m0i" parameter is equal to -(1/m0) mod 2^31, where m0 is the least
 * significant value word of m[] (this works only if m[] is an odd
 * integer). The t1[] and t2[] parameters must be temporary arrays,
 * each large enough to accommodate an integer with the same size as m[].
 */
void br_i31_modpow(uint32_t *x, const unsigned char *e, size_t elen,
	const uint32_t *m, uint32_t m0i, uint32_t *t1, uint32_t *t2);

/*
 * Compute d+a*b, result in d. The initial announced bit length of d[]
 * MUST match that of a[]. The d[] array MUST be large enough to
 * accommodate the full result, plus (possibly) an extra word. The
 * resulting announced bit length of d[] will be the sum of the announced
 * bit lengths of a[] and b[] (therefore, it may be larger than the actual
 * bit length of the numerical result).
 *
 * a[] and b[] may be the same array. d[] must be disjoint from both a[]
 * and b[].
 */
void br_i31_mulacc(uint32_t *d, const uint32_t *a, const uint32_t *b);

/* ==================================================================== */

static inline void
br_i15_zero(uint16_t *x, uint16_t bit_len)
{
	*x ++ = bit_len;
	memset(x, 0, ((bit_len + 15) >> 4) * sizeof *x);
}

uint32_t br_i15_iszero(const uint16_t *x);

uint16_t br_i15_ninv15(uint16_t x);

uint32_t br_i15_add(uint16_t *a, const uint16_t *b, uint32_t ctl);

uint32_t br_i15_sub(uint16_t *a, const uint16_t *b, uint32_t ctl);

void br_i15_muladd_small(uint16_t *x, uint16_t z, const uint16_t *m);

void br_i15_montymul(uint16_t *d, const uint16_t *x, const uint16_t *y,
	const uint16_t *m, uint16_t m0i);

void br_i15_to_monty(uint16_t *x, const uint16_t *m);

void br_i15_modpow(uint16_t *x, const unsigned char *e, size_t elen,
	const uint16_t *m, uint16_t m0i, uint16_t *t1, uint16_t *t2);

void br_i15_encode(void *dst, size_t len, const uint16_t *x);

uint32_t br_i15_decode_mod(uint16_t *x,
	const void *src, size_t len, const uint16_t *m);

void br_i15_rshift(uint16_t *x, int count);

uint32_t br_i15_bit_length(uint16_t *x, size_t xlen);

void br_i15_decode(uint16_t *x, const void *src, size_t len);

void br_i15_from_monty(uint16_t *x, const uint16_t *m, uint16_t m0i);

void br_i15_decode_reduce(uint16_t *x,
	const void *src, size_t len, const uint16_t *m);

void br_i15_reduce(uint16_t *x, const uint16_t *a, const uint16_t *m);

void br_i15_mulacc(uint16_t *d, const uint16_t *a, const uint16_t *b);

/* ==================================================================== */

static inline size_t
br_digest_size(const br_hash_class *digest_class)
{
	return (size_t)(digest_class->desc >> BR_HASHDESC_OUT_OFF)
		& BR_HASHDESC_OUT_MASK;
}

/*
 * Get the output size (in bytes) of a hash function.
 */
size_t br_digest_size_by_ID(int digest_id);

/*
 * Get the OID (encoded OBJECT IDENTIFIER value, without tag and length)
 * for a hash function. If digest_id is not a supported digest identifier
 * (in particular if it is equal to 0, i.e. br_md5sha1_ID), then NULL is
 * returned and *len is set to 0.
 */
const unsigned char *br_digest_OID(int digest_id, size_t *len);

/* ==================================================================== */
/*
 * DES support functions.
 */

/*
 * Apply DES Initial Permutation.
 */
void br_des_do_IP(uint32_t *xl, uint32_t *xr);

/*
 * Apply DES Final Permutation (inverse of IP).
 */
void br_des_do_invIP(uint32_t *xl, uint32_t *xr);

/*
 * Key schedule unit: for a DES key (8 bytes), compute 16 subkeys. Each
 * subkey is two 28-bit words represented as two 32-bit words; the PC-2
 * bit extration is NOT applied.
 */
void br_des_keysched_unit(uint32_t *skey, const void *key);

/*
 * Reversal of 16 DES sub-keys (for decryption).
 */
void br_des_rev_skey(uint32_t *skey);

/*
 * DES/3DES key schedule for 'des_tab' (encryption direction). Returned
 * value is the number of rounds.
 */
unsigned br_des_tab_keysched(uint32_t *skey, const void *key, size_t key_len);

/*
 * DES/3DES key schedule for 'des_ct' (encryption direction). Returned
 * value is the number of rounds.
 */
unsigned br_des_ct_keysched(uint32_t *skey, const void *key, size_t key_len);

/*
 * DES/3DES subkey decompression (from the compressed bitsliced subkeys).
 */
void br_des_ct_skey_expand(uint32_t *sk_exp,
	unsigned num_rounds, const uint32_t *skey);

/*
 * DES/3DES block encryption/decryption ('des_tab').
 */
void br_des_tab_process_block(unsigned num_rounds,
	const uint32_t *skey, void *block);

/*
 * DES/3DES block encryption/decryption ('des_ct').
 */
void br_des_ct_process_block(unsigned num_rounds,
	const uint32_t *skey, void *block);

/* ==================================================================== */
/*
 * AES support functions.
 */

/*
 * The AES S-box (256-byte table).
 */
extern const unsigned char br_aes_S[];

/*
 * AES key schedule. skey[] is filled with n+1 128-bit subkeys, where n
 * is the number of rounds (10 to 14, depending on key size). The number
 * of rounds is returned. If the key size is invalid (not 16, 24 or 32),
 * then 0 is returned.
 *
 * This implementation uses a 256-byte table and is NOT constant-time.
 */
unsigned br_aes_keysched(uint32_t *skey, const void *key, size_t key_len);

/*
 * AES key schedule for decryption ('aes_big' implementation).
 */
unsigned br_aes_big_keysched_inv(uint32_t *skey,
	const void *key, size_t key_len);

/*
 * AES block encryption with the 'aes_big' implementation (fast, but
 * not constant-time). This function encrypts a single block "in place".
 */
void br_aes_big_encrypt(unsigned num_rounds, const uint32_t *skey, void *data);

/*
 * AES block decryption with the 'aes_big' implementation (fast, but
 * not constant-time). This function decrypts a single block "in place".
 */
void br_aes_big_decrypt(unsigned num_rounds, const uint32_t *skey, void *data);

/*
 * AES block encryption with the 'aes_small' implementation (small, but
 * slow and not constant-time). This function encrypts a single block
 * "in place".
 */
void br_aes_small_encrypt(unsigned num_rounds,
	const uint32_t *skey, void *data);

/*
 * AES block decryption with the 'aes_small' implementation (small, but
 * slow and not constant-time). This function decrypts a single block
 * "in place".
 */
void br_aes_small_decrypt(unsigned num_rounds,
	const uint32_t *skey, void *data);

/*
 * The constant-time implementation is "bitsliced": the 128-bit state is
 * split over eight 32-bit words q* in the following way:
 *
 * -- Input block consists in 16 bytes:
 *    a00 a10 a20 a30 a01 a11 a21 a31 a02 a12 a22 a32 a03 a13 a23 a33
 * In the terminology of FIPS 197, this is a 4x4 matrix which is read
 * column by column.
 *
 * -- Each byte is split into eight bits which are distributed over the
 * eight words, at the same rank. Thus, for a byte x at rank k, bit 0
 * (least significant) of x will be at rank k in q0 (if that bit is b,
 * then it contributes "b << k" to the value of q0), bit 1 of x will be
 * at rank k in q1, and so on.
 *
 * -- Ranks given to bits are in "row order" and are either all even, or
 * all odd. Two independent AES states are thus interleaved, one using
 * the even ranks, the other the odd ranks. Row order means:
 *    a00 a01 a02 a03 a10 a11 a12 a13 a20 a21 a22 a23 a30 a31 a32 a33
 *
 * Converting input bytes from two AES blocks to bitslice representation
 * is done in the following way:
 * -- Decode first block into the four words q0 q2 q4 q6, in that order,
 * using little-endian convention.
 * -- Decode second block into the four words q1 q3 q5 q7, in that order,
 * using little-endian convention.
 * -- Call br_aes_ct_ortho().
 *
 * Converting back to bytes is done by using the reverse operations. Note
 * that br_aes_ct_ortho() is its own inverse.
 */

/*
 * Perform bytewise orthogonalization of eight 32-bit words. Bytes
 * of q0..q7 are spread over all words: for a byte x that occurs
 * at rank i in q[j] (byte x uses bits 8*i to 8*i+7 in q[j]), the bit
 * of rank k in x (0 <= k <= 7) goes to q[k] at rank 8*i+j.
 *
 * This operation is an involution.
 */
void br_aes_ct_ortho(uint32_t *q);

/*
 * The AES S-box, as a bitsliced constant-time version. The input array
 * consists in eight 32-bit words; 32 S-box instances are computed in
 * parallel. Bits 0 to 7 of each S-box input (bit 0 is least significant)
 * are spread over the words 0 to 7, at the same rank.
 */
void br_aes_ct_bitslice_Sbox(uint32_t *q);

/*
 * Like br_aes_bitslice_Sbox(), but for the inverse S-box.
 */
void br_aes_ct_bitslice_invSbox(uint32_t *q);

/*
 * Compute AES encryption on bitsliced data. Since input is stored on
 * eight 32-bit words, two block encryptions are actually performed
 * in parallel.
 */
void br_aes_ct_bitslice_encrypt(unsigned num_rounds,
	const uint32_t *skey, uint32_t *q);

/*
 * Compute AES decryption on bitsliced data. Since input is stored on
 * eight 32-bit words, two block decryptions are actually performed
 * in parallel.
 */
void br_aes_ct_bitslice_decrypt(unsigned num_rounds,
	const uint32_t *skey, uint32_t *q);

/*
 * AES key schedule, constant-time version. skey[] is filled with n+1
 * 128-bit subkeys, where n is the number of rounds (10 to 14, depending
 * on key size). The number of rounds is returned. If the key size is
 * invalid (not 16, 24 or 32), then 0 is returned.
 */
unsigned br_aes_ct_keysched(uint32_t *comp_skey,
	const void *key, size_t key_len);

/*
 * Expand AES subkeys as produced by br_aes_ct_keysched(), into
 * a larger array suitable for br_aes_ct_bitslice_encrypt() and
 * br_aes_ct_bitslice_decrypt().
 */
void br_aes_ct_skey_expand(uint32_t *skey,
	unsigned num_rounds, const uint32_t *comp_skey);

/*
 * For the ct64 implementation, the same bitslicing technique is used,
 * but four instances are interleaved. First instance uses bits 0, 4,
 * 8, 12,... of each word; second instance uses bits 1, 5, 9, 13,...
 * and so on.
 */

/*
 * Perform bytewise orthogonalization of eight 64-bit words. Bytes
 * of q0..q7 are spread over all words: for a byte x that occurs
 * at rank i in q[j] (byte x uses bits 8*i to 8*i+7 in q[j]), the bit
 * of rank k in x (0 <= k <= 7) goes to q[k] at rank 8*i+j.
 *
 * This operation is an involution.
 */
void br_aes_ct64_ortho(uint64_t *q);

/*
 * Interleave bytes for an AES input block. If input bytes are
 * denoted 0123456789ABCDEF, and have been decoded with little-endian
 * convention (w[0] contains 0123, with '3' being most significant;
 * w[1] contains 4567, and so on), then output word q0 will be
 * set to 08192A3B (again little-endian convention) and q1 will
 * be set to 4C5D6E7F.
 */
void br_aes_ct64_interleave_in(uint64_t *q0, uint64_t *q1, const uint32_t *w);

/*
 * Perform the opposite of br_aes_ct64_interleave_in().
 */
void br_aes_ct64_interleave_out(uint32_t *w, uint64_t q0, uint64_t q1);

/*
 * The AES S-box, as a bitsliced constant-time version. The input array
 * consists in eight 64-bit words; 64 S-box instances are computed in
 * parallel. Bits 0 to 7 of each S-box input (bit 0 is least significant)
 * are spread over the words 0 to 7, at the same rank.
 */
void br_aes_ct64_bitslice_Sbox(uint64_t *q);

/*
 * Like br_aes_bitslice_Sbox(), but for the inverse S-box.
 */
void br_aes_ct64_bitslice_invSbox(uint64_t *q);

/*
 * Compute AES encryption on bitsliced data. Since input is stored on
 * eight 64-bit words, four block encryptions are actually performed
 * in parallel.
 */
void br_aes_ct64_bitslice_encrypt(unsigned num_rounds,
	const uint64_t *skey, uint64_t *q);

/*
 * Compute AES decryption on bitsliced data. Since input is stored on
 * eight 64-bit words, four block decryptions are actually performed
 * in parallel.
 */
void br_aes_ct64_bitslice_decrypt(unsigned num_rounds,
	const uint64_t *skey, uint64_t *q);

/*
 * AES key schedule, constant-time version. skey[] is filled with n+1
 * 128-bit subkeys, where n is the number of rounds (10 to 14, depending
 * on key size). The number of rounds is returned. If the key size is
 * invalid (not 16, 24 or 32), then 0 is returned.
 */
unsigned br_aes_ct64_keysched(uint64_t *comp_skey,
	const void *key, size_t key_len);

/*
 * Expand AES subkeys as produced by br_aes_ct64_keysched(), into
 * a larger array suitable for br_aes_ct64_bitslice_encrypt() and
 * br_aes_ct64_bitslice_decrypt().
 */
void br_aes_ct64_skey_expand(uint64_t *skey,
	unsigned num_rounds, const uint64_t *comp_skey);

/* ==================================================================== */
/*
 * RSA.
 */

/*
 * Apply proper PKCS#1 v1.5 padding (for signatures). 'hash_oid' is
 * the encoded hash function OID, or NULL.
 */
uint32_t br_rsa_pkcs1_sig_pad(const unsigned char *hash_oid,
	const unsigned char *hash, size_t hash_len,
	uint32_t n_bitlen, unsigned char *x);

/*
 * Check PKCS#1 v1.5 padding (for signatures). 'hash_oid' is the encoded
 * hash function OID, or NULL. The provided 'sig' value is _after_ the
 * modular exponentiation, i.e. it should be the padded hash. On
 * success, the hashed message is extracted.
 */
uint32_t br_rsa_pkcs1_sig_unpad(const unsigned char *sig, size_t sig_len,
	const unsigned char *hash_oid, size_t hash_len,
	unsigned char *hash_out);

/* ==================================================================== */
/*
 * Elliptic curves.
 */

/*
 * Type for generic EC parameters: curve order (unsigned big-endian
 * encoding) and encoded conventional generator.
 */
typedef struct {
	int curve;
	const unsigned char *order;
	size_t order_len;
	const unsigned char *generator;
	size_t generator_len;
} br_ec_curve_def;

extern const br_ec_curve_def br_secp256r1;
extern const br_ec_curve_def br_secp384r1;
extern const br_ec_curve_def br_secp521r1;

#if 1
/* obsolete */
/*
 * Type for the parameters for a "prime curve":
 *   coordinates are in GF(p), with p prime
 *   curve equation is Y^2 = X^3 - 3*X + b
 *   b is in Montgomery representation
 *   curve order is n and is prime
 *   base point is G (encoded) and has order n
 */
typedef struct {
	const uint32_t *p;
	const uint32_t *b;
	const uint32_t p0i;
} br_ec_prime_i31_curve;

extern const br_ec_prime_i31_curve br_ec_prime_i31_secp256r1;
extern const br_ec_prime_i31_curve br_ec_prime_i31_secp384r1;
extern const br_ec_prime_i31_curve br_ec_prime_i31_secp521r1;

#define BR_EC_I31_LEN   ((BR_MAX_EC_SIZE + 61) / 31)
#endif

/*
 * Decode some bytes as an i31 integer, with truncation (corresponding
 * to the 'bits2int' operation in RFC 6979). The target ENCODED bit
 * length is provided as last parameter. The resulting value will have
 * this declared bit length, and consists the big-endian unsigned decoding
 * of exactly that many bits in the source (capped at the source length).
 */
void br_ecdsa_i31_bits2int(uint32_t *x,
	const void *src, size_t len, uint32_t ebitlen);

/*
 * Decode some bytes as an i15 integer, with truncation (corresponding
 * to the 'bits2int' operation in RFC 6979). The target ENCODED bit
 * length is provided as last parameter. The resulting value will have
 * this declared bit length, and consists the big-endian unsigned decoding
 * of exactly that many bits in the source (capped at the source length).
 */
void br_ecdsa_i15_bits2int(uint16_t *x,
	const void *src, size_t len, uint32_t ebitlen);

/* ==================================================================== */
/*
 * SSL/TLS support functions.
 */

/*
 * Record types.
 */
#define BR_SSL_CHANGE_CIPHER_SPEC    20
#define BR_SSL_ALERT                 21
#define BR_SSL_HANDSHAKE             22
#define BR_SSL_APPLICATION_DATA      23

/*
 * Handshake message types.
 */
#define BR_SSL_HELLO_REQUEST          0
#define BR_SSL_CLIENT_HELLO           1
#define BR_SSL_SERVER_HELLO           2
#define BR_SSL_CERTIFICATE           11
#define BR_SSL_SERVER_KEY_EXCHANGE   12
#define BR_SSL_CERTIFICATE_REQUEST   13
#define BR_SSL_SERVER_HELLO_DONE     14
#define BR_SSL_CERTIFICATE_VERIFY    15
#define BR_SSL_CLIENT_KEY_EXCHANGE   16
#define BR_SSL_FINISHED              20

/*
 * Alert levels.
 */
#define BR_LEVEL_WARNING   1
#define BR_LEVEL_FATAL     2

/*
 * Low-level I/O state.
 */
#define BR_IO_FAILED   0
#define BR_IO_IN       1
#define BR_IO_OUT      2
#define BR_IO_INOUT    3

/*
 * Mark a SSL engine as failed. The provided error code is recorded if
 * the engine was not already marked as failed. If 'err' is 0, then the
 * engine is marked as closed (without error).
 */
void br_ssl_engine_fail(br_ssl_engine_context *cc, int err);

/*
 * Test whether the engine is closed (normally or as a failure).
 */
static inline int
br_ssl_engine_closed(const br_ssl_engine_context *cc)
{
	return cc->iomode == BR_IO_FAILED;
}

/*
 * Configure a new maximum fragment length. If possible, the maximum
 * length for outgoing records is immediately adjusted (if there are
 * not already too many buffered bytes for that).
 */
void br_ssl_engine_new_max_frag_len(
	br_ssl_engine_context *rc, unsigned max_frag_len);

/*
 * Test whether the current incoming record has been fully received
 * or not. This functions returns 0 only if a complete record header
 * has been received, but some of the (possibly encrypted) payload
 * has not yet been obtained.
 */
int br_ssl_engine_recvrec_finished(const br_ssl_engine_context *rc);

/*
 * Flush the current record (if not empty). This is meant to be called
 * from the handshake processor only.
 */
void br_ssl_engine_flush_record(br_ssl_engine_context *cc);

/*
 * Test whether there is some accumulated payload to send.
 */
static inline int
br_ssl_engine_has_pld_to_send(const br_ssl_engine_context *rc)
{
	return rc->oxa != rc->oxb && rc->oxa != rc->oxc;
}

/*
 * Initialize RNG in engine. Returned value is 1 on success, 0 on error.
 * This function will try to use the OS-provided RNG, if available. If
 * there is no OS-provided RNG, or if it failed, and no entropy was
 * injected by the caller, then a failure will be reported. On error,
 * the context error code is set.
 */
int br_ssl_engine_init_rand(br_ssl_engine_context *cc);

/*
 * Reset the handshake-related parts of the engine.
 */
void br_ssl_engine_hs_reset(br_ssl_engine_context *cc,
	void (*hsinit)(void *), void (*hsrun)(void *));

/*
 * Get the PRF to use for this context, for the provided PRF hash
 * function ID.
 */
br_tls_prf_impl br_ssl_engine_get_PRF(br_ssl_engine_context *cc, int prf_id);

/*
 * Consume the provided pre-master secret and compute the corresponding
 * master secret. The 'prf_id' is the ID of the hash function to use
 * with the TLS 1.2 PRF (ignored if the version is TLS 1.0 or 1.1).
 */
void br_ssl_engine_compute_master(br_ssl_engine_context *cc,
	int prf_id, const void *pms, size_t len);

/*
 * Switch to CBC decryption for incoming records.
 *    cc               the engine context
 *    is_client        non-zero for a client, zero for a server
 *    prf_id           id of hash function for PRF (ignored if not TLS 1.2+)
 *    mac_id           id of hash function for HMAC
 *    bc_impl          block cipher implementation (CBC decryption)
 *    cipher_key_len   block cipher key length (in bytes)
 */
void br_ssl_engine_switch_cbc_in(br_ssl_engine_context *cc,
	int is_client, int prf_id, int mac_id,
	const br_block_cbcdec_class *bc_impl, size_t cipher_key_len);

/*
 * Switch to CBC encryption for outgoing records.
 *    cc               the engine context
 *    is_client        non-zero for a client, zero for a server
 *    prf_id           id of hash function for PRF (ignored if not TLS 1.2+)
 *    mac_id           id of hash function for HMAC
 *    bc_impl          block cipher implementation (CBC encryption)
 *    cipher_key_len   block cipher key length (in bytes)
 */
void br_ssl_engine_switch_cbc_out(br_ssl_engine_context *cc,
	int is_client, int prf_id, int mac_id,
	const br_block_cbcenc_class *bc_impl, size_t cipher_key_len);

/*
 * Switch to GCM decryption for incoming records.
 *    cc               the engine context
 *    is_client        non-zero for a client, zero for a server
 *    prf_id           id of hash function for PRF
 *    bc_impl          block cipher implementation (CTR)
 *    cipher_key_len   block cipher key length (in bytes)
 */
void br_ssl_engine_switch_gcm_in(br_ssl_engine_context *cc,
	int is_client, int prf_id,
	const br_block_ctr_class *bc_impl, size_t cipher_key_len);

/*
 * Switch to GCM encryption for outgoing records.
 *    cc               the engine context
 *    is_client        non-zero for a client, zero for a server
 *    prf_id           id of hash function for PRF
 *    bc_impl          block cipher implementation (CTR)
 *    cipher_key_len   block cipher key length (in bytes)
 */
void br_ssl_engine_switch_gcm_out(br_ssl_engine_context *cc,
	int is_client, int prf_id,
	const br_block_ctr_class *bc_impl, size_t cipher_key_len);

/*
 * Switch to ChaCha20+Poly1305 decryption for incoming records.
 *    cc               the engine context
 *    is_client        non-zero for a client, zero for a server
 *    prf_id           id of hash function for PRF
 */
void br_ssl_engine_switch_chapol_in(br_ssl_engine_context *cc,
	int is_client, int prf_id);

/*
 * Switch to ChaCha20+Poly1305 encryption for outgoing records.
 *    cc               the engine context
 *    is_client        non-zero for a client, zero for a server
 *    prf_id           id of hash function for PRF
 */
void br_ssl_engine_switch_chapol_out(br_ssl_engine_context *cc,
	int is_client, int prf_id);

/*
 * Calls to T0-generated code.
 */
void br_ssl_hs_client_init_main(void *ctx);
void br_ssl_hs_client_run(void *ctx);
void br_ssl_hs_server_init_main(void *ctx);
void br_ssl_hs_server_run(void *ctx);

/*
 * Get the hash function to use for signatures, given a bit mask of
 * supported hash functions. This implements a strict choice order
 * (namely SHA-256, SHA-384, SHA-512, SHA-224, SHA-1). If the mask
 * does not document support of any of these hash functions, then this
 * functions returns 0.
 */
int br_ssl_choose_hash(unsigned bf);

/* ==================================================================== */

#endif
