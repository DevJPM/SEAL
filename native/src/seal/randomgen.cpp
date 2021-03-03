// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/randomgen.h"
#include "seal/util/blake2.h"
#include "seal/util/fips202.h"
#include <algorithm>
#include <iostream>
#include <random>
#include <immintrin.h>
#if (SEAL_SYSTEM == SEAL_SYSTEM_WINDOWS)
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt")
#endif

using namespace std;
using namespace seal::util;

#if (SEAL_SYSTEM == SEAL_SYSTEM_WINDOWS)

constexpr auto RTL_GENRANDOM = "SystemFunction036";

// Preserve error codes to diagnose in case of failure
NTSTATUS last_bcrypt_error = 0;
DWORD last_genrandom_error = 0;

#endif

namespace seal
{
    uint64_t random_uint64()
    {
        uint64_t result;
#if SEAL_SYSTEM == SEAL_SYSTEM_UNIX_LIKE
        random_device rd("/dev/urandom");
        result = (static_cast<uint64_t>(rd()) << 32) + static_cast<uint64_t>(rd());
#elif SEAL_SYSTEM == SEAL_SYSTEM_WINDOWS
        NTSTATUS status = BCryptGenRandom(
            NULL, reinterpret_cast<unsigned char *>(&result), sizeof(result), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        if (BCRYPT_SUCCESS(status))
        {
            return result;
        }

        last_bcrypt_error = status;

        HMODULE hAdvApi = LoadLibraryA("ADVAPI32.DLL");
        if (!hAdvApi)
        {
            last_genrandom_error = GetLastError();
            throw runtime_error("Failed to load ADVAPI32.dll");
        }

        BOOLEAN(APIENTRY * RtlGenRandom)
        (void *, ULONG) = (BOOLEAN(APIENTRY *)(void *, ULONG))GetProcAddress(hAdvApi, RTL_GENRANDOM);

        BOOLEAN genrand_result = FALSE;
        if (RtlGenRandom)
        {
            genrand_result = RtlGenRandom(&result, bytes_per_uint64);
        }

        DWORD dwError = GetLastError();
        FreeLibrary(hAdvApi);

        if (!genrand_result)
        {
            last_genrandom_error = dwError;
            throw runtime_error("Failed to call RtlGenRandom");
        }
#elif SEAL_SYSTEM == SEAL_SYSTEM_OTHER
#warning "SECURITY WARNING: System detection failed; falling back to a potentially insecure randomness source!"
        random_device rd;
        result = (static_cast<uint64_t>(rd()) << 32) + static_cast<uint64_t>(rd());
#endif
        return result;
    }

    void UniformRandomGeneratorInfo::save_members(ostream &stream) const
    {
        // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
        auto old_except_mask = stream.exceptions();
        try
        {
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            stream.write(reinterpret_cast<const char *>(&type_), sizeof(prng_type));
            stream.write(reinterpret_cast<const char *>(seed_.data()), prng_seed_byte_count);
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            throw runtime_error("I/O error");
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);
    }

    void UniformRandomGeneratorInfo::load_members(istream &stream, SEAL_MAYBE_UNUSED SEALVersion version)
    {
        // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
        auto old_except_mask = stream.exceptions();
        try
        {
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            UniformRandomGeneratorInfo info;

            // Read the PRNG type
            stream.read(reinterpret_cast<char *>(&info.type_), sizeof(prng_type));
            if (!info.has_valid_prng_type())
            {
                throw logic_error("prng_type is invalid");
            }

            // Read the seed data
            stream.read(reinterpret_cast<char *>(info.seed_.data()), prng_seed_byte_count);

            swap(*this, info);

            stream.exceptions(old_except_mask);
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            throw runtime_error("I/O error");
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);
    }

    shared_ptr<UniformRandomGenerator> UniformRandomGeneratorInfo::make_prng() const
    {
        switch (type_)
        {
        case prng_type::blake2xb:
            return make_shared<Blake2xbPRNG>(seed_);

        case prng_type::shake256:
            return make_shared<Shake256PRNG>(seed_);

          case prng_type::aesni:
            return make_shared<AESNIPRNG>(seed_);

            case prng_type::vaes:
                return make_shared<VAESPRNG>(seed_);

        case prng_type::unknown:
            return nullptr;
        }
        return nullptr;
    }

    void UniformRandomGenerator::generate(size_t byte_count, seal_byte *destination)
    {
        lock_guard<mutex> lock(mutex_);
        while (byte_count)
        {
            size_t current_bytes = min(byte_count, static_cast<size_t>(distance(buffer_head_, buffer_end_)));
            copy_n(buffer_head_, current_bytes, destination);
            buffer_head_ += current_bytes;
            destination += current_bytes;
            byte_count -= current_bytes;

            if (buffer_head_ == buffer_end_)
            {
                refill_buffer();
                buffer_head_ = buffer_begin_;
            }
        }
    }

    auto UniformRandomGeneratorFactory::DefaultFactory() -> shared_ptr<UniformRandomGeneratorFactory>
    {
        //static shared_ptr<UniformRandomGeneratorFactory> default_factory{ new SEAL_DEFAULT_PRNG_FACTORY() };
        static shared_ptr<UniformRandomGeneratorFactory> default_factory{ new VAESPRNGFactory() };
        return default_factory;
    }

    void Blake2xbPRNG::refill_buffer()
    {
        // Fill the randomness buffer
        if (blake2xb(
                buffer_begin_, buffer_size_, &counter_, sizeof(counter_), seed_.cbegin(),
                seed_.size() * sizeof(decltype(seed_)::type)) != 0)
        {
            throw runtime_error("blake2xb failed");
        }
        counter_++;
    }

    void Shake256PRNG::refill_buffer()
    {
        // Fill the randomness buffer
        array<uint64_t, prng_seed_uint64_count + 1> seed_ext;
        copy_n(seed_.cbegin(), prng_seed_uint64_count, seed_ext.begin());
        seed_ext[prng_seed_uint64_count] = counter_;
        shake256(
            reinterpret_cast<uint8_t *>(buffer_begin_), buffer_size_,
            reinterpret_cast<const uint8_t *>(seed_ext.data()), seed_ext.size() * bytes_per_uint64);
        seal_memzero(seed_ext.data(), seed_ext.size() * bytes_per_uint64);
        counter_++;
    }

    __attribute__((target("sse4.1,aes")))
    static void expandAESKey(__m128i userkey, uint8_t *alignedStoragePointer)
    {
        // this uses the fast AES key expansion (i.e. not using keygenassist) from
        // https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
        // page 37

        __m128i temp1, temp2, temp3, globAux;
        const __m128i shuffle_mask = _mm_set_epi32(0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d);
        const __m128i con3 = _mm_set_epi32(0x07060504, 0x07060504, 0x0ffffffff, 0x0ffffffff);
        __m128i rcon;
        temp1 = userkey;
        rcon = _mm_set_epi32(1, 1, 1, 1);
        _mm_storeu_si128((__m128i *)(alignedStoragePointer + 0 * 16), temp1);
        for (int i = 1; i <= 8; i++)
        {
            temp2 = _mm_shuffle_epi8(temp1, shuffle_mask);
            temp2 = _mm_aesenclast_si128(temp2, rcon);
            rcon = _mm_slli_epi32(rcon, 1);
            globAux = _mm_slli_epi64(temp1, 32);
            temp1 = _mm_xor_si128(globAux, temp1);
            globAux = _mm_shuffle_epi8(temp1, con3);
            temp1 = _mm_xor_si128(globAux, temp1);
            temp1 = _mm_xor_si128(temp2, temp1);
            _mm_storeu_si128((__m128i *)(alignedStoragePointer + i * 16), temp1);
        }
        rcon = _mm_set_epi32(0x1b, 0x1b, 0x1b, 0x1b);
        temp2 = _mm_shuffle_epi8(temp1, shuffle_mask);
        temp2 = _mm_aesenclast_si128(temp2, rcon);
        rcon = _mm_slli_epi32(rcon, 1);
        globAux = _mm_slli_epi64(temp1, 32);
        temp1 = _mm_xor_si128(globAux, temp1);
        globAux = _mm_shuffle_epi8(temp1, con3);
        temp1 = _mm_xor_si128(globAux, temp1);
        temp1 = _mm_xor_si128(temp2, temp1);
        _mm_storeu_si128((__m128i *)(alignedStoragePointer + 9 * 16), temp1);
        temp2 = _mm_shuffle_epi8(temp1, shuffle_mask);
        temp2 = _mm_aesenclast_si128(temp2, rcon);
        globAux = _mm_slli_epi64(temp1, 32);
        temp1 = _mm_xor_si128(globAux, temp1);
        globAux = _mm_shuffle_epi8(temp1, con3);
        temp1 = _mm_xor_si128(globAux, temp1);
        temp1 = _mm_xor_si128(temp2, temp1);
        _mm_storeu_si128((__m128i *)(alignedStoragePointer + 10 * 16), temp1);
    }

    AESNIPRNG::AESNIPRNG(prng_seed_type seed) : UniformRandomGenerator(seed)
    {
        __m128i key = _mm_loadu_si128(reinterpret_cast<const __m128i*>(seed_.cbegin()));
        expandAESKey(key, reinterpret_cast<uint8_t *>(expanded_key.begin()));
    }

    __attribute__((target("sse4.1,aes")))
    void AESNIPRNG::refill_buffer()
    {
        __m128i counter = _mm_set_epi64x(counter_, 0);
        __m128i offset = _mm_set_epi64x(0, 1);

        constexpr size_t width = 8;
        const size_t num_blocks = buffer_size_ / (16);

        __m128i round_keys[11];
        for (size_t i = 0; i < 11; ++i)
            round_keys[i] = _mm_loadu_si128(reinterpret_cast<const __m128i *>(expanded_key.cbegin()) + i);

        __m128i data[width];

        for (size_t progress = 0; progress < num_blocks; progress += width)
        {
            for (size_t w = 0; w < width; ++w)
            {
                data[w] = counter;
                counter = _mm_add_epi64(counter, offset);
                data[w] = _mm_xor_si128(data[w], round_keys[0]);
            }

            for (size_t r = 1; r < 10; ++r)
            {
                for (size_t w = 0; w < width; ++w)
                {
                    data[w] = _mm_aesenc_si128(data[w], round_keys[r]);
                }
            }

            for (size_t w = 0; w < width; ++w)
            {
                data[w] = _mm_aesenclast_si128(data[w], round_keys[10]);
                _mm_storeu_si128(reinterpret_cast<__m128i *>(buffer_begin_) + w + progress, data[w]);
            }
        }    
        counter_++;
    }

    VAESPRNG::VAESPRNG(prng_seed_type seed) : UniformRandomGenerator(seed)
    {
        __m128i key = _mm_loadu_si128(reinterpret_cast<const __m128i *>(seed_.cbegin()));
        expandAESKey(key, reinterpret_cast<uint8_t *>(expanded_key.begin()));
    }

    __attribute__((target("avx512f,avx512vl,vaes"))) void VAESPRNG::refill_buffer()
    {
        __m256i counter = _mm256_set_epi64x(counter_, 1,counter_,0);
        __m256i offset = _mm256_set_epi64x(0, 2,0,2);

        constexpr size_t width = 8;
        const size_t num_blocks = buffer_size_ / (16);

        __m256i round_keys[11];
        for (size_t i = 0; i < 11; ++i)
            round_keys[i] = _mm256_broadcastsi128_si256(_mm_loadu_si128(reinterpret_cast<const __m128i *>(expanded_key.cbegin()) + i));

        __m256i data[width];

        for (size_t progress = 0; progress < num_blocks; progress += 2*width)
        {
            for (size_t w = 0; w < width; ++w)
            {
                data[w] = counter;
                counter = _mm256_add_epi64(counter, offset);
                data[w] = _mm256_xor_si256(data[w], round_keys[0]);
            }

            for (size_t r = 1; r < 10; ++r)
            {
                for (size_t w = 0; w < width; ++w)
                {
                    data[w] = _mm256_aesenc_epi128(data[w], round_keys[r]);
                }
            }

            for (size_t w = 0; w < width; ++w)
            {
                data[w] = _mm256_aesenclast_epi128(data[w], round_keys[10]);
                _mm256_storeu_si256(reinterpret_cast<__m256i *>(buffer_begin_) + w + progress/2, data[w]);
            }
        }
        counter_++;
    }
} // namespace seal
