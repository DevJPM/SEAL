// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_ckks_basics()
{
    print_example_banner("Example: CKKS Basics");

    /*
    In this example we demonstrate evaluating a polynomial function

        PI*x^3 + 0.4*x + 1

    on encrypted floating-point input data x for a set of 4096 equidistant points
    in the interval [0, 1]. This example demonstrates many of the main features
    of the CKKS scheme, but also the challenges in using it.

    We start by setting up the CKKS scheme.
    */
    EncryptionParameters parms(scheme_type::CKKS);

    /*
    We saw in `2_encoders.cpp' that multiplication in CKKS causes scales
    in ciphertexts to grow. The scale of any ciphertext must not get too close
    to the total size of coeff_modulus, or else the ciphertext simply runs out of
    room to store the scaled-up plaintext. The CKKS scheme provides a `rescale'
    functionality that can reduce the scale, and stablize the scale expansion.

    Rescaling is a kind of modulus switch operation (recall `3_levels.cpp').
    As modulus switching, it removes the last of the primes from coeff_modulus,
    but as a side-effect it scales down the ciphertext by the removed prime.
    Usually we want to have perfect control over how the scales are changed,
    which is why for the CKKS scheme it is more common to use carefully selected
    primes for the coeff_modulus.

    More precisely, suppose that the scale in a CKKS ciphertext is S, and the
    last prime in the current coeff_modulus (for the ciphertext) is P. Rescaling
    to the next level changes the scale to S/P, and removes the prime P from the
    coeff_modulus, as usual in modulus switching. The number of primes limits
    how many rescalings can be done, and thus limits the multiplicative depth of
    the computation.

    It is possible to choose the initial scale freely. One good strategy can be
    to is to set the initial scale S and primes P_i in the coeff_modulus to be
    very close to each other. If ciphertexts have scale S before multiplication,
    they have scale S^2 after multiplication, and S^2/P_i after rescaling. If all
    P_i are close to S, then S^2/P_i is close to S again. This way we stablize the
    scales to be close to S throughout the computation. Generally, for a circuit
    of depth D, we need to rescale D times, i.e., we need to be able to remove D
    primes from the coefficient modulus. Once we have only one prime left in the
    coeff_modulus, the remaining prime must be larger than S by a few bits to
    preserve the pre-decimal-point value of the plaintext.

    Therefore, a generally good strategy is to choose parameters for the CKKS
    scheme as follows:

        (1) Choose a 60-bit prime as the first prime in coeff_modulus. This will
            give the highest precision when decrypting;
        (2) Choose another 60-bit prime as the last element of coeff_modulus, as
            this will be used as the special prime and should be as large as the
            largest of the other primes;
        (3) Choose the intermediate primes to be close to each other.

    We use CoeffModulus::Custom to generate primes of the appropriate size. Note
    that our coeff_modulus is 200 bits total, which is below the bound for our
    poly_modulus_degree: CoeffModulus::MaxBitCount(8192) returns 218.
    */
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Custom(
        poly_modulus_degree, { 60, 40, 40, 60 }));

    /*
    We choose the initial scale to be 2^40. At the last level, this leaves us
    60-40=20 bits of precision before the decimal point, and enough (roughly
    10-20 bits) of precision after the decimal point. Since our intermediate
    primes are 40 bits (in fact, they are very close to 2^40), we can achieve
    scale stabilization as described above.
    */
    double scale = pow(2, 40);

    auto context = SEALContext::Create(parms);
    print_parameters(context);

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    cout << "Evaluating polynomial PI*x^3 + 0.4x + 1 ..." << endl;

    /*
    We create plaintexts for PI, 0.4, and 1 using an overload of CKKSEncoder::encode
    that encodes the given floating-point value to every slot in the vector.
    */
    Plaintext plain_coeff3;
    encoder.encode(3.14159265, scale, plain_coeff3);
    Plaintext plain_coeff1;
    encoder.encode(0.4, scale, plain_coeff1);
    Plaintext plain_coeff0;
    encoder.encode(1.0, scale, plain_coeff0);

    Plaintext plain_x;
    cout << "-- Encoding input vector: ";
    encoder.encode(input, scale, plain_x);
    cout << "Done (plain x)" << endl;
    Ciphertext encrypted_x1;
    cout << "-- Encrypting input vector: ";
    encryptor.encrypt(plain_x, encrypted_x1);
    cout << "Done (encrypted x)" << endl;

    /*
    To compute x^3 we first compute x^2 and relinearize. However, the scale has
    now grown to 2^80.
    */
    Ciphertext encrypted_x3;
    cout << "-- Computing x^2 and relinearizing: ";
    evaluator.square(encrypted_x1, encrypted_x3);
    evaluator.relinearize_inplace(encrypted_x3, relin_keys);
    cout << "Done (x^2)" << endl;
    cout << "\tScale of x^2 before rescale: " << log2(encrypted_x3.scale())
        << " bits" << endl;

    /*
    Now rescale; in addition to a modulus switch, the scale is reduced down by
    a factor equal to the prime that was switched away (40-bit prime). Hence, the
    new scale should be close to 2^40. Note, however, that the scale is not equal
    to 2^40: this is because the 40-bit prime is only close to 2^40.
    */
    evaluator.rescale_to_next_inplace(encrypted_x3);
    cout << "\tScale of x^2 after rescale: " << log2(encrypted_x3.scale())
        << " bits" << endl;

    /*
    Now encrypted_x3 is at a different level than encrypted_x1, which prevents us
    from multiplying them to compute x^3. We could simply switch encrypted_x1 to
    the next parameters in the modulus switching chain. However, since we still
    need to multiply the x^3 term with PI (plain_coeff3), we instead compute PI*x
    first and multiply that with x^2 to obtain PI*x^3. To this end, we compute
    PI*x and rescale it back from scale 2^80 to something close to 2^40.
    */
    cout << "-- Computing PI*x: ";
    Ciphertext encrypted_x1_coeff3;
    evaluator.multiply_plain(encrypted_x1, plain_coeff3, encrypted_x1_coeff3);
    cout << "Done (PI*x)" << endl;
    cout << "\tScale of PI*x before rescale: " << log2(encrypted_x1_coeff3.scale())
        << " bits" << endl;
    evaluator.rescale_to_next_inplace(encrypted_x1_coeff3);
    cout << "\tScale of PI*x after rescale: " << log2(encrypted_x1_coeff3.scale())
        << " bits" << endl;

    /*
    Since encrypted_x3 and encrypted_x1_coeff3 have the same exact scale and use
    the same encryption parameters, we can multiply them together. We write the
    result to encrypted_x3, relinearize, and rescale. Note that again the scale
    is something close to 2^40, but not exactly 2^40 due to yet another scaling
    by a prime. We are down to the last level in the modulus switching chain.
    */
    cout << "-- Computing (PI*x)*x^2: ";
    evaluator.multiply_inplace(encrypted_x3, encrypted_x1_coeff3);
    evaluator.relinearize_inplace(encrypted_x3, relin_keys);
    cout << "Done (PI*x^3)" << endl;
    cout << "\tScale of PI*x^3 before rescale: " << log2(encrypted_x3.scale())
        << " bits" << endl;
    evaluator.rescale_to_next_inplace(encrypted_x3);
    cout << "\tScale of PI*x^3 after rescale: " << log2(encrypted_x3.scale())
        << " bits" << endl;

    /*
    Next we compute the degree one term. All this requires is one multiply_plain
    with plain_coeff1. We overwrite encrypted_x1 with the result.
    */
    cout << "-- Computing 0.4*x: ";
    evaluator.multiply_plain_inplace(encrypted_x1, plain_coeff1);
    cout << "Done (0.4*x)" << endl;
    cout << "\tScale of 0.4*x before rescale: " << log2(encrypted_x1.scale())
        << " bits" << endl;
    evaluator.rescale_to_next_inplace(encrypted_x1);
    cout << "\tScale of 0.4*x after rescale: " << log2(encrypted_x1.scale())
        << " bits" << endl;

    /*
    Now we would hope to compute the sum of all three terms. However, there is
    a serious problem: the encryption parameters used by all three terms are
    different due to modulus switching from rescaling.

    Encrypted addition and subtraction require that the scales of the inputs are
    the same, and also that the encryption parameters (parms_id) match. If there
    is a mismatch, Evaluator will throw an exception.
    */
    cout << endl << "Parameters used by all three terms are different:" << endl;
    cout << "\tModulus chain index for encrypted_x3: "
        << context->get_context_data(encrypted_x3.parms_id())->chain_index() << endl;
    cout << "\tModulus chain index for encrypted_x1: "
        << context->get_context_data(encrypted_x1.parms_id())->chain_index() << endl;
    cout << "\tModulus chain index for plain_coeff0: "
        << context->get_context_data(plain_coeff0.parms_id())->chain_index() << endl;
    cout << endl;

    /*
    Let us carefully consider what the scales are at this point. We denote the
    primes in coeff_modulus as P_0, P_1, P_2, P_3, in this order. P_3 is used as
    the special modulus and is not involved in rescalings. After the computations
    above the scales in ciphertexts are:

        - Product x^2 has scale 2^80 and is at level 2;
        - Product PI*x has scale 2^80/P_2 and is at level 2;
        - We rescaled both down to scale 2^80/P2 and level 1;
        - Product PI*x^3 has scale (2^80/P_2)^2;
        - We rescaled it down to scale (2^80/P_2)^2/P_1 and level 0;
        - Product 0.4*x has scale 2^80;
        - We rescaled it down to scale 2^80/P_2 and level 1;
        - The contant term 1 has scale 2^40 and is at level 2.

    Although the scales of all three terms are approximately 2^40, their exact
    values are different, hence they cannot be added together.
    */
    cout << endl << "The exact scales of all three terms are different:" << endl;
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "\tExact scale in PI*x^3: " << encrypted_x3.scale() << endl;
    cout << "\tExact scale in  0.4*x: " << encrypted_x1.scale() << endl;
    cout << "\tExact scale in      1: " << plain_coeff0.scale() << endl;
    cout << endl;
    cout.copyfmt(old_fmt);

    /*
    There are many ways to fix this problem. Since P_2 and P_1 are really close
    to 2^40, we can simply "lie" to Microsoft SEAL and set the scales to be the
    same. For example, changing the scale of PI*x^3 to 2^40 simply means that we
    scale the value of PI*x^3 by 2^120/(P_2^2*P_1), which is very close to 1.
    This should not result in any noticeable error.

    Another option would be to encode 1 with scale 2^80/P_2, do a multiply_plain
    with 0.4*x, and finally rescale. In this case we would need to additionally
    make sure to encode 1 with appropriate encryption parameters (parms_id).

    In this example we will use the first (simplest) approach and simply change
    the scale of PI*x^3 and 0.4*x to 2^40.
    */
    cout << "-- Normalizing scales: ";
    encrypted_x3.scale() = pow(2.0, 40);
    encrypted_x1.scale() = pow(2.0, 40);
    cout << "Done (2^40)" << endl;

    /*
    We still have a problem with mismatching encryption parameters. This is easy
    to fix by using traditional modulus switching (no rescaling). CKKS supports
    modulus switching just like the BFV scheme, allowing us to switch away parts
    of the coefficient modulus when it is simply not needed.
    */
    cout << "-- Normalizing encryption parameters: ";
    parms_id_type last_parms_id = encrypted_x3.parms_id();
    evaluator.mod_switch_to_inplace(encrypted_x1, last_parms_id);
    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id);
    cout << "Done" << endl;

    /*
    All three ciphertexts are now compatible and can be added.
    */
    cout << "-- Computing PI*x^3 + 0.4*x + 1: ";
    Ciphertext encrypted_result;
    evaluator.add(encrypted_x3, encrypted_x1, encrypted_result);
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0);
    cout << "Done (PI*x^3 + 0.4*x + 1)" << endl;

    /*
    We decrypt, decode, and print the result.
    */
    Plaintext plain_result;
    cout << "-- Decrypting and decoding: ";
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "Done" << endl;

    cout << endl;
    cout << "Computed result of PI*x^3 + 0.4x + 1:" << endl;
    print_vector(result, 3, 7);

    cout << "Expected result of PI*x^3 + 0.4x + 1:" << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        true_result.push_back((3.14159265 * x * x + 0.4)* x + 1);
    }
    print_vector(true_result, 3, 7);

    /*
    While we did not show any computations on complex numbers in these examples,
    the CKKSEncoder would allow us to have done that just as easily. Additions
    and multiplications of complex numbers behave just as one would expect.
    */
}