//
// Created by Anat Samohi on 14/10/2020.
//

#include <exception>
#include "../../examples.h"
#include "serv_func.h"

using namespace std;
using namespace seal;

void Logrank_protocol_sim();

//void Logrank_protocol()
void Logrank_protocol(double O1, double E1, double V1, double r1,
                      double O2, double E2, double V2, double r2,
                      double O3, double E3, double V3, double r3)
{
    print_example_banner("Example: PROTOCOL");

    /*
    This function evaluates a protocol
    */
    EncryptionParameters parms(scheme_type::CKKS);

    size_t poly_modulus_degree = 8192;
    int scale_cost_param = 30;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    //I icreased the bit_sizes from (60, 40, 40, 60) to (60, 30, 30, 30, 60) to avoid wrap around
    // on the encypted data. this way by the end of the calculation we have 60+30 bits and not 60 bits.
    //the max  bits for poly_modulus_degree=8192 is 218. 60+30+30+30+60 = 210,  so we are still in the write range.
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, scale_cost_param, scale_cost_param, scale_cost_param, 60 }));

    /*
    We choose the initial scale to be 2^30. At the last level, this leaves us
    60+30-30=60 bits of precision before the decimal point, and enough (roughly
    ???? bits) of precision after the decimal point. Since our intermediate
    primes are 30 bits (in fact, they are very close to 2^30), we can achieve
    scale stabilization as described above.
    */
    double scale = pow(2.0, scale_cost_param);

    auto context = SEALContext::Create(parms);
    print_parameters(context);
    cout << endl;

    /*
    When parameters are used to create SEALContext, Microsoft SEAL will first
    validate those parameters. The parameters chosen here are valid.
    */
    cout << "Parameter validation (success): " << context->parameter_error_message() << endl;


    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count(); // the cncoder use poly_modulus_degree/2 slots => 4096
    cout << "Number of slots: " << slot_count << endl;


    double trueResult = (((O1 + O2 + O3) - (E1 + E2 + E3)) / sqrt(V1 + V2 + V3));
    cout << " True value: " << trueResult << endl;

    //H1 do this:
    Cipher_Msg cipher_msg_1 = create_encrypted_msg(encoder, encryptor, scale, O1, E1, V1, r1);

    // H2 do this:
    Cipher_Msg cipher_msg_2 = create_encrypted_msg(encoder, encryptor, scale, O2, E2, V2, r2);

    // H3 do this:
    Cipher_Msg cipher_msg_3 = create_encrypted_msg(encoder, encryptor, scale, O3, E3, V3, r3);

    //--------- SERVER SIDE -----------//

    //Arage the msgs in vectors:
    Basic_Vectors basicVectors = create_basic_vectors(cipher_msg_1, cipher_msg_2, cipher_msg_3);

    /*
    To compute R scale has now grown to 2^30+3 ?....
    */
    Ciphertext sigma_r_encrypted;
    calculate_R(evaluator, basicVectors, sigma_r_encrypted);

    /*
    To compute T0 scale has now grown to 2^30 + log(3)?....
    */
    Ciphertext sigma_T0_encrypted;
    calculate_T0(evaluator, basicVectors, sigma_T0_encrypted);

    /*
    To compute T1 scale has now grown to 2^30 + log(3)?....
    */
    Ciphertext sigma_T1_encrypted;
    calculate_T1(evaluator, basicVectors, sigma_T1_encrypted);

    /*
    Compute D = T0 * R  and relinearize and rescale
    */
    Ciphertext D_encrypted;
    multiply_relinearize_and_rescale(evaluator, sigma_T0_encrypted, sigma_r_encrypted,
                        D_encrypted, "D", relin_keys);

    /*
    Compute R * R  and relinearize and rescale
    */
    Ciphertext R_sq_encrypted;
    square_relinearize_and_rescale(evaluator, sigma_r_encrypted,
                                             R_sq_encrypted, "R", relin_keys);


    /*
    Now R_sq_encrypted is at a different level than sigma_T1_encrypted, which prevents us
    from multiplying them to compute U = T1*R*R. We could simply switch sigma_T1_encrypted to
    the next parameters in the modulus switching chain. However, since we still
    need to multiply the x^3 term with PI (plain_coeff3), we instead compute PI*x
    first and multiply that with x^2 to obtain PI*x^3. To this end, we compute
    PI*x and rescale it back from scale 2^60 to something close to 2^30.
    */

    print_line(__LINE__);
    cout << "Parameters used by all three terms are different." << endl;
    cout << "    + Modulus chain index for sigma_T1_encrypted: "
         << context->get_context_data(sigma_T1_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for R_sq_encrypted: "
         << context->get_context_data(R_sq_encrypted.parms_id())->chain_index() << endl;
    cout << endl;

    print_line(__LINE__);
    cout << "Normalize scales to 2^30." << endl;
    sigma_T1_encrypted.scale() = pow(2.0, scale_cost_param);
    R_sq_encrypted.scale() = pow(2.0, scale_cost_param);

    /*
    We still have a problem with mismatching encryption parameters. This is easy
    to fix by using traditional modulus switching (no rescaling). CKKS supports
    modulus switching just like the BFV scheme, allowing us to switch away parts
    of the coefficient modulus when it is simply not needed.
    */
    print_line(__LINE__);
    cout << "Normalize encryption parameters to the lowest level." << endl;
    parms_id_type last_parms_id = R_sq_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(sigma_T1_encrypted, last_parms_id);

    print_line(__LINE__);
    cout << "Compute and rescale U = T1*R*R." << endl;
    Ciphertext U_encrypted;
    multiply_relinearize_and_rescale(evaluator, sigma_T1_encrypted, R_sq_encrypted,
                                               U_encrypted, "U", relin_keys);

    /*
    Now we would hope to compute the sum of all three terms. However, there is
    a serious problem: the encryption parameters used by all three terms are
    different due to modulus switching from rescaling.

    Encrypted addition and subtraction require that the scales of the inputs are
    the same, and also that the encryption parameters (parms_id) match. If there
    is a mismatch, Evaluator will throw an exception.
    */

    last_parms_id = U_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(D_encrypted, last_parms_id);

    cout << endl;
    print_line(__LINE__);
    cout << "Parameters used by all three terms are different." << endl;
    cout << "    + Modulus chain index for D_encrypted: "
         << context->get_context_data(D_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for U_encrypted: "
         << context->get_context_data(U_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Exact scale in D_encrypted: " << D_encrypted.scale() << endl;
    cout << "    + Exact scale in  U_encrypted: " << U_encrypted.scale() << endl;
    cout << endl;



    /*
    Decrypt, decode, and print the result.
    */
    Plaintext D_plain;
    Plaintext U_plain;

    decryptor.decrypt(D_encrypted, D_plain);
    decryptor.decrypt(U_encrypted, U_plain);
    vector <double> D_result, U_result;
    encoder.decode(D_plain, D_result);
    encoder.decode(U_plain, U_result);

    print_vector(D_result, 3, 7);
    print_vector(U_result, 3, 7);
    double d, u;
    d=D_result[0];
    u=U_result[0];
    double calculatedResult = (d / sqrt(u));
    print_line(__LINE__);
    cout << "True result : " << trueResult << endl;
    cout << "u= : " << u << " d= : " << d << endl;
    cout << "Computed result : " << (d / sqrt(u)) << endl;

    if(std::abs ((double)(calculatedResult - trueResult)/calculatedResult) > 0.01)
    {
        throw;
    }

    /*
    While we did not show any computations on complex numbers in these examples,
    the CKKSEncoder would allow us to have done that just as easily. Additions
    and multiplications of complex numbers behave just as one would expect.
    */
}

void example_anat_basics()
{
    /*
     * lets do 3 hospitals:
     */

//    double O1 = 3000, E1 = 2345.669, V1 = 422.6, r1 = 7134.328;
//    double O2 = 4000, E2 = 1749.779, V2 = 205.4, r2 = 783.385;
//    double O3 = 5000, E3 = 4231.296, V3 = 111.6, r3 = 4283.739;

//    Logrank_protocol(O1, E1, V1, r1, O2, E2, V2, r2, O3, E3, V3, r3);

    for (int i=0; i<10; i++)
    {
        Logrank_protocol_sim();
    }

//    for (int i=0; i<10; i++)
//    {
//        double O1 = rand() % 100;
//        double E1 = (double) (rand() % 100000)/1000; //2345.669;
//        double V1 = (double) (rand() % 10000)/1000; //422.6;
//        double r1 = (double) (rand() % 100000000)/10000; //7134.328;
//
//        double O2 = rand() % 100;
//        double E2 = (double) (rand() % 100000)/1000; //2345.669;
//        double V2 = (double) (rand() % 10000)/1000; //422.6;
//        double r2 = (double) (rand() % 100000000)/10000; //7134.328;
//
//        double O3 = rand() % 100;
//        double E3 = (double) (rand() % 100000)/1000; //2345.669;
//        double V3 = (double) (rand() % 10000)/1000; //422.6;
//        double r3 = (double) (rand() % 100000000)/10000; //7134.328;
//
//        std::cout << " Test Number: "<< i << endl;
//
//        std::cout << " O1="<< O1 <<", E1=" << E1 << ", V1=" << V1 << ", r1=" << r1 << endl;
//        std::cout << " O2="<< O2 <<", E2=" << E2 << ", V2=" << V2 << ", r2=" << r2 << endl;
//        std::cout << " O3="<< O3 <<", E3=" << E3 << ", V3=" << V3 << ", r3=" << r3 << endl;
//
//        Logrank_protocol(O1, E1, V1, r1, O2, E2, V2, r2, O3, E3, V3, r3);
//    }

}