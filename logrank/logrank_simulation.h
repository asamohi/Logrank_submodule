//
// Created by Anat Samohi on 25/10/2020.
//

#ifndef SEAL_LOGRANK_SIMULATION_H
#define SEAL_LOGRANK_SIMULATION_H

#include <random>
using namespace std;

void example_logrank_5_clients_test();

struct Inputs3Clients
{
    double O1;
    double E1;
    double V1;
    double r1;

    double O2;
    double E2;
    double V2;
    double r2;

    double O3;
    double E3;
    double V3;
    double r3;
};

struct Crypto_Resources
{
    double scale;
    SEALContext context;
    CKKSEncoder encoder;
};

inline std::__1::shared_ptr<seal::SEALContext> create_context(const int scale_cost_param)
{
    /* I increased the bit_sizes from (60, 40, 40, 60) to (60, 30, 30, 30, 60) to avoid wrap around bugs
     * on the encrypted data. By the end of the calculation we have 60+30 bits instead of 60 bits.
     * (60 bits caused an error, 60+30 bits solved the issue.)
     * the CoeffModulus maximum bits for poly_modulus_degree=8192 is 218.
     * 60+30+30+30+60 = 210 < 218, so we are still in the valid range. */

    EncryptionParameters parms(scheme_type::CKKS);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, scale_cost_param, scale_cost_param, scale_cost_param, 60 }));

    /*  We choose the initial scale to be 2^30. At level 1 (the lowest level we used), we still have 60+30-30=60
     *  bits of precision before the decimal point, and enough (how much?) of precision after the decimal point.
     *  (The -30 is because of the scale, 60+30 is because we still have 2 primes left in the CoeffModulus)
     *  Since our intermediate primes are 30 bits (in fact, they are very close to 2^30), we can achieve
     *  scale stabilization as described above.  */

    auto context = SEALContext::Create(parms);

    /*  When parameters are used to create SEALContext, Microsoft SEAL will first validate those parameters.
     *  The parameters chosen are valid. */
    print_parameters(context);
    cout << endl;
    cout << "Parameter validation (success): " << context->parameter_error_message() << endl;

    return context;
}

inline std::__1::shared_ptr<seal::CKKSEncoder> create_encoder(std::__1::shared_ptr<seal::SEALContext> context)
{
    auto encoder = std::make_shared<CKKSEncoder>(context); // the encoder use poly_modulus_degree/2 slots => 4096
    cout << "Number of slots: " << encoder->slot_count() << endl;

    return encoder;
}

inline Inputs3Clients sample_inputs_3_clients()
{
    //sample random values.

    Inputs3Clients inputs;
    inputs.O1 = rand() % 100;
    inputs.E1 = (double) (rand() % 100000)/1000; //2345.669;
    inputs.V1 = (double) (rand() % 10000)/1000; //422.6;
    inputs.r1 = (double) (rand() % 100000000)/10000; //7134.328;

    inputs.O2 = rand() % 100;
    inputs.E2 = (double) (rand() % 100000)/1000; //2345.669;
    inputs.V2 = (double) (rand() % 10000)/1000; //422.6;
    inputs.r2 = (double) (rand() % 100000000)/10000; //7134.328;

    inputs.O3 = rand() % 100;
    inputs.E3 = (double) (rand() % 100000)/1000; //2345.669;
    inputs.V3 = (double) (rand() % 10000)/1000; //422.6;
    inputs.r3 = (double) (rand() % 100000000)/10000; //7134.328;

    return inputs;
}

inline void verify_result(client& client, double trueResult)
{
    /*  Simulation verification  */
    double calculatedResult = client.get_result();
    cout << "True result : " << trueResult << endl;
    if(std::abs ((double)(calculatedResult - trueResult)/calculatedResult) > 0.001)
    {
        cout << "---- ERROR!! ----- the gap is : " << std::abs((double)(calculatedResult - trueResult)/calculatedResult) << endl;
        throw;
    }
}

inline void measure_test_time(chrono::high_resolution_clock::time_point time_start)
{
    /*  Measure performance of the online phase */
    chrono::high_resolution_clock::time_point time_end = chrono::high_resolution_clock::now();
    chrono::milliseconds time_diff = chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
    cout << "END ONLINE PHASE [" << time_diff.count() << " milliseconds]" << endl;

}
#endif // SEAL_LOGRANK_SIMULATION_H

