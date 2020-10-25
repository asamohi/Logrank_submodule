//
// Created by Anat Samohi on 25/10/2020.
//

#ifndef SEAL_LOGRANK_SIMULATION_H
#define SEAL_LOGRANK_SIMULATION_H

#include <random>
using namespace std;

struct Inputs
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

std::__1::shared_ptr<seal::SEALContext> create_context(const int scale_cost_param)
{
    //I icreased the bit_sizes from (60, 40, 40, 60) to (60, 30, 30, 30, 60) to avoid wrap around
    // on the encypted data. this way by the end of the calculation we have 60+30 bits and not 60 bits.
    //the max  bits for poly_modulus_degree=8192 is 218. 60+30+30+30+60 = 210,  so we are still in the write range.

    EncryptionParameters parms(scheme_type::CKKS);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, scale_cost_param, scale_cost_param, scale_cost_param, 60 }));

    auto context = SEALContext::Create(parms);
    print_parameters(context);
    cout << endl;
    cout << "Parameter validation (success): " << context->parameter_error_message() << endl;

    return context;
}

std::__1::shared_ptr<seal::CKKSEncoder> create_encoder(std::__1::shared_ptr<seal::SEALContext> context)
{
    auto encoder = std::make_shared<CKKSEncoder>(context);
    cout << "Number of slots: " << encoder->slot_count() << endl;

    return encoder;
}

Inputs sample_imputs()
{
    //Init values:
    Inputs inputs;
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


#endif // SEAL_LOGRANK_SIMULATION_H

