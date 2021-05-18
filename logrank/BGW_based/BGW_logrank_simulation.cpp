//
// Created by Anat Samohi on 22/12/2020.
//

#include "BGW_client.h"
#include "../CKKS_based/real_values_simulation.h"

void Logrank_BGW_protocol_sim (int test_index) {
    /*  Init values - sample random numbers to be clients' inputs   */
    Inputs5Clients inputs = take_inputs_from_data(test_index);

    /*  Calculate the protocol correct output, for verification only  */
    double sigma_O = (inputs.O1 + inputs.O2 + inputs.O3 + inputs.O4 + inputs.O5);
    double sigma_E = (inputs.E1 + inputs.E2 + inputs.E3 + inputs.E4 + inputs.E5);
    double sigma_V = (inputs.V1 + inputs.V2 + inputs.V3 + inputs.V4 + inputs.V5);

    double trueResult = (sigma_O - sigma_E) / sqrt(sigma_V);
    std::cout << " True value: " << trueResult << std::endl;

    /*  client entities: perform the experiment and wait for the decrypted output.
     *  In this simulation the experiment results are given to the object */
    BGW_client client1( inputs.O1, inputs.E1, inputs.V1, inputs.r1);
    BGW_client client2( inputs.O2, inputs.E2, inputs.V2, inputs.r2);
    BGW_client client3( inputs.O3, inputs.E3, inputs.V3, inputs.r3);
    BGW_client client4( inputs.O4, inputs.E4, inputs.V4, inputs.r4);
    BGW_client client5( inputs.O5, inputs.E5, inputs.V5, inputs.r5);

    double L1 = client1.get_Li();
    double L2 = client2.get_Li();
    double L3 = client3.get_Li();
    double L4 = client4.get_Li();
    double L5 = client5.get_Li();


    double Lmax = max(max(max(L1, L2), max(L3,L4)), L5);
    std::cout << " Lmax: " << Lmax << std::endl;

    int prime_size  = client1.get_prime_size(Lmax, 5);
    std::cout << " prime_size: " << prime_size << std::endl;

    //use field 42b
    long long int prime = 2871385470517; //42b


}