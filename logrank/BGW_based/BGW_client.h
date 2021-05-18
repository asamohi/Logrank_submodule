//
// Created by Anat Samohi on 22/12/2020.
//

#ifndef SEAL_BGW_CLIENT_H
#define SEAL_BGW_CLIENT_H

#include <math.h>
#include "../../../examples.h"
using namespace std;

struct Client_Input
{
    double O;
    double E;
    double V;
    double r;
};

class BGW_client
{
private:
    Client_Input input;
    double Li;
    long long int prime = 1;
    int lamda[6];

public:
    BGW_client(double O, double E, double V, double r)
    {
        /*  Get the experiment results which are the input: */
        input.E = E;
        input.O = O;
        input.V = V;
        input.r = r;
        Li = (input.O != 0) ? floor(log2(input.O))+1 : 1;
        std::cout << " input.O: " << input.O << " Li: " << Li <<std::endl;

        lamda[0] = 0;
        lamda[1] = 5;
        lamda[2] = -10;
        lamda[3] = 10;
        lamda[4] = -5;
        lamda[5] = 1;
    }

    double get_Li()
    {
        return Li;
    }

    double get_prime_size(int Lmax, int k)
    {
        return (31 + Lmax + 3*log2(k));
    }

    void  set_prime(long long int prime_)
    {
        prime = prime_;
    }

    long long int calculate_modulu(long long int value)
    {
        value = value % prime;
        value = value - (long long int)floor(prime/2);
        return(value);
    }

    long long int rand_coeef()
    {
        return calculate_modulu ((rand() << 32) + rand());
    }

    


};

#endif // SEAL_BGW_CLIENT_H;
