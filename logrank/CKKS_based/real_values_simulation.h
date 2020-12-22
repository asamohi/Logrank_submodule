//
// Created by Anat Samohi on 26/10/2020.
//

#ifndef SEAL_REAL_VALUES_SIMULATION_H
#define SEAL_REAL_VALUES_SIMULATION_H

struct Inputs5Clients
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

    double O4;
    double E4;
    double V4;
    double r4;

    double O5;
    double E5;
    double V5;
    double r5;
};

inline Inputs5Clients take_inputs_from_data(int test_index)
{
    //This numbers are taken from actual data (Mainz cohort)
    //Z = -2.1903628450938113

    Inputs5Clients inputs;

    switch(test_index)
    {
    case 0:
        inputs.O1 = 2.0; inputs.E1 = 6.212558176392608; inputs.V1 = 3.446733878275501;
        inputs.O2 = 0.0; inputs.E2 = 0.444444444444444; inputs.V2 = 0.246913580246913;
        inputs.O3 = 2.0; inputs.E3 = 2.909841585620464; inputs.V3 = 2.000985460430647;
        inputs.O4 = 6.0; inputs.E4 = 6.691643130267606; inputs.V4 = 3.627487212922465;
        inputs.O5 = 2.0; inputs.E5 = 2.450894909688013; inputs.V5 = 1.408912992240098;
        break;
    case 1:
        inputs.O1 = 0.0; inputs.E1 = 2.764382651882651; inputs.V1 = 1.655899995615502;
        inputs.O2 = 4.0; inputs.E2 = 4.045909749321727; inputs.V2 = 2.674478349333708;
        inputs.O3 = 2.0; inputs.E3 = 4.405309661552012; inputs.V3 = 2.447099024107411;
        inputs.O4 = 2.0; inputs.E4 = 4.560036458244919; inputs.V4 = 2.146062469663711;
        inputs.O5 = 4.0; inputs.E5 = 3.074196501697351; inputs.V5 = 1.883923054488748;
        break;
    case 2:
        inputs.O1 = 3.0; inputs.E1 = 4.303808986635138; inputs.V1 = 2.227701183392008;
        inputs.O2 = 2.0; inputs.E2 = 2.783354218880534; inputs.V2 = 1.668003739071293;
        inputs.O3 = 1.0; inputs.E3 = 2.155582706766917; inputs.V3 = 1.217894585264854;
        inputs.O4 = 3.0; inputs.E4 = 6.710881264573549; inputs.V4 = 3.683748150472197;
        inputs.O5 = 3.0; inputs.E5 = 2.972902079625193; inputs.V5 = 2.064968793041594;
        break;
    case 3:
        inputs.O1 = 4.0; inputs.E1 = 7.722036069936982;  inputs.V1 = 3.95806375562691;
        inputs.O2 = 2.0; inputs.E2 = 1.886528822055138;  inputs.V2 = 1.1699563719763066;
        inputs.O3 = 3.0; inputs.E3 = 4.7230593476444955; inputs.V3 = 2.861966759621795;
        inputs.O4 = 1.0; inputs.E4 = 2.231968755881799;  inputs.V4 = 1.3684969682905628;
        inputs.O5 = 2.0; inputs.E5 = 3.4721664808621333; inputs.V5 = 1.731875280760938;
        break;
    case 4:
        inputs.O1 = 1.0; inputs.E1 = 5.006480606858572;  inputs.V1 = 2.9147856164827948;
        inputs.O2 = 3.0; inputs.E2 = 4.471781182265463;  inputs.V2 = 2.631050392552203;
        inputs.O3 = 1.0; inputs.E3 = 2.7368347338935575; inputs.V3 = 0.8614163116226885;
        inputs.O4 = 6.0; inputs.E4 = 4.899659258720877;  inputs.V4 = 3.173284051817217;
        inputs.O5 = 1.0; inputs.E5 = 1.572908572908573;  inputs.V5 = 0.9494672114459736;
        break;
    }

    inputs.r1 = (double) (rand() % 10000000)/10000;
    inputs.r2 = (double) (rand() % 10000000)/10000;
    inputs.r3 = (double) (rand() % 10000000)/10000;
    inputs.r4 = (double) (rand() % 10000000)/10000;
    inputs.r5 = (double) (rand() % 10000000)/10000;

    return inputs;
}

#endif // SEAL_REAL_VALUES_SIMULATION_H
