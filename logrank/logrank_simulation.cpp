//
// Created by Anat Samohi on 23/10/2020.
//

#include <exception>
#include <queue>
#include "../../examples.h"

using namespace std;
using namespace seal;

#include "serv_func.h"
#include "creator_server.h"
#include "client.h"
#include "evaluator_server.h"
#include "logrank_simulation.h"

std::queue<Cipher_Msg> enc_msg_q; //This channel must be secure by HTTPS or other
std::queue<Decrypted_Result> decrypted_result_q; //This channel can be open

void Logrank_protocol_sim () {

    const int scale_cost_param = 30;
    double scale = pow(2.0, scale_cost_param);

    std::__1::shared_ptr<seal::SEALContext> context = create_context(scale_cost_param);
    std::shared_ptr<CKKSEncoder> encoder = create_encoder(context);

    //Init values:
    Inputs inputs = sample_imputs();

    double trueResult =
        (((inputs.O1 + inputs.O2 + inputs.O3) - (inputs.E1 + inputs.E2 + inputs.E3)) / sqrt(inputs.V1 + inputs.V2 + inputs.V3));
    cout << " True value: " << trueResult << endl;

    //Create Entities
    creator_server key_server(context, encoder);
    evaluator_server eval_server(context, key_server.get_relin_keys(), scale);

    client client1(context, encoder, key_server.get_public_key(), scale);
    client client2(context, encoder, key_server.get_public_key(), scale);
    client client3(context, encoder, key_server.get_public_key(), scale);

    //Start online phase
    client1.get_encryped_msg(inputs.O1, inputs.E1, inputs.V1, inputs.r1);
    client2.get_encryped_msg(inputs.O2, inputs.E2, inputs.V2, inputs.r2);
    client3.get_encryped_msg(inputs.O3, inputs.E3, inputs.V3, inputs.r3);

    Encrypted_Result encryptedResult = eval_server.evaluate();
    key_server.decrypt_msg(encryptedResult);

    //Print all client ouputs:
    client1.print_result();
    client2.print_result();
    double calculatedResult = client3.get_result();

    cout << "True result : " << trueResult << endl;

    if(std::abs ((double)(calculatedResult - trueResult)/calculatedResult) > 0.001)
    {
        cout << std::abs((double)(calculatedResult - trueResult)/calculatedResult) << endl;
        throw;
    }
}



