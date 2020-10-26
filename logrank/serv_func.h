//
// Created by Anat Samohi on 21/10/2020.
//

#ifndef SEAL_SERV_FUNC_H
#define SEAL_SERV_FUNC_H

#include "../../examples.h"

using namespace std;
using namespace seal;

enum MultiplicatioType
{
    MULTIPLY =0,
    SQUARE =1
};

struct Cipher_Msg
{
    Ciphertext enc_O_minus_E;
    Ciphertext enc_V;
    Ciphertext enc_r;
};

struct Basic_Vectors
{
    vector<Ciphertext> r_encrypted_vector;
    vector<Ciphertext> T0_encrypted_vector;
    vector<Ciphertext> T1_encrypted_vector;
};

struct Encrypted_Result
{
    Ciphertext D_encrypted;
    Ciphertext U_encrypted;
};

struct Decrypted_Result
{
    double D;
    double U;
};

inline Cipher_Msg create_encrypted_msg(CKKSEncoder& encoder, Encryptor& encryptor, double scale, double O, double E, double V, double r)
{
    Plaintext plain_O_minus_E, plain_V, plain_r;
    encoder.encode(O - E, scale, plain_O_minus_E);
    encoder.encode(V, scale, plain_V);
    encoder.encode(r, scale, plain_r);

    Cipher_Msg cipher;
    encryptor.encrypt(plain_O_minus_E, cipher.enc_O_minus_E);
    encryptor.encrypt(plain_V, cipher.enc_V);
    encryptor.encrypt(plain_r, cipher.enc_r);

    return (cipher);
}

inline Basic_Vectors create_basic_vectors(vector<Cipher_Msg> msg_vec)
{
    Basic_Vectors basicVectors;
    for (unsigned long i=0; i< msg_vec.size(); i++)
    {
        basicVectors.r_encrypted_vector.push_back(msg_vec[i].enc_r);
        basicVectors.T0_encrypted_vector.push_back(msg_vec[i].enc_O_minus_E);
        basicVectors.T1_encrypted_vector.push_back(msg_vec[i].enc_V);
    }
    return basicVectors;
}

inline Basic_Vectors create_basic_vectors(Cipher_Msg& cipher_msg_1, Cipher_Msg& cipher_msg_2, Cipher_Msg& cipher_msg_3)
{
    Basic_Vectors basicVectors;

    basicVectors.r_encrypted_vector.push_back(cipher_msg_1.enc_r);
    basicVectors.r_encrypted_vector.push_back(cipher_msg_2.enc_r);
    basicVectors.r_encrypted_vector.push_back(cipher_msg_3.enc_r);

    basicVectors.T0_encrypted_vector.push_back(cipher_msg_1.enc_O_minus_E);
    basicVectors.T0_encrypted_vector.push_back(cipher_msg_2.enc_O_minus_E);
    basicVectors.T0_encrypted_vector.push_back(cipher_msg_3.enc_O_minus_E);

    basicVectors.T1_encrypted_vector.push_back(cipher_msg_1.enc_V);
    basicVectors.T1_encrypted_vector.push_back(cipher_msg_2.enc_V);
    basicVectors.T1_encrypted_vector.push_back(cipher_msg_3.enc_V);

    return basicVectors;
}

inline void calculate_sigma(Evaluator& evaluator, vector<Ciphertext>& basicVectorsField, Ciphertext& sigma_encrypted, std::string str)
{
    print_line(__LINE__);
    cout << "Compute sigma_" << str << "_encrypted. No relinearize, No rescale" << endl;
    evaluator.add_many(basicVectorsField, sigma_encrypted);
    cout << "    + size of sigma_" << str << "_encrypted: " << sigma_encrypted.size() << endl;
    cout << "    + Scale of sigma_" << str << "_encrypted: " << log2(sigma_encrypted.scale()) << " bits" << endl;
}

inline void calculate_R(Evaluator& evaluator, Basic_Vectors& basicVectors, Ciphertext& sigma_r_encrypted)
{
    calculate_sigma(evaluator, basicVectors.r_encrypted_vector, sigma_r_encrypted, "r");
}

inline void calculate_T0(Evaluator& evaluator, Basic_Vectors& basicVectors, Ciphertext& sigma_T0_encrypted)
{
    calculate_sigma(evaluator, basicVectors.T0_encrypted_vector, sigma_T0_encrypted, "T0");
}

inline void calculate_T1(Evaluator& evaluator, Basic_Vectors& basicVectors, Ciphertext& sigma_T1_encrypted)
{
    calculate_sigma(evaluator, basicVectors.T1_encrypted_vector, sigma_T1_encrypted, "T1");
}

inline void general_multiply_relinearize_and_rescale(Evaluator& evaluator, Ciphertext& first_arg, Ciphertext& second_arg,
                                                Ciphertext& result, std::string name, RelinKeys& relin_keys,
                                                MultiplicatioType multiplicatioType)
{
    print_line(__LINE__);
    cout << "Compute multiply and relinearize and rescale" << endl;
    if(multiplicatioType == MULTIPLY)
    {
        evaluator.multiply(first_arg, second_arg, result);
    }
    else
    {
        evaluator.square(first_arg, result);
    }
    cout << "    + size of " << name << " (before relinearization): " << result.size() << endl;
    evaluator.relinearize_inplace(result, relin_keys);
    cout << "    + size of " << name << " (after relinearization): " << result.size() << endl;
    cout << "    + Scale of " << name << " before rescale: " << log2(result.scale()) << " bits" << endl;

    /*
    Now rescale; in addition to a modulus switch, the scale is reduced down by
    a factor equal to the prime that was switched away (30-bit prime). Hence, the
    new scale should be close to 2^30. Note, however, that the scale is not equal
    to 2^30: this is because the 30-bit prime is only close to 2^30.
    */

    evaluator.rescale_to_next_inplace(result);
    cout << "    + Scale of "<< name << " after rescale: " << log2(result.scale()) << " bits" << endl;

}

inline void multiply_relinearize_and_rescale(Evaluator& evaluator, Ciphertext& first_arg, Ciphertext& second_arg,
                               Ciphertext& result, std::string name, RelinKeys& relin_keys)
{
    general_multiply_relinearize_and_rescale(evaluator, first_arg, second_arg,
                                             result, name, relin_keys,MULTIPLY);
}

//inline void multiply_relinearize_and_rescale(Evaluator& evaluator, Ciphertext& first_arg, Ciphertext& second_arg,
//                                             Ciphertext& result, std::string name, RelinKeys& relin_keys)
//{
//    print_line(__LINE__);
//    cout << "Compute multiply and relinearize and rescale" << endl;
//    evaluator.multiply(first_arg, second_arg, result);
//    cout << "    + size of " << name << " (before relinearization): " << result.size() << endl;
//    evaluator.relinearize_inplace(result, relin_keys);
//    cout << "    + size of " << name << " (after relinearization): " << result.size() << endl;
//    cout << "    + Scale of " << name << " before rescale: " << log2(result.scale()) << " bits" << endl;
//
//    /*
//    Now rescale; in addition to a modulus switch, the scale is reduced down by
//    a factor equal to the prime that was switched away (30-bit prime). Hence, the
//    new scale should be close to 2^30. Note, however, that the scale is not equal
//    to 2^30: this is because the 30-bit prime is only close to 2^30.
//    */
//
//    evaluator.rescale_to_next_inplace(result);
//    cout << "    + Scale of "<< name << " after rescale: " << log2(result.scale()) << " bits" << endl;
//
//}

inline void square_relinearize_and_rescale(Evaluator& evaluator, Ciphertext& arg,
                                                    Ciphertext& result, std::string name, RelinKeys& relin_keys)
{
    general_multiply_relinearize_and_rescale(evaluator, arg, arg,
                                             result, name, relin_keys, SQUARE);
}


#endif // SEAL_SERV_FUNC_H
