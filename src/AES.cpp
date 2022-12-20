#include <cmath>
#include <cstddef>
#include <ios>
#include <iostream>
#include <string>
#include <type_traits>
#include <fstream>
#include "AES.hpp"

int main() {
    auto AES_128 = AES(128);
    std::vector<unsigned char> in, key;
    std::string l;
    std::ifstream OpenText("../open.txt");
    while(std::getline(OpenText, l)) {
        for(size_t i = 0; i < l.size(); i++)
            in.push_back(l[i]);
    }
    OpenText.close();
    
    std::ifstream Key("../key.txt");
    while(std::getline(Key, l)) {
        for(size_t i = 0; i < l.size(); i++)
            key.push_back(l[i]);
    }
    Key.close();
    
    AES_128.AddOpen(in);
    AES_128.AddKey(key);
    AES_128.KeyExpansion();
    AES_128.Crypt();
    auto out_str = AES_128.MatrStr(AES_128.OUT);
    AES_128.AddOpen(out_str);
    AES_128.Decrypt();
    auto dec_str = AES_128.MatrStr(AES_128.OUT);

    std::ofstream Out("../out.txt");
    for(size_t i = 0; i < dec_str.size(); i++)
        Out<<dec_str[i];
    Out.close();
}

AES::AES() {
    this->NK = 4;
    this->NR = 10;
    this->RESIZE();
}

AES::AES(unsigned int len) {
    if(len == 128) {
        this->NK = 4;
        this->NR = 10;
        this->RESIZE();
    }
    else if (len == 192) {
        this->NK = 6;
        this->NR = 12;
        this->RESIZE();
    }
    else if(len == 256) {
        this->NK = 8;
        this->NR = 14;
        this->RESIZE();
    }
}

void AES::RESIZE() {
    this->KEY.resize(4);
    this->KEYSHEDULE.resize(this->NB * (this->NR + 1), std::vector<unsigned char>(4, 0));
}

void AES::AddOpen(std::vector<unsigned char> in) {
    this->IN.clear();
    while(in.size() % (4 * this->NB) != 0)
        in.push_back(0x00);
    std::vector<unsigned char> block;
    for(size_t i = 0; i < in.size(); i++) {
        block.push_back(in[i]);
        if((i + 1) % (4 * this->NB) == 0) {
            this->IN.push_back(StrMatr(block));
            block.clear();
        }
    }
}

void AES::AddCipher(std::vector<unsigned char> out) {
    this->OUT.clear();
    while(out.size() % (4 * this->NB) != 0)
        out.push_back(0x00);
    std::vector<unsigned char> block;
    for(size_t i = 0; i < out.size(); i++) {
        block.push_back(out[i]);
        if((i + 1) % (4 * this->NB) == 0) {
            this->OUT.push_back(StrMatr(block));
            block.clear();
        }
    }
}

void AES::AddKey(std::vector<unsigned char> key) {
    this->KEY.clear();
    if(key.size() % 16 != 0 && key.size() % 24 != 0 && key.size() % 32 != 0)
        throw std::runtime_error("unable to parse key");
    size_t pos = 0;
    for(size_t i = 0; i < key.size(); i++) {
        this->KEY[pos].push_back(key[i]);
        pos = (pos + 1) % 4;
    }
}

void AES::Crypt() {
    this->OUT.clear();
    for(size_t i = 0; i < this->IN.size(); i++)
        this->OUT.push_back(CryptBlock(this->IN[i]));
}

void AES::Decrypt() {
    this->OUT.clear();
    for(size_t i = 0; i < this->IN.size(); i++)
        this->OUT.push_back(DecryptBlock(this->IN[i]));
}

void PrVec(std::vector<unsigned char>& vec) {
    std::cout<<std::hex;
    for(size_t i = 0; i < vec.size(); i++)
        std::cout<<static_cast<int>(vec[i])<<' ';
    std::cout<<std::dec<<'\n';
}

std::vector<std::vector<unsigned char>> AES::CryptBlock(std::vector<std::vector<unsigned char>> block) {
    AddRoundKey(block, 0);
    for(size_t round = 0; round < this->NR - 1; round++) {
        SubBytes(block);
        ShiftRows(block);
        MixColumns(block);
        AddRoundKey(block, (round + 1) * this->NB);
    }
    SubBytes(block);
    ShiftRows(block);
    AddRoundKey(block, this->NR * this->NB);
    return block;
}

std::vector<std::vector<unsigned char>> AES::DecryptBlock(std::vector<std::vector<unsigned char>> block) {
    AddRoundKey(block, this->NR * this->NB);
    for(size_t round = this->NR - 1; round >= 1; round--) {
        InvShifRows(block);
        InvSubBytes(block);
        AddRoundKey(block, (round) * this->NB);
        InvMixColumns(block);
    }
    InvShifRows(block);
    InvSubBytes(block);
    AddRoundKey(block, 0);
    return block;
}

void PrWord(std::vector<unsigned char>& word) {
    std::cout<<std::hex<<static_cast<int>(word[0])<<' ';
    std::cout<<std::hex<<static_cast<int>(word[1])<<' ';
    std::cout<<std::hex<<static_cast<int>(word[2])<<' ';
    std::cout<<std::hex<<static_cast<int>(word[3])<<'\n';
    std::cout<<std::dec;
}

void AES::KeyExpansion() {
    size_t pos = 0;
    while(pos < this->NK) {
        this->KEYSHEDULE[pos][0] = this->KEY[0][pos];
        this->KEYSHEDULE[pos][1] = this->KEY[1][pos];
        this->KEYSHEDULE[pos][2] = this->KEY[2][pos];
        this->KEYSHEDULE[pos][3] = this->KEY[3][pos];
        pos++;
    }

    while(pos < this->NB * (this->NR + 1)) {
        auto temp = this->KEYSHEDULE[pos-1];
        if(pos % this->NK == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] = temp[0] ^ RCON[pos / this->NK - 1][0];
            temp[1] = temp[1] ^ RCON[pos / this->NK - 1][1];
            temp[2] = temp[2] ^ RCON[pos / this->NK - 1][2];
            temp[3] = temp[3] ^ RCON[pos / this->NK - 1][3];
        }
        else if(this->NK > 6 && pos % this->NK == 4) {
            SubWord(temp);
        }
        this->KEYSHEDULE[pos][0] = this->KEYSHEDULE[pos - this->NK][0] ^ temp[0];
        this->KEYSHEDULE[pos][1] = this->KEYSHEDULE[pos - this->NK][1] ^ temp[1];
        this->KEYSHEDULE[pos][2] = this->KEYSHEDULE[pos - this->NK][2] ^ temp[2];
        this->KEYSHEDULE[pos][3] = this->KEYSHEDULE[pos - this->NK][3] ^ temp[3];
        pos++;
    }
}

void AES::RotWord(std::vector<unsigned char>& word) {
    std::swap(word[0], word[1]);
    std::swap(word[1], word[2]);
    std::swap(word[2], word[3]);
}

void AES::SubWord(std::vector<unsigned char>& word) {
    for(size_t i = 0; i < word.size(); i++)
        word[i] = SBOX[word[i]];
}

std::vector<std::vector<unsigned char>> AES::StrMatr(std::vector<unsigned char>& str) {
    auto vec = std::vector<std::vector<unsigned char>>(4, std::vector<unsigned char>());
    size_t pos = 0;
    for(size_t i = 0; i < str.size(); i++) {
        vec[pos].push_back(str[i]);
        pos = (pos + 1) % 4;
    }
    return vec;
}

std::vector<unsigned char> AES::MatrStr(std::vector<std::vector<std::vector<unsigned char>>>& vec) {
    std::vector<unsigned char> str;
    for(size_t i = 0; i < vec.size(); i++) {
        for(size_t j = 0; j < vec[0][0].size(); j++) {
            for(size_t k = 0; k < vec[0].size(); k++)
                str.push_back(vec[i][k][j]);
        }
    }
    return str;
}

void AES::AddRoundKey(std::vector<std::vector<unsigned char>>& state, size_t pos0) {
    for(size_t i = 0; i < this->NB; i++) {
        state[0][i] ^= this->KEYSHEDULE[pos0 + i][0];
        state[1][i] ^= this->KEYSHEDULE[pos0 + i][1];
        state[2][i] ^= this->KEYSHEDULE[pos0 + i][2];
        state[3][i] ^= this->KEYSHEDULE[pos0 + i][3];
    }
}

void AES::SubBytes(std::vector<std::vector<unsigned char>>& state) {
    for(size_t i = 0; i < state.size(); i++) {
        for(size_t j = 0; j < state[0].size(); j++) {
            state[i][j] = SBOX[state[i][j]];
        }
    }
}

void AES::ShiftRows(std::vector<std::vector<unsigned char>>& state) {
    std::swap(state[1][0], state[1][1]);
    std::swap(state[1][1], state[1][2]);
    std::swap(state[1][2], state[1][3]);

    std::swap(state[2][0], state[2][2]);
    std::swap(state[2][1], state[2][3]);

    std::swap(state[3][3], state[3][2]);
    std::swap(state[3][2], state[3][1]);
    std::swap(state[3][1], state[3][0]);
}

void AES::MixColumns(std::vector<std::vector<unsigned char>>& state) {
    auto temp = state;
    for(size_t pos = 0; pos < this->NB; pos++) {
        temp[0][pos] = GF[2][state[0][pos]] ^ GF[3][state[1][pos]] ^ state[2][pos] ^ state[3][pos];
        temp[1][pos] = state[0][pos] ^ GF[2][state[1][pos]] ^ GF[3][state[2][pos]] ^ state[3][pos];
        temp[2][pos] = state[0][pos] ^ state[1][pos] ^ GF[2][state[2][pos]] ^ GF[3][state[3][pos]];
        temp[3][pos] = GF[3][state[0][pos]] ^ state[1][pos] ^ state[2][pos] ^ GF[2][state[3][pos]];
    }
    state = temp;
}

void AES::InvSubBytes(std::vector<std::vector<unsigned char>>& state) {
    for(size_t i = 0; i < state.size(); i++) {
        for(size_t j = 0; j < state[0].size(); j++) {
            state[i][j] = INVSBOX[state[i][j]];
        }
    }
}

void AES::InvShifRows(std::vector<std::vector<unsigned char>>& state) {
    std::swap(state[1][3], state[1][2]);
    std::swap(state[1][2], state[1][1]);
    std::swap(state[1][1], state[1][0]);

    std::swap(state[2][3], state[2][1]);
    std::swap(state[2][2], state[2][0]);

    std::swap(state[3][0], state[3][1]);
    std::swap(state[3][1], state[3][2]);
    std::swap(state[3][2], state[3][3]);
}

void AES::InvMixColumns(std::vector<std::vector<unsigned char>>& state) {
    auto temp = state;
    for(size_t pos = 0; pos < this->NB; pos++) {
        temp[0][pos] = GF[14][state[0][pos]] ^ GF[11][state[1][pos]] ^ GF[13][state[2][pos]] ^ GF[9][state[3][pos]];
        temp[1][pos] = GF[9][state[0][pos]] ^ GF[14][state[1][pos]] ^ GF[11][state[2][pos]] ^ GF[13][state[3][pos]];
        temp[2][pos] = GF[13][state[0][pos]] ^ GF[9][state[1][pos]] ^ GF[14][state[2][pos]] ^ GF[11][state[3][pos]];
        temp[3][pos] = GF[11][state[0][pos]] ^ GF[13][state[1][pos]] ^ GF[9][state[2][pos]] ^ GF[14][state[3][pos]];
    }
    state = temp;
}

void AES::PrintBlock(std::vector<std::vector<unsigned char>>& block) {
    for(size_t i = 0; i < block.size(); i++) {
        for(size_t j = 0; j < block[i].size(); j++)
            std::cout<<std::hex<<static_cast<int>(block[i][j])<<' ';
        std::cout<<'\n';
    }
}
