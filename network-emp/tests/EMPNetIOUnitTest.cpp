#include "io_channel.h"
#include "net_io_channel.h"
#include "highspeed_net_io_channel.h"
#include <cryptoTools/Crypto/PRNG.h>
#include "utils/colors.h"

using namespace std;
using namespace emp;
using namespace osuCrypto;

#define ALICE 0
#define BOB   1

int length = 1<<10;

int main(int argc, char** argv){
	int port, party;
	parse_party_and_port(argv, 2, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);
	block seed = toBlock(1, 1);
    osuCrypto::PRNG prng;
	prng.SetSeed(seed);

    uint8_t* x = new uint8_t[length];
	uint8_t* x_ = new uint8_t[length];
	cout<<"Filled up data arrays"<<endl;
	prng.get<uint8_t>(x, length);
	cout<<"Now calling network functions"<<endl;
	switch(party) {
		case ALICE: {
			cout<<"Alice: Sending data"<<endl;
			for(int i = 0; i < length; i++)
				io->send_data(x+i, 1);
			cout<<"Alice: Receiving data"<<endl;
			for(int i = 0; i < length; i++)
				io->recv_data(x_+i, 1);
			cout<<"Alice: Checking correctness"<<endl;
			for(int i = 0; i < length; i++)
				assert(x[i] == x_[i]);
			cout<<GREEN<<"Network function is: CORRECT!"<<RESET<<endl;
			break;
		}
		case BOB: {
			cout<<"Bob: Sending data"<<endl;
			for(int i = 0; i < length; i++)
				io->send_data(x+i, 1);
			cout<<"Bob: Receiving data"<<endl;
			for(int i = 0; i < length; i++)
				io->recv_data(x_+i, 1);
			cout<<"Bob: Checking correctness"<<endl;
			for(int i = 0; i < length; i++)
				assert(x[i] == x_[i]);
			cout<<GREEN<<"Network function is: CORRECT!"<<RESET<<endl;
			break;
		}
	}
	delete io;
}
