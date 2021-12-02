#ifndef EMP_IO_CHANNEL_H__
#define EMP_IO_CHANNEL_H__
#include <memory>
#include "emp_utils.h"

namespace emp {
template<typename T> 
class IOChannel { public:
	uint64_t counter = 0;
	void send_data(const void * data, int nbyte) {
		counter +=nbyte;
		derived().send_data_internal(data, nbyte);
	}

	void recv_data(void * data, int nbyte) {
		derived().recv_data_internal(data, nbyte);
	}

	private:
	T& derived() {
		return *static_cast<T*>(this);
	}
};
}
#endif
