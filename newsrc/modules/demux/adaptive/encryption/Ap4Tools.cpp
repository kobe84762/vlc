#include <vlc_block.h>

#include "Ap4.h"
#include "Ap4Tools.hpp"

std::string Bento4::getKeyId(block_t **initData) {

	if ((*initData)->i_buffer < 1) {
		return { };
	}

	keyId.clear();

	AP4_MemoryByteStream* stream = new AP4_MemoryByteStream((*initData)->p_buffer, (*initData)->i_buffer);
	AP4_File file = AP4_File(*stream, true);

	stream->Release();

	return keyId;
}
