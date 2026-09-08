#include "Ap4.h"
#include "Ap4Tools.h"

std::string Ap4Tools::getKeyId(void *inputdata, size_t inputbytes) {

    if (inputbytes < 1)
        return { };

    keyId.clear();

    AP4_MemoryByteStream* stream = new AP4_MemoryByteStream(reinterpret_cast<unsigned char *>(inputdata), inputbytes);
    AP4_File file = AP4_File(*stream, true);

    stream->Release();

    return keyId;
}
