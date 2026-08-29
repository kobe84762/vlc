#include "Ap4.h"
#include "Ap4Tools.h"

namespace {

	class AP4_EditingProcessor final : public AP4_Processor {
	private:
		void* operator new(size_t);          // standard new
		void* operator new(size_t, void*);   // placement new
		void* operator new[](size_t);        // array new
		void* operator new[](size_t, void*); // placement array new

	public:
		virtual AP4_Result Initialize(AP4_AtomParent& top_level, AP4_ByteStream& stream, ProgressListener* listener) {
			const AP4_Result result = remove(top_level);

			if (AP4_FAILED(result)) {
				return result;
			}

			return AP4_SUCCESS;
		}


	private:
		AP4_Result remove(AP4_AtomParent& top_level) {
			AP4_Atom* atom = top_level.FindChild(this->atom);
			if (atom == NULL) {
				return AP4_FAILURE;
			}
			else {
				atom->Detach();
				delete atom;
				return AP4_SUCCESS;
			}
		}

	public:
		const char* atom = "ftyp";

	private:
		AP4_AtomParent m_TopLevelParent;
	};
}

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

void Bento4::decrypt(block_t **segmentData, const char* keyId, const char* key) {

	if (strlen(keyId) != 32 || strlen(key) != 32) {
		return;
	}

	unsigned char keyID[16];
	unsigned char decryptionKey[16];
	AP4_ParseHex(keyId, keyID, 16);
	AP4_ParseHex(key, decryptionKey, 16);

	AP4_ProtectionKeyMap keyMap;
	keyMap.SetKeyForKid(keyID, decryptionKey, 16);

	AP4_MemoryByteStream* input = new AP4_MemoryByteStream((*segmentData)->p_buffer, (*segmentData)->i_buffer);
	AP4_MemoryByteStream* output = new AP4_MemoryByteStream();

	AP4_CencDecryptingProcessor processor = AP4_CencDecryptingProcessor(&keyMap);

	if (AP4_FAILED(processor.Process(*input, *output))) {
		input->Release();
		output->Release();
		return;
	}

	block_Release(*segmentData);
    *segmentData = block_Alloc(output->GetDataSize());
    if (*segmentData == NULL)
        return;
	memcpy((*segmentData)->p_buffer, output->GetData(), (*segmentData)->i_buffer);

	input->Release();
	output->Release();
}

bool Bento4::removeAtom(block_t **segmentData, const char *atom) {

	if (strlen(atom) == 0) {
		return false;
	}

	AP4_EditingProcessor processor;
	processor.atom = atom;

	AP4_MemoryByteStream* input = new AP4_MemoryByteStream((*segmentData)->p_buffer, (*segmentData)->i_buffer);
	AP4_MemoryByteStream* output = new AP4_MemoryByteStream();

	if (AP4_FAILED(processor.Process(*input, *output))) {
		input->Release();
		output->Release();
		return false;
	}

	block_Release(*segmentData);
    *segmentData = block_Alloc(output->GetDataSize());
    if (*segmentData == NULL)
        return;
	memcpy((*segmentData)->p_buffer, output->GetData(), (*segmentData)->i_buffer);

	input->Release();
	output->Release();

	return true;
}
