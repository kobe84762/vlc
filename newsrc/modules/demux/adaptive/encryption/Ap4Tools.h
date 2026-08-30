#ifndef _AP4_TOOLS_H_
#define _AP4_TOOLS_H_

#include <string>

typedef struct vlc_frame_t block_t;

class Ap4Tools final {
private:
	friend class AP4_CencTrackEncryption;
	Ap4Tools() = delete;
	Ap4Tools(const Ap4Tools& other) = delete;
	Ap4Tools& operator=(const Ap4Tools& other) = delete;
	Ap4Tools(Ap4Tools&& other) = delete;
	Ap4Tools& operator=(Ap4Tools&& other) = delete;

	void* operator new(size_t);
	void* operator new(size_t, void*);
	void  operator delete(void*);
	void* operator new[](size_t);
	void* operator new[](size_t, void*);
	void  operator delete[](void*);

public:
	static std::string getKeyId(block_t **initData);
	static void decrypt(block_t **segment, const char* keyId, const char* key);
	static bool removeAtom(block_t **segment, const char *atom);

private:
	inline static std::string keyId = std::string("");
};

#endif // !_AP4_TOOLS_H_
