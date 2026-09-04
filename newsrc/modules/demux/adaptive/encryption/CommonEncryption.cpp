/*****************************************************************************
 * CommonEncryption.cpp
 *****************************************************************************
 * Copyright (C) 2015-2019 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "CommonEncryption.hpp"
#include "Ap4.h"
#include "Keyring.hpp"
#include "../SharedResources.hpp"

#include <vlc_block.h>
#include <vlc_common.h>
#include <vlc_strings.h>

#include <iomanip>
#include <sstream>

#ifdef HAVE_GCRYPT
 #include <gcrypt.h>
 #include <vlc_gcrypt.h>
#endif

using namespace adaptive::encryption;

namespace
{
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

    std::string rawKeyToHex(const KeyringKey& key)
    {
        std::ostringstream oss;
    	oss << std::hex << std::setfill('0');
    	for (unsigned char byte : key)
    		oss << std::setw(2) << static_cast<int>(byte);
    	return oss.str();
    }
}


CommonEncryption::CommonEncryption()
{
    method = CommonEncryption::Method::None;
}

void CommonEncryption::mergeWith(const CommonEncryption &other)
{
    if(method == CommonEncryption::Method::None &&
       other.method != CommonEncryption::Method::None)
        method = other.method;
    if(uri.empty() && !other.uri.empty())
        uri = other.uri;
    if(iv.empty() && !other.iv.empty())
        iv = other.iv;
}

CommonEncryptionSession::CommonEncryptionSession()
{
    ctx = nullptr;
}


CommonEncryptionSession::~CommonEncryptionSession()
{
    close();
}

bool CommonEncryptionSession::start(SharedResources *res, const CommonEncryption &enc)
{
    if(ctx)
        close();
    encryption = enc;
#ifndef HAVE_GCRYPT
    /* We don't use the SharedResources */
    VLC_UNUSED(res);
#else
    if(encryption.method == CommonEncryption::Method::AES_128_CBC)
    {
        if(key.empty())
        {
            if(!encryption.uri.empty())
                key = res->getKeyring()->getKey(res, encryption.uri);
            if(key.size() != 16)
                return false;
        }

        vlc_gcrypt_init();
        gcry_cipher_hd_t handle;
        if( gcry_cipher_open(&handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0) ||
                gcry_cipher_setkey(handle, &key[0], 16) ||
                gcry_cipher_setiv(handle, &encryption.iv[0], 16) )
        {
            gcry_cipher_close(handle);
            ctx = nullptr;
            return false;
        }
        ctx = handle;
    }
    else if(encryption.method == CommonEncryption::Method::AES_128_CTR)
    {
        if(key.empty())
        {
            if(!encryption.uri.empty())
                key = res->getKeyring()->getKey(res, encryption.uri);
            if(key.size() != 16)
                return false;
        }
    }
#endif
    return true;
}

void CommonEncryptionSession::close()
{
#ifdef HAVE_GCRYPT
    gcry_cipher_hd_t handle = reinterpret_cast<gcry_cipher_hd_t>(ctx);
    if(ctx)
        gcry_cipher_close(handle);
    ctx = nullptr;
#endif
}

size_t CommonEncryptionSession::decrypt(void *inputdata, size_t inputbytes, bool last)
{
#ifndef HAVE_GCRYPT
    VLC_UNUSED(inputdata);
    VLC_UNUSED(last);
#else
    if(encryption.method == CommonEncryption::Method::AES_128_CBC && ctx)
    {
        gcry_cipher_hd_t handle = reinterpret_cast<gcry_cipher_hd_t>(ctx);
        if ((inputbytes % 16) != 0 || inputbytes < 16 ||
            gcry_cipher_decrypt(handle, inputdata, inputbytes, nullptr, 0))
        {
            inputbytes = 0;
        }
        else if(last)
        {
            /* last bytes */
            /* remove the PKCS#7 padding from the buffer */
            const uint8_t pad = reinterpret_cast<uint8_t *>(inputdata)[inputbytes - 1];
            for(uint8_t i=0; i<pad && i<16; i++)
            {
                if(reinterpret_cast<uint8_t *>(inputdata)[inputbytes - i - 1] != pad)
                    break;
                if(i+1==pad)
                    inputbytes -= pad;
            }
        }
    }
    else
#endif
    if(encryption.method != CommonEncryption::Method::None)
    {
        inputbytes = 0;
    }

    return inputbytes;
}

void CommonEncryptionSession::decrypt(block_t **pp_block, const bool removeAtom)
{
    block_t *p_block = *pp_block;
    const std::string keyIdString = rawKeyToHex(encryption.iv);
    const std::string keyString = rawKeyToHex(key);
    
    unsigned char keyID[16];
    unsigned char decryptionKey[16];
    AP4_ParseHex(keyIdString.c_str(), keyID, 16);
    AP4_ParseHex(keyString.c_str(), decryptionKey, 16);

    AP4_ProtectionKeyMap keyMap;
    keyMap.SetKeyForKid(keyID, decryptionKey, 16);

    AP4_MemoryByteStream* encryptedDataStream = new AP4_MemoryByteStream(p_block->p_buffer, p_block->i_buffer);
    AP4_MemoryByteStream* decryptedDataStream = new AP4_MemoryByteStream();

    AP4_CencDecryptingProcessor decryptionProcessor = AP4_CencDecryptingProcessor(&keyMap);

    if (AP4_FAILED(decryptionProcessor.Process(*encryptedDataStream, *decryptedDataStream))) {
        encryptedDataStream->Release();
        decryptedDataStream->Release();
        return;
    }

    encryptedDataStream->Release();

    if ( !removeAtom )
    {
        block_Release(p_block);
        p_block = block_Alloc(decryptedDataStream->GetDataSize());
        memcpy(p_block->p_buffer, decryptedDataStream->GetData(), decryptedDataStream->GetDataSize());
        decryptedDataStream->Release();
        return;
    }
    
    AP4_EditingProcessor editingProcessor;
    AP4_MemoryByteStream* modifiedDataStream = new AP4_MemoryByteStream();

    if (AP4_FAILED(editingProcessor.Process(*decryptedDataStream, *modifiedDataStream))) {
        decryptedDataStream->Release();
        modifiedDataStream->Release();
        return;
    }

    decryptedDataStream->Release();
    
    block_Release(p_block);
    p_block = block_Alloc(modifiedDataStream->GetDataSize());
    memcpy(p_block->p_buffer, modifiedDataStream->GetData(), modifiedDataStream->GetDataSize());
    modifiedDataStream->Release();
}
