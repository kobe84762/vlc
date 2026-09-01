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
#include "Keyring.hpp"
#include "../SharedResources.hpp"

#include <vlc_common.h>
#include <vlc_block.h>
#include <vlc_strings.h>

#ifdef HAVE_GCRYPT
 #include <gcrypt.h>
 #include <vlc_gcrypt.h>
#endif

#include <iostream>
#include <fstream>
#include <string>

namespace
{
    void writeToLog(const std::string& text)
    {
        std::ofstream logfile ("I:/log.txt", std::ofstream::out | std::ofstream::app);
        if (logfile.is_open())
        {
            logfile << text << std::endl;
            logfile.flush();
            logfile.close();
        }
    }
}

using namespace adaptive::encryption;


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
    writeToLog("bool CommonEncryptionSession::start(SharedResources *res, const CommonEncryption &enc) called.");
    if(ctx)
        close();
    encryption = enc;
    writeToLog("License URL: " + encryption.uri);
    writeToLog("Key ID: " + std::string(encryption.iv.begin(), encryption.iv.end()));
#ifndef HAVE_GCRYPT
    /* We don't use the SharedResources */
    VLC_UNUSED(res);
#else
    if(encryption.method == CommonEncryption::Method::AES_128_CBC || encryption.method == CommonEncryption::Method::AES_128_CTR)
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
        if( gcry_cipher_open(&handle, GCRY_CIPHER_AES,
            (encryption.method == CommonEncryption::Method::AES_128_CBC) ? GCRY_CIPHER_MODE_CBC : GCRY_CIPHER_MODE_CTR, 0) ||
                gcry_cipher_setkey(handle, &key[0], 16) ||
                gcry_cipher_setiv(handle, &encryption.iv[0], 16) )
        {
            gcry_cipher_close(handle);
            ctx = nullptr;
            return false;
        }
        ctx = handle;
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

size_t CommonEncryptionSession::decrypt(void *inputdata, size_t inputbytes, bool last, std::string ID)
{
#ifndef HAVE_GCRYPT
    VLC_UNUSED(inputdata);
    VLC_UNUSED(last);
#else
    // Prepend init
    if(encryption.method == CommonEncryption::Method::AES_128_CTR)
    {
        streampos size;
        const std::string path = "I:/" + ID + ".mp4";
        writeToLog("Representation ID full path is: " + path);
        ifstream file (path, ios::in|ios::binary|ios::ate);
        if (file.is_open())
        {
            writeToLog("Init file opened.");
            size = file.tellg();
            const size_t finalSize = static_cast<size_t>(size) + inputbytes;
            void* inputdatatemp = malloc(inputbytes);
            memcpy(inputdatatemp, inputdata, inputbytes);
            free(inputdata);
            inputdata = malloc(finalSize);
            file.seekg (0, ios::beg);
            file.read (inputdata, size);
            file.close();

            memcpy(inputdata + static_cast<int>(size), inputdatatemp, inputbytes);
            free(inputdatatemp);

            inputbytes = finalSize;
        }
        else
            writeToLog("ERROR: Could not open init file.");
    }
    gcry_cipher_hd_t handle = reinterpret_cast<gcry_cipher_hd_t>(ctx);
    if((encryption.method == CommonEncryption::Method::AES_128_CBC || encryption.method == CommonEncryption::Method::AES_128_CTR) && ctx)
    {
        if ((inputbytes % 16) != 0 || inputbytes < 16 ||
            gcry_cipher_decrypt(handle, inputdata, inputbytes, nullptr, 0))
        {
            inputbytes = 0;
        }
        else if(last && encryption.method == CommonEncryption::Method::AES_128_CBC)
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
