/*
 * SegmentChunk.cpp
 *****************************************************************************
 * Copyright (C) 2014 - 2015 VideoLAN Authors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
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

#include "SegmentChunk.hpp"
#include "Segment.h"
#include "BaseRepresentation.h"
#include "../encryption/CommonEncryption.hpp"

#include <vlc_block.h>

#include <cassert>
#include <iostream>
#include <fstream>

using namespace adaptive::playlist;
using namespace adaptive::encryption;
using namespace adaptive;


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

SegmentChunk::SegmentChunk(AbstractChunkSource *source, BaseRepresentation *rep_) :
    AbstractChunk(source)
{
    rep = rep_;
    encryptionSession = nullptr;
    discontinuity = false;
    discontinuitySequenceNumber = 0;
}

SegmentChunk::~SegmentChunk()
{
    delete encryptionSession;
}

bool SegmentChunk::decrypt(block_t **pp_block)
{
    block_t *p_block = *pp_block;

    if(encryptionSession)
    {
        const bool b_last = !hasMoreData();
        if ( encryptionSession->getEncryptionMethod() == CommonEncryption::Method::AES_128_CTR && source->getChunkType() == adaptive::http::ChunkType::Segment )
        {
            writeToLog("1");
            std::streampos size;
            const std::string path = "I:/" + rep->getID().str() + ".mp4";
            std::ifstream file (path, std::ios::in|std::ios::binary|std::ios::ate);
            if (file.is_open())
            {
                writeToLog("2");
                size = file.tellg();
                const size_t finalSize = static_cast<size_t>(size) + p_block->i_buffer;
                writeToLog("3");
                block_t *inputdatatemp = block_Duplicate(p_block);
                writeToLog("4");
                block_Release(p_block);
                writeToLog("5");
                p_block = block_Alloc(finalSize);
                writeToLog("6");
                file.seekg (0, std::ios::beg);
                writeToLog("7");
                file.read((char*)p_block->p_buffer, size);
                writeToLog("8");
                file.close();
                writeToLog("9");
    
                memcpy((void*)p_block->p_buffer + static_cast<int>(size), inputdatatemp->p_buffer, inputdatatemp->i_buffer);
                writeToLog("10");
                block_Release(inputdatatemp);
                writeToLog("11");
                p_block->i_buffer = encryptionSession->decrypt(p_block->p_buffer,
                                                       p_block->i_buffer, b_last);
                writeToLog("12");
                if (rep->getID().str() == "0")
                {
                    std::ofstream videoFile ("I:/video.mp4", std::ios::out | std::ios::app | std::ios::binary);
                    if (!videoFile.is_open())
                    {
                        writeToLog("ERROR: Can't open output video file.");
                        return false;
                    }
                    videoFile.write(reinterpret_cast<char*>(p_block->p_buffer), p_block->i_buffer);
                    videoFile.close();
                }
            }
            else
                writeToLog("ERROR: Can't open file " + path);
        }
        
        if(b_last)
            encryptionSession->close();
    }

    return true;
}

void SegmentChunk::onDownload(block_t **pp_block)
{
    decrypt(pp_block);
}

StreamFormat SegmentChunk::getStreamFormat() const
{
    return (format == StreamFormat() && rep) ? rep->getStreamFormat() : format;
}

void SegmentChunk::setStreamFormat(const StreamFormat &f)
{
    format = f;
}

void SegmentChunk::setEncryptionSession(CommonEncryptionSession *s)
{
    delete encryptionSession;
    encryptionSession = s;
}
