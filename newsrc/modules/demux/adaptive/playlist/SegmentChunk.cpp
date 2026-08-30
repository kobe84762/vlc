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
#include "../encryption/Ap4Tools.h"

#include <vlc_block.h>

#include <cassert>

using namespace adaptive::playlist;
using namespace adaptive::encryption;
using namespace adaptive;

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
        if ( encryptionSession->getEncryptionMethod() == CommonEncryption::Method::AES_128_CBC )
        {
            p_block->i_buffer = encryptionSession->decrypt(p_block->p_buffer, p_block->i_buffer, b_last);
        }
        else if ( encryptionSession->getEncryptionMethod() == CommonEncryption::Method::AES_128_CTR )
        {
            if ( source->getChunkType() == adaptive::http::ChunkType::Init )
            {
                if (rep)
                    rep->saveInitData(pp_block);
            }
            else if ( source->getChunkType() == adaptive::http::ChunkType::Segment )
            {
                if ( !encryptionSession->hasKeyId() )
                    encryptionSession->setKeyId(Ap4Tools::getKeyId(pp_block));

                if (rep)
                {
                    const bool success = rep->prependInitData(pp_block);
                    if (success)
                        encryptionSession->decrypt(pp_block);
                }
            }
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
