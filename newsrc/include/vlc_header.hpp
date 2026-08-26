/*****************************************************************************
 * vlc_header.hpp: HTTP header API
 *****************************************************************************
 * Copyright (C) 1999-2026 VLC authors and VideoLAN
 *
 * Authors: 
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

#ifndef VLC_HEADER_H
#define VLC_HEADER_H 1

#include <map>
#include <string>

namespace vlc {

	class Header final {
	public:
		static void insertHeader(const std::string& name, const std::string& value) noexcept {
			headers.emplace(name, value);
		}

		static void clearHeaders() noexcept {
			headers.clear();
		}

	private:
      friend class adaptive::http::LibVLCHTTPSource;
		Header() = delete;
		Header(const Header& other) = delete;
		Header& operator=(const Header& other) = delete;
		Header(Header&& other) = delete;
		Header& operator=(Header&& other) = delete;

		void* operator new(size_t);
		void* operator new(size_t, void*);
		void* operator new[](size_t);
		void* operator new[](size_t, void*);

		static inline std::multimap<std::string, std::string> headers = { };
	};
}

#endif
