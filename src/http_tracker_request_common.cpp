/*

Copyright (c) 2004-2026, Arvid Norberg
Copyright (c) 2004, Magnus Jonsson
Copyright (c) 2015, Mikhail Titov
Copyright (c) 2016-2018, 2020-2021, Alden Torres
Copyright (c) 2016, Andrei Kurushin
Copyright (c) 2016-2018, Steven Siloti
Copyright (c) 2017, Pavel Pimenov
Copyright (c) 2020, Paul-Louis Ageneau
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libtorrent/aux_/http_tracker_request_common.hpp"

#include <list>
#include <algorithm>
#include <string>
#include <cstdio> // for snprintf
#include <cinttypes> // for PRId64 et.al.

#include "libtorrent/aux_/array.hpp"
#include "libtorrent/aux_/escape_string.hpp"
#include "libtorrent/http_tracker_connection.hpp"
#include "libtorrent/parse_url.hpp"
#include "libtorrent/tracker_manager.hpp"
#include "libtorrent/i2p_stream.hpp"
#include "libtorrent/string_util.hpp"
#include "libtorrent/string_view.hpp"

namespace libtorrent::aux {

http_tracker_request_common::error_type http_tracker_request_common::validate_socket(bool i2p) const
{
	// i2p trackers don't use our outgoing sockets, they use the SAM connection
	if (!i2p && !req.outgoing_socket)
	{
		return {errors::invalid_listen_socket, operation_t::get_interface
			, "outgoing socket was closed"};
	}
	return {};
}

std::string http_tracker_request_common::get_user_agent() const
{
	// in anonymous mode we omit the user agent to mitigate fingerprinting of
	// the client. Private torrents is an exception because some private
	// trackers may require the user agent
	bool const anon_user = settings.get_bool(settings_pack::anonymous_mode)
		&& !req.private_torrent;
	return anon_user
		? "curl/7.81.0"
		: settings.get_str(settings_pack::user_agent);
}

seconds32 http_tracker_request_common::get_timeout() const
{
	const auto timeout = req.event == event_t::stopped
		? settings.get_int(settings_pack::stop_tracker_timeout)
		: settings.get_int(settings_pack::tracker_completion_timeout);
	return seconds32{timeout};
}

http_tracker_request_common::error_type http_tracker_request_common::process_response(
	request_callback& cb,
	const address& tracker_ip,
	const std::list<address>& ip_list,
	const span<char const> data) const
{
	error_code ecode;
	tracker_response resp = parse_tracker_response(data, ecode, req.kind, req.info_hash);

	resp.interval = std::max(resp.interval,
		seconds32{settings.get_int(settings_pack::min_announce_interval)});

	// this check is normally performed in tracker_connection::fail_impl
	if (resp.interval == seconds32{0})
		resp.interval = resp.min_interval;

	if (!resp.warning_message.empty())
		cb.tracker_warning(req, resp.warning_message);

	if (ecode)
	{
		return {ecode,
			operation_t::bittorrent,
			resp.failure_reason,
			resp.interval};
	}

	// do slightly different things for scrape requests
	if (req.kind & tracker_request::scrape_request)
	{
		cb.tracker_scrape_response(req, resp.complete
			, resp.incomplete, resp.downloaded, resp.downloaders);
	}
	else
	{
		cb.tracker_response(req, tracker_ip, ip_list, resp);
	}

	return {};
}

#ifndef TORRENT_DISABLE_LOGGING
void http_tracker_request_common::log_request(request_callback& cb, const std::string& url) const
{
	cb.debug_log("==> TRACKER_REQUEST [ url: %s ]", url.c_str());
}
#endif

std::string http_tracker_request_common::build_tracker_url(bool i2p, error_type& error) const
{
	std::string url = req.url;

	if (req.kind & tracker_request::scrape_request)
	{
		// find and replace "announce" with "scrape"
		// in request
		std::size_t pos = url.find("announce");
		if (pos == std::string::npos) {
			error.code = errors::scrape_not_available;
			return {};
		}
		url.replace(pos, 8, "scrape");
	}

	// if request-string already contains
	// some parameters, append an ampersand instead
	// of a question mark
	auto const arguments_start = url.find('?');
	if (arguments_start != std::string::npos)
	{
		// tracker URLs that come pre-baked with query string arguments will be
		// rejected when SSRF-mitigation is enabled
		bool const ssrf_mitigation = settings.get_bool(settings_pack::ssrf_mitigation);
		if (ssrf_mitigation && has_tracker_query_string(string_view(url).substr(arguments_start + 1)))
		{
			error.code = errors::ssrf_mitigation;
			return {};
		}
		url += "&";
	}
	else
	{
		url += "?";
	}

	url += "info_hash=";
	url += lt::escape_string({req.info_hash.data(), 20});

	if (!(req.kind & tracker_request::scrape_request))
	{
		static array<const char*, 4> const event_string{{{"completed", "started", "stopped", "paused"}}};

		char str[1024];
		std::snprintf(str, sizeof(str)
			, "&peer_id=%s"
			"&port=%d"
			"&uploaded=%" PRId64
			"&downloaded=%" PRId64
			"&left=%" PRId64
			"&corrupt=%" PRId64
			"&key=%08X"
			"%s%s" // event
			"&numwant=%d"
			"&compact=1"
			"&no_peer_id=1"
			, lt::escape_string({req.pid.data(), 20}).c_str()
			// the i2p tracker seems to verify that the port is not 0,
			// even though it ignores it otherwise
			, req.listen_port
			, req.uploaded
			, req.downloaded
			, req.left
			, req.corrupt
			, req.key
			, (req.event != event_t::none) ? "&event=" : ""
			, (req.event != event_t::none) ? event_string[static_cast<int>(req.event) - 1] : ""
			, req.num_want);
		url += str;
#if !defined TORRENT_DISABLE_ENCRYPTION
		if (settings.get_int(settings_pack::in_enc_policy) != settings_pack::pe_disabled
			&& settings.get_bool(settings_pack::announce_crypto_support))
			url += "&supportcrypto=1";
#endif
		if (settings.get_bool(settings_pack::report_redundant_bytes))
		{
			url += "&redundant=";
			url += libtorrent::to_string(req.redundant).data();
		}
		if (!req.trackerid.empty())
		{
			url += "&trackerid=";
			url += lt::escape_string(req.trackerid);
		}

#if TORRENT_USE_I2P
		if (i2p && req.i2pconn)
		{
			if (req.i2pconn->local_endpoint().empty())
			{
				error.code = errors::no_i2p_endpoint;
				error.failure_reason = "Waiting for i2p acceptor from SAM bridge";
				error.interval = seconds32(5);
				return {};
			}
			else
			{
				url += "&ip=" + req.i2pconn->local_endpoint () + ".i2p";
			}
		}
		else
#endif
			if (!settings.get_bool(settings_pack::anonymous_mode))
			{
				std::string const& announce_ip = settings.get_str(settings_pack::announce_ip);
				if (!announce_ip.empty())
				{
					url += "&ip=" + lt::escape_string(announce_ip);
				}
			}
	}

	if (!req.ipv4.empty() && !i2p)
	{
		for (auto const& v4 : req.ipv4)
		{
			std::string const ip = v4.to_string();
			url += "&ipv4=";
			url += lt::escape_string(ip);
		}
	}
	if (!req.ipv6.empty() && !i2p)
	{
		for (auto const& v6 : req.ipv6)
		{
			std::string const ip = v6.to_string();
			url += "&ipv6=";
			url += lt::escape_string(ip);
		}
	}

	return url;
}
}
