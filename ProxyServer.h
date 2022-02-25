#pragma once
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjsip.h>
#include <pjsip_ua.h>
#include <iostream>
#include <vector>
#include <string>
#include <regex>

struct global_struct;

class Account
{
public:
	
	Account(pjsip_uri* uri, unsigned short port, std::string ip)
	{
		this->destination = uri;
		this->port = port;
		this->ip = ip;
		this->contact = std::string{ ((pjsip_sip_uri*)uri)->host.ptr, static_cast<size_t>(((pjsip_sip_uri*)uri)->host.slen) };
	}

	pjsip_uri* destination = nullptr;
	std::string contact;
	std::string ip;
	unsigned short port;

	pj_bool_t isEqual(pjsip_uri* uri)
	{
		if (pjsip_uri_cmp(PJSIP_URI_IN_CONTACT_HDR, this->destination, uri) == PJ_SUCCESS) return PJ_TRUE;
		return PJ_FALSE;
	}

	pj_bool_t isEqual(const std::string& sip)
	{
		return sip == contact;
	}
};

static struct global_struct
{
	pj_caching_pool	 cp;
	pjsip_endpoint* endpt;
	int			 port;
	pj_pool_t* pool;
	pj_thread_t* thread;
	pj_bool_t		 quit_flag;
	pj_bool_t		 record_route;
	unsigned		 name_cnt;
	pjsip_host_port	 name[16];
	std::vector<Account> registrar;
} global;

class ProxyServer
{

public:
	ProxyServer();
	~ProxyServer();
	
	//options
	

	pj_status_t initOptions();
private:
	pj_status_t initProxy();
	static int worker_thread(void* ptr);
};

/* Proxy utility to verify incoming requests.
 * Return non-zero if verification failed.
 */
static pj_status_t proxy_verify_request(pjsip_rx_data* rdata)
{
	char text[] = "Proxy-Require";
	const pj_str_t STR_PROXY_REQUIRE = { text, 13 };

	/* RFC 3261 Section 16.3 Request Validation */

	/* Before an element can proxy a request, it MUST verify the message's
	 * validity.  A valid message must pass the following checks:
	 *
	 * 1. Reasonable Syntax
	 * 2. URI scheme
	 * 3. Max-Forwards
	 * 4. (Optional) Loop Detection
	 * 5. Proxy-Require
	 * 6. Proxy-Authorization
	 */

	 /* 1. Reasonable Syntax.
	  * This would have been checked by transport layer.
	  */

	  /* 2. URI scheme.
	   * We only want to support "sip:"/"sips:" URI scheme for this simple proxy.
	   */
	if (!PJSIP_URI_SCHEME_IS_SIP(rdata->msg_info.msg->line.req.uri) &&
		!PJSIP_URI_SCHEME_IS_SIPS(rdata->msg_info.msg->line.req.uri))
	{
		pjsip_endpt_respond_stateless(global.endpt, rdata,
			PJSIP_SC_UNSUPPORTED_URI_SCHEME, NULL,
			NULL, NULL);
		return PJSIP_ERRNO_FROM_SIP_STATUS(PJSIP_SC_UNSUPPORTED_URI_SCHEME);
	}

	/* 3. Max-Forwards.
	 * Send error if Max-Forwards is 1 or lower.
	 */
	if (rdata->msg_info.max_fwd && rdata->msg_info.max_fwd->ivalue <= 1) {
		pjsip_endpt_respond_stateless(global.endpt, rdata,
			PJSIP_SC_TOO_MANY_HOPS, NULL,
			NULL, NULL);
		return PJSIP_ERRNO_FROM_SIP_STATUS(PJSIP_SC_TOO_MANY_HOPS);
	}

	/* 4. (Optional) Loop Detection.
	 * Nah, we don't do that with this simple proxy.
	 */

	 /* 5. Proxy-Require */
	if (pjsip_msg_find_hdr_by_name(rdata->msg_info.msg, &STR_PROXY_REQUIRE,
		NULL) != NULL)
	{
		pjsip_endpt_respond_stateless(global.endpt, rdata,
			PJSIP_SC_BAD_EXTENSION, NULL,
			NULL, NULL);
		return PJSIP_ERRNO_FROM_SIP_STATUS(PJSIP_SC_BAD_EXTENSION);
	}

	/* 6. Proxy-Authorization.
	 * Nah, we don't require any authorization with this sample.
	 */

	return PJ_SUCCESS;
}
