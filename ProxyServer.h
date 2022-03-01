#pragma once
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjsip.h>
#include <pjsip_ua.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <iomanip>
#include <regex>
#include <ctime>

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
};

/* Proxy utility to verify incoming requests.
 * Return non-zero if verification failed.
 */
static pj_status_t proxy_verify_request(pjsip_rx_data* rdata)
{
	char text[] = "Proxy-Require";
	const pj_str_t STR_PROXY_REQUIRE = { text, 13 };

	if (!PJSIP_URI_SCHEME_IS_SIP(rdata->msg_info.msg->line.req.uri) &&
		!PJSIP_URI_SCHEME_IS_SIPS(rdata->msg_info.msg->line.req.uri))
	{
		pjsip_endpt_respond_stateless(global.endpt, rdata,
			PJSIP_SC_UNSUPPORTED_URI_SCHEME, NULL,
			NULL, NULL);
		return PJSIP_ERRNO_FROM_SIP_STATUS(PJSIP_SC_UNSUPPORTED_URI_SCHEME);
	}

	if (rdata->msg_info.max_fwd && rdata->msg_info.max_fwd->ivalue <= 1) {
		pjsip_endpt_respond_stateless(global.endpt, rdata,
			PJSIP_SC_TOO_MANY_HOPS, NULL,
			NULL, NULL);
		return PJSIP_ERRNO_FROM_SIP_STATUS(PJSIP_SC_TOO_MANY_HOPS);
	}

	if (pjsip_msg_find_hdr_by_name(rdata->msg_info.msg, &STR_PROXY_REQUIRE,
		NULL) != NULL)
	{
		pjsip_endpt_respond_stateless(global.endpt, rdata,
			PJSIP_SC_BAD_EXTENSION, NULL,
			NULL, NULL);
		return PJSIP_ERRNO_FROM_SIP_STATUS(PJSIP_SC_BAD_EXTENSION);
	}

	return PJ_SUCCESS;
}

static pj_status_t incomming_logger(pjsip_rx_data *rdata) {
	//log file
	try
	{
		std::ofstream log_file("voip_log.txt", std::ios_base::app);

		if (log_file.is_open() && log_file.good())
		{
			std::string from{ "undefined" };
			std::string to{ "undefined" };
			char buffer[1300];
			int len = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, rdata->msg_info.from->uri, buffer, sizeof(buffer) - 1);
			buffer[len] = '\0';
			if (len > 0)
			{
				from = std::string{ buffer, static_cast<unsigned>(len) };
			}
			auto cur_time = std::time(nullptr);
			len = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, rdata->msg_info.to->uri, buffer, sizeof(buffer) - 1);
			if (len > 0)
			{
				to = std::string{ buffer, static_cast<unsigned>(len) };
			}

			std::string id{ rdata->msg_info.cid->id.ptr , static_cast<size_t>(rdata->msg_info.cid->id.slen) };

			if (rdata->msg_info.msg->line.req.method.id == PJSIP_INVITE_METHOD)
			{
				log_file << std::put_time(std::localtime(&cur_time), "%y-%m-%d %OH:%OM:%OS") << " [INVITE] {ID: " + id + " } Calling : " + from + " ------> " + to << std::endl;
				log_file.flush();
				return PJ_FALSE;
			}

			if (rdata->msg_info.msg->line.req.method.id == PJSIP_BYE_METHOD)
			{
				log_file << std::put_time(std::localtime(&cur_time), "%y-%m-%d %OH:%OM:%OS") << " [BYE] {ID: " + id + " } Call ended by : " + from << std::endl;
				log_file.flush();
				return PJ_FALSE;
			}
		}
		return PJ_FALSE;
	}
	catch (std::exception& err)
	{
		std::cerr << err.what() << std::endl;
		return PJ_FALSE;
	}
}

//LOGGER MODULE
static char logger_mod_name[] = "logger";
static pjsip_module logger =
{
	nullptr, nullptr,
	{logger_mod_name, 6},
	-1,
	PJSIP_MOD_PRIORITY_TRANSPORT_LAYER -1,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	&incomming_logger,
	&incomming_logger,
	nullptr,
	nullptr,
	nullptr,
};
