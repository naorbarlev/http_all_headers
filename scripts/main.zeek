module Http_all_headrs;

#module http_all_headrs;

# redef the Info record that will be logged out to http.log
# &log must be and &optional/&defulat should also be

redef record HTTP::Info += {
	#extnted headrs from orig
	orig_authorization: string &optional &log;
	orig_accept: string &optional &log;
	orig_host: string &optional &log;
	orig_referer: string &optional &log;
	orig_accept_language: string &optional &log;
	orig_connection: string &optional &log;
	orig_user_agent: string &optional &log;
	orig_cookie: string &optional &log;
	orig_accept_encoding: string &optional &log;
	orig_cache_control: string &optional &log;
	orig_if_modified_since: string &optional &log;
	orig_accept_charset: string &optional &log;

	#extended headrs from dest
	dest_cache_control: string &optional &log;
	dest_date: string &optional &log;
	dest_keep_alive: string &optional &log;
	dest_transfer_encoding: string &optional &log;
	dest_expires: string &optional &log;
	dest_server: string &optional &log;
	dest_pragma: string &optional &log;
	dest_content_type: string &optional &log;
	dest_connection: string &optional &log;

	###TODO in switch
	dest_www_authenticate: string &optional &log;
	dest_etag: string &optional &log; #ETag
	dest_vary: string &optional &log;
	dest_accept_ranges: string &optional &log;
	dest_content_length: string &optional &log;
	dest_last_modified: string &optional &log;
};

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
	{
	#if the packet is from orig
	if ( is_orig )
		{
		#print "-------orig------------";

		for ( key in hlist )
			{
			#print fmt("%s = %s ", hlist[key]$original_name, hlist[key]$value);

			#checks every key and assign the exact value from the record
			switch ( hlist[key]$original_name )
				{
				case "Authorization":
					c$http$orig_authorization = hlist[key]$value;
					break;
				case "User-Agent":
					c$http$orig_user_agent = hlist[key]$value;
					break;
				case "Accept":
					c$http$orig_accept = hlist[key]$value;
					break;
				case "Referer":
					c$http$orig_referer = hlist[key]$value;
					break;
				case "Accept-Encoding":
					c$http$orig_accept_encoding = hlist[key]$value;
					break;
				case "Accept-Language":
					c$http$orig_accept_language = hlist[key]$value;
					break;
				case "Cookie":
					c$http$orig_cookie = hlist[key]$value;
					break;
				case "Host":
					c$http$orig_host = hlist[key]$value;
					break;
				case "Connection":
					c$http$orig_connection = hlist[key]$value;
					break;
				case "Cache-Control":
					c$http$orig_cache_control = hlist[key]$value;
					break;
				case "If-Modified-Since":
					c$http$orig_if_modified_since = hlist[key]$value;
					break;
				case "Accept-Charset":
					c$http$orig_accept_charset = hlist[key]$value;
					break;

				default:
					break;
				}
			}
		}
	else
		{
		#print "-------dest------------";
		for ( key in hlist )
			{
			#print fmt("%s = %s ", hlist[key]$original_name, hlist[key]$value);

			#checks every key and assign the exact value from the record
			switch ( hlist[key]$original_name )
				{
				case "Expires":
					c$http$dest_expires = hlist[key]$value;
					break;

				case "Pragma":
					c$http$dest_pragma = hlist[key]$value;
					break;

				case "Cache-Control":
					c$http$dest_cache_control = hlist[key]$value;
					break;

				case "Keep-Alive":
					c$http$dest_keep_alive = hlist[key]$value;
					break;

				case "Connection":
					c$http$dest_connection = hlist[key]$value;
					break;

				case "Transfer-Encoding":
					c$http$dest_transfer_encoding = hlist[key]$value;
					break;

				case "Content-Type":
					c$http$dest_content_type = hlist[key]$value;
					break;

				case "Date":
					c$http$dest_date = hlist[key]$value;
					break;

				case "Server":
					c$http$dest_server = hlist[key]$value;
					break;

				case "WWW-Authenticate":
					c$http$dest_www_authenticate = hlist[key]$value;
					break;

				case "ETag":
					c$http$dest_etag = hlist[key]$value;
					break;

				case "Vary":
					c$http$dest_vary = hlist[key]$value;
					break;

				case "Accept-Ranges":
					c$http$dest_accept_ranges = hlist[key]$value;
					break;

				case "Content-Length":
					c$http$dest_content_length = hlist[key]$value;
					break;

				case "Last-Modified":
					c$http$dest_last_modified = hlist[key]$value;
					break;

				default:
					break;
				}
			}
		}
	}
