-- Description: Get email addresses from domain WHOIS data
-- Version: 0.1.0
-- Source: domains
-- License: GPL-3.0

function run(arg)
	domain = arg['value']

	-- Get Whois server for domain querying whois.iana.org
	sock = sock_connect("whois.iana.org", 43)
	sock_sendline(sock, domain)
	x = sock_recvline_regex(sock, "^whois: ")
	server = x:match("%s%a.+"):sub(2,-2)
	if last_err() then
		error("Couldn't reach IANA whois server")
		return
	end

	--Querying TLD WHOIS
	sock = sock_connect(server, 43)
	sock_sendline(sock, domain)
	data = sock_recvall(sock)
	if last_err() then
		error("Couldn't reach TLD whois server")
		return
	end

	--check for registrar WHOIS
	registrarWhois = data:match("Registrar WHOIS Server: (%g+)%G")
	if registrarWhois ~= nil then
		--got registrat WHOIS, querying
		sock = sock_connect(registrarWhois, 43)
		sock_send(sock, domain.."\r\n")
		registrarData = sock_recvall(sock)
		if registrarData ~= "" then
			data = registrarData
		else
			error("Registrar whois query failed")
		end
	end
	for w in data:gmatch("%S+") do
		if w:match("^[%w.]+@[%w+%.]+%w+$") then
			id = db_add('email', {
				value=w,
			})
		end
	end

end
