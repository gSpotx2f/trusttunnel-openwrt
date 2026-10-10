#!/bin/sh

TTC="/usr/bin/trusttunnel_client"
if [ ! -x "$TTC" ]; then
	logger -t "trusttunnel" -p "user.error" "error: missing trusttunnel_client (${TTC})"
	exit 1
fi
TTW="/usr/bin/trusttunnel-wrapper"
if [ ! -x "$TTW" ]; then
	logger -t "trusttunnel" -p "user.error" "error: missing trusttunnel-wrapper (${TTW})"
	exit 1
fi
TT_TMP_DIR="/tmp/trusttunnel"

[ -n "$INCLUDE_ONLY" ] || {
	. /lib/functions.sh
	. ../netifd-proto.sh
	init_proto "$@"
}

toml_array_from_string() {
	printf "$1" | awk 'END {s=""; for(i=1;i<=NF;i++){s=sprintf("%s%s\"%s\"", s, (i>1 ? "," : ""), $i)}; printf "["s"]"}'
}

toml_bool_from_string() {
	[ "$1" = "1" ] && { printf "true"; return; }
	printf "false"
}

proto_trusttunnel_init_config() {
	proto_config_add_string "loglevel"
	proto_config_add_string "vpn_mode"
	proto_config_add_string "killswitch_enabled"
	proto_config_add_array "killswitch_allow_ports"
	proto_config_add_string "post_quantum_group_enabled"
	proto_config_add_string "exclusions_tcp_early_ack_enabled"
	proto_config_add_string "exclusions_preresolve_enabled"
	proto_config_add_string "exclusions_preresolve_max_queries"
	proto_config_add_string "exclusions_scannable_ports"
	proto_config_add_array "exclusions"
	proto_config_add_string "hostname"
	proto_config_add_array "addresses"
	proto_config_add_string "custom_sni"
	proto_config_add_string "has_ipv6"
	proto_config_add_string "username"
	proto_config_add_string "password"
	proto_config_add_string "client_random"
	proto_config_add_string "skip_verification"
	proto_config_add_string "upstream_protocol"
	proto_config_add_string "tls_profile"
	proto_config_add_string "anti_dpi"
	proto_config_add_array "dns_upstreams"
	proto_config_add_array "included_routes"
	proto_config_add_string "mtu_size"
	proto_config_add_string "tcp_recv_buf_size"
	proto_config_add_string "tcp_send_buf_size"
	proto_config_add_string "proto_run_attempts"
	proto_config_add_string "proto_run_timeout_1"
	proto_config_add_string "proto_run_timeout_2"
	proto_config_add_string "interface_dependency"
	no_device=1
	available=1
}

proto_trusttunnel_setup() {
	local config="$1"
	local tt_cfg="${TT_TMP_DIR}/${config}"

	local loglevel
	local vpn_mode
	local killswitch_enabled
	local killswitch_allow_ports
	local post_quantum_group_enabled
	local exclusions_tcp_early_ack_enabled
	local exclusions_preresolve_enabled
	local exclusions_preresolve_max_queries
	local exclusions_scannable_ports
	local exclusions
	local hostname
	local addresses
	local custom_sni
	local has_ipv6
	local username
	local password
	local client_random
	local skip_verification
	local upstream_protocol
	local tls_profile
	local anti_dpi
	local dns_upstreams
	local included_routes
	local mtu_size
	local tcp_recv_buf_size
	local tcp_send_buf_size
	local proto_run_attempts
	local proto_run_timeout_1
	local proto_run_timeout_2
	local interface_dependency

	json_get_vars \
		loglevel \
		vpn_mode \
		killswitch_enabled \
		post_quantum_group_enabled \
		exclusions_tcp_early_ack_enabled \
		exclusions_preresolve_enabled \
		exclusions_preresolve_max_queries \
		exclusions_scannable_ports \
		hostname \
		custom_sni \
		has_ipv6 \
		username \
		password \
		client_random \
		skip_verification \
		upstream_protocol \
		tls_profile \
		anti_dpi \
		mtu_size \
		tcp_recv_buf_size \
		tcp_send_buf_size \
		proto_run_attempts \
		proto_run_timeout_1 \
		proto_run_timeout_2 \
		interface_dependency

	json_get_values killswitch_allow_ports killswitch_allow_ports
	json_get_values exclusions exclusions
	json_get_values addresses addresses
	json_get_values dns_upstreams dns_upstreams
	json_get_values included_routes included_routes

	local device_name="$config"

	[ -n "$proto_run_attempts" ] || proto_run_attempts=30
	[ -n "$proto_run_timeout_1" ] || proto_run_timeout_1=10
	[ -n "$proto_run_timeout_2" ] || proto_run_timeout_2=60

	local endpoint_cert_file="/etc/trusttunnel/endpoint-cert-${device_name}.pem"
	local endpoint_cert=
	[ -s "$endpoint_cert_file" ] && {
		endpoint_cert=$(cat "$endpoint_cert_file")
	}

	umask 077
	mkdir -p "${TT_TMP_DIR}"
	printf "" > "$tt_cfg"
	[ -n "$loglevel" ] && { printf "loglevel = \"%s\"\n" "$loglevel" >> "$tt_cfg"; }
	[ -n "$vpn_mode" ] || vpn_mode="general"
	printf "vpn_mode = \"%s\"\n" "$vpn_mode" >> "$tt_cfg"
	[ -n "$killswitch_enabled" ] && { printf "killswitch_enabled = %s\n" $(toml_bool_from_string "$killswitch_enabled") >> "$tt_cfg"; }
	[ -n "$killswitch_allow_ports" ] && { printf "killswitch_allow_ports = %s\n" $(toml_array_from_string "$killswitch_allow_ports") >> "$tt_cfg"; }
	[ -n "$post_quantum_group_enabled" ] && { printf "post_quantum_group_enabled = %s\n" $(toml_bool_from_string "$post_quantum_group_enabled") >> "$tt_cfg"; }
	[ -n "$exclusions_tcp_early_ack_enabled" ] && { printf "exclusions_tcp_early_ack_enabled = %s\n" $(toml_bool_from_string "$exclusions_tcp_early_ack_enabled") >> "$tt_cfg"; }
	[ -n "$exclusions_preresolve_enabled" ] && { printf "exclusions_preresolve_enabled = %s\n" $(toml_bool_from_string "$exclusions_preresolve_enabled") >> "$tt_cfg"; }
	[ -n "$exclusions_preresolve_max_queries" ] && { printf "exclusions_preresolve_max_queries = %s\n" "$exclusions_preresolve_max_queries" >> "$tt_cfg"; }
	[ -n "$exclusions_scannable_ports" ] && { printf "exclusions_scannable_ports = \"%s\"\n" "$exclusions_scannable_ports" >> "$tt_cfg"; }
	[ -n "$exclusions" ] && { printf "exclusions = %s\n" $(toml_array_from_string "$exclusions") >> "$tt_cfg"; }
	printf "[endpoint]\n" >> "$tt_cfg"
	[ -n "$addresses" ] && { printf "addresses = %s\n" $(toml_array_from_string "$addresses") >> "$tt_cfg"; }
	[ -n "$username" ] && { printf "username = \"%s\"\n" "$username" >> "$tt_cfg"; }
	[ -n "$password" ] && { printf "password = \"%s\"\n" "$password" >> "$tt_cfg"; }
	[ -n "$hostname" ] && { printf "hostname = \"%s\"\n" "$hostname" >> "$tt_cfg"; }
	[ -n "$upstream_protocol" ] || upstream_protocol="http2"
	printf "upstream_protocol = \"%s\"\n" "$upstream_protocol" >> "$tt_cfg"
	[ -n "$skip_verification" ] && { printf "skip_verification = %s\n" $(toml_bool_from_string "$skip_verification") >> "$tt_cfg"; }
	[ -n "$endpoint_cert" ] && { printf "certificate = \"\"\"\n%s\n\"\"\"\n" "$endpoint_cert" >> "$tt_cfg"; }
	[ -n "$custom_sni" ] && { printf "custom_sni = \"%s\"\n" "$custom_sni" >> "$tt_cfg"; }
	[ -n "$client_random" ] && { printf "client_random = \"%s\"\n" "$client_random" >> "$tt_cfg"; }
	[ -n "$tls_profile" ] && { printf "tls_profile = \"%s\"\n" "$tls_profile" >> "$tt_cfg"; }
	[ -n "$anti_dpi" ] && { printf "anti_dpi = %s\n" $(toml_bool_from_string "$anti_dpi") >> "$tt_cfg"; }
	[ -n "$has_ipv6" ] && { printf "has_ipv6 = %s\n" $(toml_bool_from_string "$has_ipv6") >> "$tt_cfg"; }
	[ -n "$dns_upstreams" ] && { printf "dns_upstreams = %s\n" $(toml_array_from_string "$dns_upstreams") >> "$tt_cfg"; }
	printf "[listener.tun]\n" >> "$tt_cfg"
	[ -n "$mtu_size" ] && { printf "mtu_size = %s\n" "$mtu_size" >> "$tt_cfg"; }
	[ -n "$tcp_recv_buf_size" ] && { printf "tcp_recv_buf_size = %s\n" "$tcp_recv_buf_size" >> "$tt_cfg"; }
	[ -n "$tcp_send_buf_size" ] && { printf "tcp_send_buf_size = %s\n" "$tcp_send_buf_size" >> "$tt_cfg"; }
	printf "included_routes = []\n" >> "$tt_cfg";
	printf "excluded_routes = []\n" >> "$tt_cfg";
	printf "change_system_dns = false\n" >> "$tt_cfg";
	printf "device_name = %s\n" "\"$device_name\"" >> "$tt_cfg";
	printf "use_existing = false\n" >> "$tt_cfg";

	[ -n "$interface_dependency" ] && {
		local trials=5
		local tmpfile="${TT_TMP_DIR}/ip.tmp"
		local addr ipaddr

		for addr in $addresses; do
			local server=$(printf "$addr" | awk -F ":" '{printf $1}')
			logger -t "trusttunnel" -p "user.notice" "adding host dependency for $server at $config"
			while ! resolveip -t 10 "$server" > "$tmpfile" && [ "$trials" -gt 0 ]; do
				sleep 5
				trials=$((trials - 1))
			done
			if [ -s "$tmpfile" ]; then
				for ipaddr in $(cat "$tmpfile"); do
					logger -t "trusttunnel" -p "user.notice" "adding host dependency for $ipaddr at $config"
					proto_add_host_dependency "$config" "$ipaddr" "$interface_dependency"
				done
			fi
			rm -f "$tmpfile"
		done
	}

	### For trusttunnel-wrapper
	proto_export INCLUDED_ROUTES="$included_routes"

	logger -t "trusttunnel" -p "user.notice" "executing '${TTC} -c ${tt_cfg}'"
	proto_run_command "$config" "$TTW" $proto_run_attempts $proto_run_timeout_1 $proto_run_timeout_2 "$config" "$device_name" "${TTC} -c ${tt_cfg}"
}

proto_trusttunnel_teardown() {
	local config="$1"
	local tt_cfg="${TT_TMP_DIR}/${config}"
	local device_name="$config"

	logger -t "trusttunnel" -p "user.notice" "bringing down trusttunnel"
	proto_kill_command "$config" 2

	rm -f "$tt_cfg"
}

[ -n "$INCLUDE_ONLY" ] || {
	add_protocol trusttunnel
}
