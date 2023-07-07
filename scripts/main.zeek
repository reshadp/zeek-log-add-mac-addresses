##! Add link-layer address (MAC) to all logs with an "id" field.

module reshadp;

redef record conn_id += {
	## Link-layer address of the originator, if available.
	orig_l2_addr:	string &log &optional;

	## Link-layer address of the responder, if available.
	resp_l2_addr:	string &log &optional;
};

# Add the link-layer addresses to the conn_id record.
event new_connection(c: connection) &priority=4
	{
	if ( c$orig?$l2_addr )
		c$id$orig_l2_addr = c$orig$l2_addr;

	if ( c$resp?$l2_addr )
		c$id$resp_l2_addr = c$resp$l2_addr;
	}
