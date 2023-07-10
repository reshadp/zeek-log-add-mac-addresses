##! Add link-layer address (MAC) to file logs.

redef record Files::Info += {
	## Link-layer address of the originator, if available.
	orig_l2_addr:	string &log &optional;

	## Link-layer address of the responder, if available.
	resp_l2_addr:	string &log &optional;
};

# Add the link-layer addresses to the "Files::Info" record.
event file_sniff(f: fa_file, meta: fa_metadata)
	{
	if ( f?$conns )
		{
		for ( cid, c in f$conns )
			{
			if ( c$orig?$l2_addr )
				f$info$orig_l2_addr = c$orig$l2_addr;

			if ( c$resp?$l2_addr )
				f$info$resp_l2_addr = c$resp$l2_addr;
			# break after first connection object
			break;
			}
		}
	}
