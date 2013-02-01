##! This script tests the correlation framework 
##! As a basic example, we are trying to finds hosts that 
##! successfully establish a TCP connection after making a 
##! DNS query (correlation by order of events) 

@load correlation.bro
@load non-cluster.bro

## The record type that is used for logging correlation.
	
global queriers: set[addr];

function correlated_test1(index: Correlation::Index, val: Correlation::Val)
	{
	#print "We have reached the block that describes what to do when correlation conditions are met.";
	print val$str_history;
	print "===============================";
	}

event bro_init()
	{
	#local str_rule1 = ";;{(n$DNS_A_QUERY>2) & (n$SUCCESSFUL_CONN>0)}";
	#local str_rule2 = "{.SUCCESSFUL_CONN:.DNS_A_QUERY}; or ; {(n$DNS_A_QUERY>2) & (n$SUCCESSFUL_CONN>0)}";
	#local str_rule3 = "{4SUCCESSFUL_CONN:5DNS_A_QUERY}; ; ";
	local str_rule4 = "; ; {SUCCESSFUL_CONN & DNS_A_QUERY}";

	local done = Correlation::add_correlation_item("test1", [$name="first_filter",
	                                       $every=5mins,
					       $rule=str_rule4,
	                                       $correlated=correlated_test1]); 
	if ( !done )
		print "Correlation Framework Error: Failed to add filter.";
	}


# DNS query		
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	if(qtype==1)
		{
		local orig = c$id$orig_h;
		local resp = c$id$resp_h;

		add queriers[orig];

		local my_index: Correlation::Index;
		my_index = [$host=orig];

		Correlation::add_stream( "test1", "first_filter", my_index, "DNS_A_QUERY", 0.9 );	
		}
	
	}

event connection_established(c: connection)
	{
	local orig = c$id$orig_h; 
	if ( orig in queriers )
		{
		local my_index: Correlation::Index;
		my_index = [$host=orig];

		Correlation::add_stream( "test1", "first_filter", my_index, "SUCCESSFUL_CONN", 0.9 );	
		}
	}



