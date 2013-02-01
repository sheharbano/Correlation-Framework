@load data.bro
@load correlation.bro

module Correlation;

## This event can be called either because $every interval has elapsed
## (in which case rule_matched would be False) or because the correlation
## rule for an index matched. In the latter case, if logging is enabled as 
## specified by Filter$log, then results will be logged. In either case 
## info about that index will be reset. The approach used for $every here
## is essentially equivalent to having a create_expire=Filter$every 
event Correlation::log_it(filter: Filter, idx: Index, rule_matched: bool)
	{
	if ( filter$log && rule_matched )
		{
		local id = filter$id;
		local name = filter$name;
		local correlation_tbl = store[id, name];
		local val = correlation_tbl[idx];

		write_log(network_time(), id, name, idx, val$begin, val$end, val$str_history);
		}
	
	reset(filter,idx);

	schedule filter$every { Correlation::log_it(filter, idx, F) };
	}
	
	
function data_added(filter: Filter, index: Index, val: Val, hist_tb: table[string] of StreamData)
	{
	## gotta check correlation rule here
	local rule_matched = Parser::parse( filter$parser, val$history, hist_tb );
	if ( rule_matched )
		{ 
		# Flatten val$history to a string and include in Correlation::Val
		local str_history = "";
		for ( idx in val$history )
			{		
			str_history+= fmt("%d%s:",val$history[idx]$times_seen, val$history[idx]$stream_name);
			} 
		val$str_history = str_history;

		filter$correlated(index,val);
		event Correlation::log_it(filter,index,T);
		}
	}

