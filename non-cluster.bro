@load correlation/data.bro
@load correlation/correlation.bro

module Correlation;


function history_to_str( history: vector of HistoryVal, use_alt_name: bool ): string
	{
	local str_history = "";
	local name = "";

	# Flatten val$history to a string and include in Correlation::Val
	for ( i in history )
		{
		name = use_alt_name? history[i]$alt_name: history[i]$stream_name; 	
		str_history+= fmt("%d%s:",history[i]$times_seen, name);
		}
	return str_history; 
	}

## This event can be called either because $every interval has elapsed
## (in which case rule_matched would be False) or because the correlation
## rule for an index matched. In the latter case, if logging is enabled as 
## specified by Filter$log, then results will be logged. In either case 
## info about that index will be reset. The approach used for $every here
## is essentially equivalent to having a create_expire=Filter$every 
event Correlation::log_it(filter: Filter, index: Index, rule_matched: bool)
	{
	if ( filter$log && rule_matched )
		{
		local id = filter$id;
		local name = filter$name;
		local correlation_tbl = store[id, name];
		local val: Correlation::Val;

		## It's horizontal correlation
		if ( filter$filter_type == "horizontal" )
			{ 
			for ( idx in correlation_tbl )
				{
				val = correlation_tbl[idx];
				val$str_history = history_to_str( val$history, filter$alt_name_in_history );
				if ( val$hz_correlated )
					write_log(network_time(), id, name, idx, val$begin, val$end, val$str_history, filter$hz_id);
				}
			}	
		else
			{
			val = correlation_tbl[index];
			write_log(network_time(), id, name, index, val$begin, val$end, val$str_history, 0);
			}
		}
	
	reset(filter,index);
	schedule filter$every { Correlation::log_it(filter, index, F) };
	}

	
function data_added(filter: Filter, index: Index, val: Val, hist_tb: table[string] of StreamData)
	{
	local str_history = "";
	local name = "";
	
	if ( filter$filter_type == "horizontal" && val$hz_correlated )
		return;

	## check vertical correlation rule here
	local rule_matched = Parser::parse( filter$parser, val$history, hist_tb );
		
	if ( rule_matched )	
		{ 
		if ( filter$filter_type == "horizontal" )
			{
			val$hz_correlated = T;
			++filter$hz_matches;
			if ( filter$hz_matches <= filter$horizontal_threshold )
				return;
			}
				
		val$str_history = history_to_str( val$history, filter$alt_name_in_history );

		if ( filter?$correlated )
			filter$correlated(index,val);

		event Correlation::log_it(filter,index,T);			
		}
	}


