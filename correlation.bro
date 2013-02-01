##! The correlation framework facilitates correlating various activities.  

@load data.bro
@load parser.bro
@load tokenizer.bro
@load parser_order.bro
@load parser_expr.bro


module Correlation;

export {
	## The correlation logging stream identifier.
	redef enum Log::ID += { LOG };
	
	## The default interval used for "breaking" correlation and writing the 
	## current values to the logging stream.
	const default_break_interval = 15mins &redef;

	## Type of Correlation::Index$str
	type StrType: enum {
		## A complete URL without the prefix "http://".
		URL,
		## User-Agent string, typically HTTP or mail message body.
		USER_AGENT,
		## Email address.
		EMAIL,
		## DNS domain name.
		DOMAIN,
		## A user name.
		USER_NAME,
		## File hash which is non-hash type specific.  It's up to the user to query
		## for any relevant hash types.
		FILE_HASH,
		## Certificate SHA-1 hash.
		CERT_HASH,
	};

	## Represents the item for which the correlation is taking place.  An instance
	## of this record type and an id together represent a single correlation item.
	type Index: record {
		## The IP address if the correlation item is an IP address.
		host:        addr           &optional;
		## The network if the correlation item is a CIDR block.
		net:         subnet         &optional;
		## The string if the correlation item is a string.
		str:         string         &optional;
		## The type of data that is in the string if the $str field is set.
		str_type:    StrType        &optional;
	}&log;


	## Value supplied when the correlation finishes, either because the observation 
	## interval expired, or the correlation condition was met.  It contains 
	## interesting information collected for the correlation item.
	type Val: record {
		## The time when the correlation was first started.
		begin:    time          &optional;

		## The time when the last value was added to this result.
		end:      time          &optional;

		## internal: A table to keep Stream Data for this index
		history_tb: 	table[string] of StreamData &default=table();

		## Internal: The last stream received for this Index
		## This information helps us construct the 
		## history field in Val
		last_stream:         string      &default="";

		## A string representing the order in which different correlation 
		## streams were observed, e.g. 2A:1B:3D 
		history:	vector of HistoryVal	&optional;

		## A string representing the order in which different correlation 
		## streams were observed, e.g. 2A:1B:3D 
		str_history:	string	&optional;
	};

	## The record type that is used for logging correlation.
	type Info: record {
		## Timestamp at which the correlation was "broken".
		ts:           time     &log;
		## The correlation ID
		correlation_id:	  string     &log;
		## The name of the filter being logged.  Values
		## can have multiple filters which represent different perspectives on
		## the data so this is necessary to understand the value.
		filter_name:  string   &log;
		## What the correlation value applies to.
		index:        string    &log;
		## When was the first stream seen for this correlation item
		start:     time	       &log;
		## When was the last stream seen for this correlation item
		end:     time	       &log;
		## The value of Correlation::Val$history.
		history:        string    &log;
	};

	## Filters define how the data for a correlation item is correlated.  
	## Filters can be used to set how often the correlation is cut 
	## and logged or how the data within them is related.  It's also 
	## possible to disable logging and use filters solely for correlation.
	type Filter: record {
		## The name for this filter so that multiple filters can be
		## applied to a single correlation item to get a different view of the same
		## correlation streams (different correlation condition, break, etc).
		name:              string                   &default="default";
		## The correlation item that this filter applies to.
		id:                string                   &optional;
		## A predicate so that you can decide per index if you would like
		## to accept the data being inserted.
		pred:              function(index: Correlation::Index, name: string): bool &optional;
		## The interval at which this filter should be "broken" and written
		## to the logging stream.  The correlation streams are also reset at 
		## this time to start afresh.
		every:             interval                 &default=default_break_interval;
		## This determines if the results should be logged when correlation rule
		## yields true.
		log:               bool                     &default=T;
		## A predicate so that you can flexibly define what to do next when
                ## a new correlation stream is fed to the framework. Any correlation
		## conditions should be implemented here
		##! I intedn to do away with this  
		new_stream_func:    function(index: Correlation::Index, val: Correlation::Val): bool &optional;
		## A function callback that is called when the correlation conditions are met
		correlated: function(index: Correlation::Index, val: Correlation::Val) &optional;
		## A correlation rule in the format [order];[join];expression). 
		## Note that order and join both must be present or absent.
		rule:		string;
		## Used internally to parse $rule
		parser:		Parser::Parser	&optional;
	};
	
	## Function to associate a correlation_filters filter with a correlation_filters ID.
	## 
	## id: The correlation_filters ID that the filter should be associated with.
	##
	## filter: The record representing the filter configuration.
	global add_correlation_item: function(id: string, filter: Correlation::Filter): bool;
	
	## Add data into a correlation_filter.  This should be called when
	## a new correlation stream is observed, e.g. upon observing an event or
	## a notice, or because the value of a variable exceeded a threshold
	##
	## id: The correlation_filter identifier that the data represents.
	##
	## index: The correlation_filters index that the value is to be added to.
	global add_stream: function(id: string, filter_name: string, index: Correlation::Index, name: string, weight: double );
		 
	## Event to access correlation_filter records as they are passed to the logging framework.
	global log_correlation_filters: event(rec: Correlation::Info);
}

# Type to store a table of correlation_filter values.
type CorrelationTable: table[Index] of Val;

# This is indexed by correlation_filter id and filter name.
global store: table[string, string] of CorrelationTable = table() &default=table();

# Store the filters indexed on the correlation_filter identifier.
global correlation_filters: table[string] of vector of Filter = table();

# Store the filters indexed on the correlation_filters identifier and filter name.
#global filter_store: table[string, string] of Filter = table();

# It is called whenever correlation streams are updated and the new val is given as 
# the `val` argument.
# It's only prototyped here because cluster and non-cluster has separate 
# implementations.
global data_added: function(filter: Filter, index: Index, val: Val, hist_tb: table[string] of StreamData);

## Event that is used to "finish" correlation_filters and adapt the correlation_filters
## framework for clustered or non-clustered usage.
global log_it: event(filter: Filter, idx: Index, rule_matched: bool);


event bro_init() &priority=5
	{
	Log::create_stream(Correlation::LOG, [$columns=Info, $ev=log_correlation_filters]);
	}
	## Represents the item for which the correlation is taking place.  An instance
	## of this record type and an id together represent a single correlation item.
	type Index: record {
		## The IP address if the intelligence is about an IP address.
		host:        addr           &optional;
		## The network if the intelligence is about a CIDR block.
		net:         subnet         &optional;
		## The string if the intelligence is about a string.
		str:         string         &optional;
		## The type of data that is in the string if the $str field is set.
		str_type:    StrType        &optional;
	}&log;
	
function index2str(index: Index): string
	{
	local out = "";
	if ( index?$host )
		out = fmt("%shost=%s", out, index$host);
	if ( index?$net )
		out = fmt("%s%snetwork=%s", out, |out|==0 ? "" : ", ", index$net);
	if ( index?$str )
		out = fmt("%s%sstr=%s", out, |out|==0 ? "" : ", ", index$str);
	if ( index?$str )
		out = fmt("%s%sstr_type=%s", out, |out|==0 ? "" : ", ", index$str_type);

	return fmt("correlation_index(%s)", out);
	}

	
function reset(filter: Filter, index: Index)
	{
	delete store[filter$id, filter$name][index];
	}

function add_correlation_item(id: string, filter: Filter): bool
	{
	if ( [id, filter$name] in store )
		{
		Reporter::warning(fmt("invalid Correlation filter (%s): Filter with same name already exists.", filter$name));
		return F;
		}
	filter$parser = Parser::init(filter$rule);

	if ( !filter$parser$initialized )
		return F;

	if ( ! filter?$id )
		filter$id = id;
	
	if ( id !in correlation_filters )
		correlation_filters[id] = vector();
	correlation_filters[id][|correlation_filters[id]|] = filter;

	#filter_store[id, filter$name] = filter;
	store[id, filter$name] = table();

	return T;
	}

function add_stream(id: string, filter_name: string, index: Correlation::Index, name: string, weight: double )
	{
	if ( id !in correlation_filters )
		return;
	
	local filters = correlation_filters[id];

	# Try to add the data to all of the defined filters for the correlation_filters.
	for ( filter_id in filters )
		{
		local filter = filters[filter_id];
		
		# If this filter has a predicate, run the predicate and skip this
		# index if the predicate returns false.
		if ( filter?$pred && ! filter$pred(index, name) )
			next;
		
		local correlation_tbl = store[id, filter$name];
		
		if ( index !in correlation_tbl )
			{
			local hist_tb: table[string] of StreamData;
			local v: vector of HistoryVal;
			hist_tb[name] = [ $times_seen=0, $weight=weight ];
			correlation_tbl[index] = [ $begin=network_time(), $end=network_time(), 
							$history=v, $history_tb=hist_tb ];
			}


		local val = correlation_tbl[index];
		if ( name !in val$history_tb )
			val$history_tb[ name ] = [ $times_seen=0, $weight=0.0 ];
		local hist = val$history_tb[ name ];

		hist$times_seen+=1;
		# If the newly reported stream has greater weight
		# than the last time the same stream was reported, 
		# consider the higher weight
		if ( weight > hist$weight )
			hist$weight = weight;
		
		# If last_stream was not the current stream,
		# update history. e.g. history won't  be updated 
		# if we receive <Stream1Stream1Stream1>, but when 
		# we receive a different stream and the sequence 
		# looks like <Stream1Stream1Stream1Stream2>, we will
		# update $history (history+=3Stream1). 
		if ( name != val$last_stream ) 
			{
			if ( val$last_stream == "" )
				val$history[1] = [ $stream_name=name, $times_seen=0 ];
			else
				val$history[|val$history|] = [ $stream_name=name, $times_seen=0 ];		
			#print fmt("Last stream: %s New stream: %s",val$last_stream,name);	
			#print fmt("History: %s",val$history);
			#print "-----------------------------";	
			}

		val$last_stream = name;
		++val$history[|val$history|-1]$times_seen;

		# Continually update the $end field.
		val$end=network_time();

		schedule filter$every { Correlation::log_it(filter, index, F) };

		data_added(filter, index, val, val$history_tb);
		}
	}

function write_log(ts: time, corr_id: string, filt_name: string, idx: Index, 
			start: time, end: time, history: string)
	{
	local m: Info = [$ts=ts,
	                 $correlation_id=corr_id,
	                 $filter_name=filt_name,
	                 $index=index2str(idx),
			 $start=start,
			 $end=end,
	                 $history=history];
		
		
	Log::write(Correlation::LOG, m);	
	}
		

## To-do\
## Interface for removing a filter
## extensible enum structures
## what is &log

