## These data items should ideally be there in correlation.bro
## but I have to put them here because of circular dependencies
## with module Parser. (These are used by Parser and Correlation 
## loads Parser before its own execution)

## Data about a :bro:type:`Correlation::Stream`
type StreamData: record {
	## The number of times this stream was seen so far.
	times_seen:      count	&default=0;
	## The weight of the stream. Note that if the same
	## stream is reported multiple times with different
	## weights, the highest weight will be preferred.
	weight:	   double 	&default=0.0;	
};

## Represents the value of Correlation::Val$history
type HistoryVal: record {
	## Name of the correlation stream.
	stream_name:        string;
	## How many times it was seen.
	times_seen:         count         &default=0;
};
