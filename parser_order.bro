##! Deals with parsing the order part of the
##! correlation rule

@load utils.bro

module Parser;

export {
	## Structures related to order part of correlation rule
	## Processing states in which order parser can exist
	## NEXT: Fetch the next token
	## DOOPERATION: Ready to process tokens
	type order_state: enum { NEXT, DOOPERATION };
	## This table represents the yield of the table
	## Parser::order_syntax_rules 
	## Index: A valid token that can follow a token
	## Yield: the processing state that this combination
	##        of tokens takes the system into
	type OrderSyntaxInfo: table[string] of order_state;
	## A table that maintains syntax rules for order part of
	## the correlation rule
	## Index: A token
	## Yield: Set of valid tokens that can follow it
	global order_syntax_rules: table[string] of OrderSyntaxInfo;
}

function do_operation_order( cardinality: string, stream: string, any_index: bool ): bool
	{
	}


## This function parses and evaluates the order part of the 
## correlation rule
## returns: a boolean value that says whether or not the order 
##	    part of the correlation rule holds
function parse_order( arr_lexemes: vector of string, history: vector of HistoryVal ): bool
	{
	local idx_wildnum = 0;
	# A <cardinality><stream> pair e.g. 2SCAN
	local card_stream = "";
	# Points to the position in :arr_history: where
	# to start matching items of :arr_lexemes:   
	local hist_idx: int;
	hist_idx = 0;

	for ( each in arr_lexemes )
		{ 
		card_stream = arr_lexemes[each];

		# Check if cardinality is a WILDNUMBER
		idx_wildnum = strstr(card_stream,"."); 
		if( idx_wildnum == 1 )
			card_stream = subst_string (card_stream, ".", "");	
		
		# Haven't attempted to match anything yet
		if ( hist_idx == 0 )
			{
			for ( idx in history )
				{
				if ( idx_wildnum == 1 )
					{
					# Matched without regard to cardinality
					# e.g. .SCAN will match 1SCAN,2SCAN and so on
					if ( history[idx]$stream_name == card_stream )
						{
						hist_idx = idx;
						break;
						}  
					}
				else
					{
					# Exact match e.g. 2SCAN will only match for 2SCAN
					if ( card_stream == fmt("%d%s",history[idx]$times_seen,history[idx]$stream_name) )
						{	
						hist_idx = idx;
						break;
						}
					}
				}
				# The very first match failed, so exit right here
				if ( hist_idx == 0 )
					return F;			
			}
		# All iterations other than the first one come here
		else
			{
			# Set hist_idx to point to next position of history 
			++hist_idx;	
		
			if ( hist_idx < |history| )
				{ 
				if ( idx_wildnum == 1 )
					{ 
					if ( history[hist_idx]$stream_name != card_stream )
						return F;
					}
				else 
					{
					if ( card_stream != fmt("%d%s",history[hist_idx]$times_seen,history[hist_idx]$stream_name) )
						return F;
					}
				}
			# Exit if the index pointed to lies outside arr_history's
			# valid range of indices
			else
				return F;
			}	
		} 
	# Made it so far means that order stmt was
	# successfully matched against history
	return T;
	}

## This function checks syntax of the order part of a 
## correlation rule
## returns: a boolean indicating whether or not the syntax of 
##	    order part of the correlation rule is correct
function check_syntax_order( lexemes_order: vector of LexemeVal ): bool
	{
	local prev_token = "";
	local curr_token = "";
	local start = T;

	for ( idx in Parser::lexemes_order )
		{
		if ( start )
			{		
			prev_token = Parser::lexemes_order[idx]$token;
			start = F;
			}
		else
			{
			curr_token = Parser::lexemes_order[idx]$token;
			if ( curr_token !in order_syntax_rules[prev_token])
				{
				print fmt("Parser Error: %s cannot be followed by %s",prev_token,curr_token);
				return F;
				}
			prev_token = curr_token;
			}
		}
	return T;
	}


function init_order_syntax_rules()
	{
	# Initializing Parser::expr_syntax_rules
	local syntax_num: Parser::OrderSyntaxInfo;
	syntax_num["STREAM"]=Parser::DOOPERATION;
	order_syntax_rules["NUMBER"] = syntax_num;
	
	local syntax_stream: Parser::OrderSyntaxInfo;
	syntax_stream["SEPARATOR"]=Parser::NEXT;
	order_syntax_rules["STREAM"] = syntax_stream;

	local syntax_sep: Parser::OrderSyntaxInfo;
	syntax_sep["NUMBER"]=Parser::NEXT;
	syntax_sep["WILDSTREAM"]=Parser::NEXT;
	syntax_sep["WILDNUMBER"]=Parser::NEXT;
	order_syntax_rules["SEPARATOR"] = syntax_sep;

	local syntax_wnum: Parser::OrderSyntaxInfo;
	syntax_wnum["STREAM"]=Parser::DOOPERATION;	
	order_syntax_rules["WILDNUMBER"] = syntax_wnum;

	local syntax_wstream: Parser::OrderSyntaxInfo;
	syntax_wstream["SEPARATOR"]=Parser::NEXT;	
	order_syntax_rules["WILDSTREAM"] = syntax_wstream;	
	}


