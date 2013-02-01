##! Some utility functions to used by correlation framework
@load stack.bro
@load tokenizer.bro

## This function converts order part of
## the correlation rule to a string
function get_lexeme_string( lexemes: vector of Parser::LexemeVal ): string
	{
	local str_lexemes = "";
	local val = "";

	for ( idx in lexemes )
		{
		val = lexemes[idx]$lexeme;
		str_lexemes+=val;
		}
	return str_lexemes;
	}

## A function that splits a string into a vector of strings (tokens)
## based on a separator of size 1
## to_split: the string to split
## separator: the one sized string (e.g. ":",";") to be used 
##		as a separator
## returns a vector of strings (tokens) 
## Note: The size of vector is always one more than the number of 
##       indices in it.
function string_to_vector( to_split: string, separator: string ): vector of string
	{
	local v: vector of string;
	local new_token = T;
	local idx = 0;

	for ( ch in to_split )
		{
		if ( new_token )
			{
			++idx;
			v[idx] = "";
			if ( ch != separator )
				v[idx]+=ch;
			new_token = F;
			}
		else
			if (ch!=separator)
				v[idx]+=ch;
			
		if (ch == separator)
			new_token = T;
		}
	return v;
	}



#========HACKY FUNCTIONS BEGIN========
# Bro does not have a while loop.
# I got around the problem by hacky use of 
# function recursion

## This function is called when Parser::convert_to_RPN() sees
## an operator. It peeks at top value of a stack and if the value
## is not an operator, it appends the value to :v: (starting at :idx:).
## It returns upon finding a non-operator value. Note that the non-op
## value is not popped as it is discovered by peeking.  
function Stack::get_stack_as_vector_till_op( s: Stack::Stack, v: vector of any, idx: int )
	{
	local ret = Stack::peek(s);

	if (type_name(ret)=="bool" )
		return;

	local r: Parser::LexemeVal;
	r = ret;

	if (r?$token && ( r$token != "MULTIPLY" && r$token != "ADD" && 
			r$token != "LOGICAL" && r$token != "MEMBERSHIP" && 
				r$token != "COMPARISON"  ) )
		return;

	if (idx >= 0)
		{
		r = Stack::pop(s);
		v[idx] = r;
		++idx;
		Stack::get_stack_as_vector_till_op(s,v,idx);
		}
	}

## This function is called when Parser::convert_to_RPN sees an 
## RPARANTHESIS. It pops stack values and appends them to :v:
## (starting at :idx:) until it encounters a LPARANTHESIS. Note
## that LPARANTHESIS is popped but not appended to :v:
function Stack::get_stack_as_vector_till_lparanthesis( s: Stack::Stack, v: vector of any, idx: int )
	{
	local ret = Stack::pop(s);

	if (type_name(ret)=="bool" )
		return;

	local r: Parser::LexemeVal;
	r = ret;
	
	if ( r?$token && r$token=="LPARANTHESIS" )
		return;

	if (idx >= 0 )
		{
		v[idx] = ret;
		++idx;
		Stack::get_stack_as_vector_till_lparanthesis(s,v,idx);
		}
	}

#====================== HACKY FUNCTIONS END============	
