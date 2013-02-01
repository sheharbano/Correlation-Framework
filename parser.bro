##! A correlation rule parser

@load data.bro
@load utils.bro

module Parser; 

export {
	## The internal data structure for the parser.
	type Parser: record {
		# Indicator for if the parser was appropriately initialized.
		initialized: bool                   &default=F;
		# A vector that holds strings of the form <cardinality><stream>
		# in the order they occur in the order part of the correlation 
		# rule
		order_stmt: vector of string	&optional;
		# A string representing join part of the correlation rule
		join_stmt: string	&optional;
		# A vector that holds Parser::LexemeVal values
		# in Reverse Polish Notation so they can be readily
		# processed
		expr_stmt: vector of Parser::LexemeVal	&optional;
		rule_type: string	&optional;
	};	

	global parse: function( p: Parser::Parser, history: vector of HistoryVal, hist_tb: table[string] of StreamData ): bool;
	global check_syntax_order: function( lexemes_order: vector of LexemeVal ): bool;
	global convert_expr_to_RPN: function( lexemes: vector of Parser::LexemeVal ): vector of Parser::LexemeVal;
	global  check_syntax_expr: function( expr_RPN: vector of Parser::LexemeVal ): bool;
	global parse_order: function( arr_lexemes: vector of string, history: vector of HistoryVal ): bool;
	global parse_expr: function( expr_RPN: vector of Parser::LexemeVal, hist_tb: table[string] of StreamData ): bool;
	global init: function( stmt: string ): Parser::Parser;
	global init_order_syntax_rules: function();
	global init_expr_syntax_rules: function();
}



function check_stmt_syntax( stmts: vector of string ): string
	{
	local stmt_parts = |stmts|-1;

	if ( stmt_parts == 3 )
		{
		local order_stmt = strip(stmts[1]);
		local join_stmt = strip(stmts[2]);
		local expr_stmt = strip(stmts[3]);
	
		if ( |order_stmt|==0 && |join_stmt|==0 && |expr_stmt|>0 )
			return "TYPE1";
		else if ( |order_stmt|>0 && |join_stmt|>0 && |expr_stmt|>0 ) 
			return "TYPE2";
		if ( |order_stmt|>0 && |join_stmt|==0 && |expr_stmt|==0 )
			return "TYPE3";
		else
			{
			print "Parser Error: Rule in wrong format (expected format [order];[join];expression). Note that order and join both must be present or absent.";
			return "ERROR";
			}
		}
	else
		{
		print "Parser Error: Rule in wrong format (expected format [order];[join];<expression>)";
		return "ERROR";
		}
	}


## Initialization of processing structures and syntax
## checking takes place here.
function init( stmt: string ): Parser::Parser
	{
	local p: Parser::Parser;
	local order_processed: vector of string;
	local join_processed = "";
	local expr_processed: vector of Parser::LexemeVal;

	local stmts = string_to_vector(stmt,";");
	# We have two correlation rule syntaxes. :st_type:  
	# identifies which format the current rule is in. 
	local st_type = check_stmt_syntax( stmts );
	if ( st_type == "ERROR" )
		return [ $initialized=F ];
	
	local order_st = strip(stmts[1]); 
	local join_st = strip(stmts[2]);
	local expr_st = strip(stmts[3]); 

	if ( |order_st| != 0 )
		{
		local lexemes_order: vector of LexemeVal;
		lexemes_order = tokenize_order( order_st ); 
		if ( |lexemes_order| == 0 )
			return [ $initialized=F ];
		if ( !Parser::check_syntax_order( lexemes_order ) ) 	
			return [ $initialized=F ];

		# An array that holds <cardinality><stream>
		# in the order they occur in the order part
		# of the correlation rule
		local str_order_lexemes = get_lexeme_string( lexemes_order );
		order_processed = string_to_vector( str_order_lexemes, ":" );		
		}
	if ( |join_st| != 0 )
		{
		local lexemes_join: vector of Parser::LexemeVal;
		lexemes_join = tokenize_join( join_st );
		# No need to check multi-token syntax here as join 
		# stmt is a single keyword which is validated in 
		# the tokenization phase
		if ( |lexemes_join| == 0 )
			return [ $initialized=F ];
		join_processed = lexemes_join[1]$lexeme;
		}

	if ( |expr_st| != 0 )
		{
		local lexemes_expr: vector of LexemeVal;
		lexemes_expr = tokenize_expr( expr_st );
		if ( |lexemes_expr| == 0 )
			return [ $initialized=F ];
		expr_processed = convert_expr_to_RPN( lexemes_expr );
		if ( !check_syntax_expr( expr_processed ) ) 	
			return [ $initialized=F ];
		}

	if ( st_type == "TYPE1" )	
		{
		p$rule_type = "TYPE1";
		p$initialized = T;
		p$expr_stmt = expr_processed;
		return p;
		}
	else if ( st_type == "TYPE2" )
		{
		p$rule_type = "TYPE2";
		p$initialized = T;
		p$order_stmt = order_processed;
		p$join_stmt = join_processed;
		p$expr_stmt = expr_processed;
		return p;
		}
	else if ( st_type == "TYPE3" )
		{
		p$rule_type = "TYPE3";
		p$initialized = T; 
		p$order_stmt = order_processed;
		return p;
		}
	}

function parse( p: Parser::Parser, history: vector of HistoryVal, hist_tb: table[string] of StreamData ): bool
	{
	local parsed_order = F;
	local parsed_expr = F;

	# correlation rule contains only expr stmt
	if ( p$rule_type=="TYPE1" )
		return Parser::parse_expr( p$expr_stmt, hist_tb );

	# correlation rule contains only order stmt
	else if ( p$rule_type=="TYPE3" )
		{
		#print fmt("parsed order: %s history: %s", parsed_order, history);
		return Parser::parse_order( p$order_stmt, history );
		}

	else if ( p$rule_type=="TYPE2" )
		{		
		parsed_order = Parser::parse_order( p$order_stmt, history );
		parsed_expr = Parser::parse_expr( p$expr_stmt, hist_tb );

		#print fmt("parsed order: %s-----parsed expr: %s: hist_tb: %s, hist: %s",parsed_order,parsed_expr, hist_tb, history);

		if ( p$join_stmt=="and")
			return parsed_order && parsed_expr;
		else if ( p$join_stmt=="or")
			return parsed_order || parsed_expr;
		}
	print fmt( "Parser Error: Unrecognized rule type (%s)", p$rule_type );
	return F;
	}



event bro_init()
	{
	Parser::init_expr_syntax_rules();
	Parser::init_order_syntax_rules();
	}
