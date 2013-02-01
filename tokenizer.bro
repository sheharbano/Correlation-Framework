##! A correlation rule parser

module Parser;

export {
	## A record that represents lexeme_join and the yield of 
	## Parser::lexemes_expr and Parser::lexemes_order  
	type LexemeVal: record {
			## the lexeme. e.g. STREAM_SCAN
			lexeme:    string;

			## the token. e.g. STREAM for the lexeme STREAM_SCAN
			token:      string;
	};
}

# Future: Might want to check syntax by comparing 
# with a table of patterns indexed on language tokens
## LANGUAGE
#!!Problem: if I prefix any valid operator with \
# it is internally ignored. e.g. \* results in OPERATOR 
#tokens["KEYWORD"]=/[wn]|and|or/;
#tokens["STREAM"]=/[A-Z_]+/;
#tokens["WILDSTREAM"]=/\-/;
#tokens["OPERATOR"]=/[+*]/;
#tokens["RELOPERATOR"]=/[&|=><]/;
#tokens["LPARANTHESIS"]=/\(/;
#tokens["RPARANTHESIS"]=/\)/;
#tokens["NUMBER"]=/[0-9]+/;
#tokens["BOOLEAN"]=/[tf]/;
#tokens["WILDNUMBER"]=/\./;
#tokens["MEMBERSHIP"]=/$/;
#
#global tokens: table[string] of pattern;
#
## This function checks if a given lexeme matches
## a token. If the match is successful, it returns
## the matched token, otherwise it returns
## an empty string (no token matched)
#function match_token( lexeme: string ): string
#	{
#	for ( token in tokens )
#		{
#		if ( lexeme == tokens[token] )
#			return token;
#		return ""; 
#		}
#	}

function add_lexeme( lexeme: string, token: string, lexemes: vector of Parser::LexemeVal )
	{
	local idx = |lexemes|;
	lexemes[idx] = [ $lexeme=lexeme, $token=token ];
	}

function reset_lexemes( lexemes: vector of Parser::LexemeVal )
	{
	lexemes = vector();
	}

function tokenize_join(stmt: string): vector of Parser::LexemeVal 
	{
	local str = "";
	local normal_exit = T;
	local token = "";
	local lex_join: Parser::LexemeVal;
	local vec_lex_join: vector of Parser::LexemeVal;

	for ( ch in stmt )
		{
		if ( ch != " " && ch != "{" && ch != "}" )
			{
			if ( ch == /[a-z]/)
				{
				token = "KEYWORD";
				str +=ch;
				}
			else
				{
				print fmt("Parser Error: Illegal character(%s) in join statement.",ch);
				normal_exit = F;
				break;
				}
			}
		}
	
	# Flushing out the value accumulated for multi-character lexemes
	# when the end of the input statement is approached. If parsing was
	# cut short by an illegal character in the input stmt, we don't need
	# to do this
	if ( normal_exit )
		{
		## Future: replace 'and' and 'or' match by more generic regex matching
		if ( str == "and" || str == "or" )
			{
			# I could return lexeme_join right away but put it in 
			# a vector so that the size if the vector conveys (ab)normal
			# execution 
			lex_join = [ $lexeme=str, $token="KEYWORD" ];
			vec_lex_join[1] = lex_join;
			return vec_lex_join;
			}
		else 
			print fmt("Parser Error: Invalid keyword(%s) in join statement.", str);
		}
	return vec_lex_join;
	}

function tokenize_order(stmt: string): vector of Parser::LexemeVal 
	{
	local last_ch_token = "";
	local curr_ch_token = "";
	local stream = "";
	local num = "";
	local token = "";
	local normal_exit = T;
	local lexeme_found = F;
	local lexemes_order: vector of Parser::LexemeVal;

	for ( ch in stmt )
		{
		last_ch_token = curr_ch_token;

		if ( ch != " " && ch != "{" && ch != "}" )
			{
			if ( ch == /[A-Z_]/)
				{
				token = "STREAM";
				stream +=ch;
				lexeme_found = F;
				}
			else if ( ch == /[0-9]/ )
				{
				token = "NUMBER";
				num += ch;
				lexeme_found = F;
				}
			else if ( ch == "." )
				{
				token = "WILDNUMBER";
				lexeme_found = T;
				}
			else if ( ch == ":" )
				{
				token = "SEPARATOR";
				lexeme_found = T;
				}
			## Future
			#else if ( ch == "-" )
			#	{
			#	token = "WILDSTREAM";
			#	lexeme_found = T;
			#	}
			else
				{
				print fmt("Parser Error: Illegal character(%s) in order statement.",ch);
				normal_exit = F;
				return vector();
				}

			curr_ch_token = token;

			## This is the place where multi-character lexemes' accumulated value
			## should be added to the table. In the end, accumulator should be
			## reset in preparation for the next lexeme of this kind.
			if ( last_ch_token == "STREAM" && (curr_ch_token != "STREAM") )
				{
				add_lexeme( stream, "STREAM", lexemes_order );
				stream = "";
				}
			if ( last_ch_token == "NUMBER" && (curr_ch_token != "NUMBER") )
				{
				add_lexeme( num, "NUMBER", lexemes_order );
				num = "";
				}
			# Add the current lexeme (if seen in its entirety)
			if ( lexeme_found )
				add_lexeme( ch, token, lexemes_order );
			}
		}
	
	# Flushing out the value accumulated for multi-character lexemes
	# when the end of the input statement is approached. If parsing was
	# cut short by an illegal character in the input stmt, we don't need
	# to do this
	if ( normal_exit )
		{
		if ( last_ch_token == "STREAM" && curr_ch_token == "STREAM" )
				add_lexeme( stream, "STREAM", lexemes_order );
		if ( last_ch_token == "NUMBER" && curr_ch_token == "NUMBER" )
				add_lexeme( num, "NUMBER", lexemes_order );
		return lexemes_order;
		}
	return vector();
	}

function tokenize_expr(stmt: string): vector of Parser::LexemeVal 
	{
	local last_ch_token = "";
	local curr_ch_token = "";
	local stream = "";
	local num = "";
	local token = "";
	local normal_exit = T;
	local lexeme_found = F;
	local lexemes_expr: vector of Parser::LexemeVal;

	for ( ch in stmt )
		{
		last_ch_token = curr_ch_token;

		if ( ch != " " && ch != "{" && ch != "}" )
			{
			if ( ch == /[A-Z_]/)
				{
				token = "STREAM";
				stream +=ch;
				lexeme_found = F;
				}
			else if ( ch == /[0-9]|[0-9]+\.[0-9]+/ )
				{
				token = "NUMBER";
				num += ch;
				lexeme_found = F;
				}
			else if ( ch == "*" )
				{
				token = "MULTIPLY";
				lexeme_found = T;
				}
			else if ( ch == "+" )
				{
				token = "ADD";
				lexeme_found = T;
				}
			else if ( ch == "$" )
				{
				token = "MEMBERSHIP";
				lexeme_found = T;
				}
			else if ( ch == /[=><]/ )
				{
				token = "COMPARISON";
				lexeme_found = T;
				}
			else if ( ch == /[&|]/ )
				{
				token = "LOGICAL";
				lexeme_found = T;
				}
			else if ( ch == "w" || ch == "n" )
				{
				token = "KEYWORD";
				lexeme_found = T;
				}
			else if ( ch == "f" || ch == "t" )
				{
				token = "BOOLEAN";
				lexeme_found = T;
				}
			else if ( ch == "(" )
				{
				token = "LPARANTHESIS";
				lexeme_found = T;
				}

			else if ( ch == ")")
				{
				token = "RPARANTHESIS";
				lexeme_found = T;
				}
			else
				{
				print fmt("Parser Error: Illegal character(%s) in expression statement.",ch);
				reset_lexemes( lexemes_expr );
				normal_exit = F;
				break;
				}

			curr_ch_token = token;

			## This is the place where multi-character lexemes' accumulated value
			## should be added to the table. In the end, accumulator should be
			## reset in preparation for the next lexeme of this kind.
			if ( last_ch_token == "STREAM" && (curr_ch_token != "STREAM") )
				{
				add_lexeme( stream, "STREAM", lexemes_expr );
				stream = "";
				}
			if ( last_ch_token == "NUMBER" && (curr_ch_token != "NUMBER") )
				{
				add_lexeme( num, "NUMBER", lexemes_expr );
				num = "";
				}
			# Add the current lexeme (if seen in its entirety)
			if ( lexeme_found )
				add_lexeme( ch, token, lexemes_expr );
			}
		}
	
	# Flushing out the value accumulated for multi-character lexemes
	# when the end of the input statement is approached. If parsing was
	# cut short by an illegal character in the input stmt, we don't need
	# to do this
	if ( normal_exit )
		{
		if ( last_ch_token == "STREAM" && curr_ch_token == "STREAM" )
				add_lexeme( stream, "STREAM", lexemes_expr );
		if ( last_ch_token == "NUMBER" && curr_ch_token == "NUMBER" )
				add_lexeme( num, "NUMBER", lexemes_expr );
		return lexemes_expr;	
		}	
	return vector();	
	}

