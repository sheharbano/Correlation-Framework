##! Deals with parsing the expression part of the
##! correlation rule

@load data.bro
@load stack.bro
@load utils.bro
@load correlation.bro

module Parser;

export {
	## Structures related to expression part of correlation rule 
	## A structure for containing the expression part of 
	## the correlation rule in Revere Polish Notation  
	global expr_RPN: vector of Parser::LexemeVal;
	type OperandTokens: record {
		## Token of the first operand
		op1_token:           string;
		## Token of the second operand
		op2_token:     string;
	};
	## A table that represents syntax rules
	## Index: valid operand tokens for an operator
	##        e.g. operand1=NUMBER and operand2=NUMBER
	##        is a valid case for the operators (+*)
	## Yield: the token of the result when an operator
	##        operates on valid operands
	##        e.g. op1+op2 is a NUMBER
	type SyntaxInfo: table[OperandTokens] of string;
	## A table that contains all relevant information 
	## for an operator (valid operand tokens, result token)
	## Index: token of operator
	## Yield: A record of type OperatorInfo
	global expr_syntax_rules: table[string] of SyntaxInfo = table() &default=table();
}
## Expression converted to Reverse Polish Notation (RPN)
## (http://www.teach-ict.com/as_as_computing/ocr/H447/F453/3_3_7/revpolish/miniweb/pg2.htm)
## using the shunting-yard-algorithm
## (http://andreinc.net/2010/10/05/converting-infix-to-rpn-shunting-yard-algorithm/)
function convert_expr_to_RPN( lexemes: vector of Parser::LexemeVal ): vector of Parser::LexemeVal
	{
	local stack_op: Stack::Stack;
	stack_op = Stack::init( [] );
	local exp_RPN: vector of Parser::LexemeVal;

	for ( i in lexemes )
		{
		local token = lexemes[i]$token; 
	
		# If token is an operator
		if ( token == "MULTIPLY" || token == "ADD" || 
			token == "LOGICAL" || token == "MEMBERSHIP" || 
				token == "COMPARISON"  )
			{
			# Pop operators from stack and append to :exp_RPN: 
			# till a non-operator value is encountered
			if ( Stack::len(stack_op)!=0 )
				Stack::get_stack_as_vector_till_op( stack_op, exp_RPN, |exp_RPN| );
			# Push the new operator on top of the stack
			Stack::push( stack_op, lexemes[i] );
			}

		else if ( token == "LPARANTHESIS" )
			Stack::push( stack_op, lexemes[i] );	
		else if ( token == "RPARANTHESIS" && Stack::len(stack_op)!=0 )
			Stack::get_stack_as_vector_till_lparanthesis( stack_op, exp_RPN, |exp_RPN| );
		else
			exp_RPN[|exp_RPN|] = lexemes[i]; 

		}
	if ( Stack::len( stack_op ) !=0 )
		Stack::get_stack_as_vector( stack_op, exp_RPN, |exp_RPN| );
	return exp_RPN;		
	}
	


## evaluates a binary expression
## a: the first stream
## b: the second stream
## op: the operator
function evaluate_expr( a: string, op: string, b: string): any
	{
	if ( op == "+" )
		return to_double(a)+to_double(b);
	else if ( op == "*" )
		return to_double(a)*to_double(b);
	else
		print fmt("Parser Error: Illegal operator(%s) encountered while parsing expression.",op);
	}

function do_operation_expr( operand1: Parser::LexemeVal, operand2: Parser::LexemeVal, 
			operator: Parser::LexemeVal, hist_tb: table[string] of StreamData ): Parser::LexemeVal
	{
	local result: Parser::LexemeVal;
	if ( operator$token == "ADD" )
		{
		local op_add_1 = to_double(operand1$lexeme);
		local op_add_2 = to_double(operand2$lexeme);
		result$lexeme = fmt("%s",op_add_1+op_add_2);
		result$token = "NUMBER";
		}
	else if ( operator$token == "MULTIPLY" )
		{
		local op_mul_1 = 0.0;
		local op_mul_2 = 0.0;

		if ( operand1$token == "NUMBER" && operand2$token == "NUMBER" )
			{
			op_mul_1 = to_double(operand1$lexeme);
			op_mul_2 = to_double(operand2$lexeme);
			result$lexeme = fmt("%s",op_mul_1*op_mul_2);
			result$token = "NUMBER";
			}
		else if ( operand1$token == "STREAM" )
			{
			if ( operand1$lexeme in hist_tb )
				{ 
				op_mul_1 = 1.0;
				op_mul_2 = to_double(operand2$lexeme);
				result$lexeme = fmt("%s",op_mul_1*op_mul_2);
				result$token = "NUMBER";
				}
			}
		else if ( operand2$token == "STREAM" )
			{
			if ( operand2$lexeme in hist_tb )
				{ 
				op_mul_2 = 1.0;
				op_mul_1 = to_double(operand2$lexeme);
				result$lexeme = fmt("%s",op_mul_1*op_mul_2);
				result$token = "NUMBER";
				}
			}
		}
	else if ( operator$token == "COMPARISON" )
		{
		local op_comp_1 = to_double(operand1$lexeme);
		local op_comp_2 = to_double(operand2$lexeme);
	
		if ( operator$lexeme == ">" )
			{
			result$lexeme = to_lower(fmt("%s",op_comp_1 > op_comp_2));
			result$token = "BOOLEAN";
			}
		if ( operator$lexeme == "<" )
			{
			result$lexeme = to_lower(fmt("%s",op_comp_1 < op_comp_2));
			result$token = "BOOLEAN";
			}
		else if ( operator$lexeme == "=" )
			{
			result$lexeme = to_lower(fmt("%s",op_comp_1 == op_comp_2));
			result$token = "BOOLEAN";
			}
		}
	else if ( operator$token == "LOGICAL" )
		{
		local op_logic_1 = F;
		local op_logic_2 = F;
		
		if ( (operand1$token == "BOOLEAN") && (operand2$token == "BOOLEAN") )
			{	
			op_logic_1 = ( operand1$lexeme == "t"? T: F );
			op_logic_2 = ( operand2$lexeme == "t"? T: F );
			}

		else if ( (operand1$token == "STREAM") && (operand2$token == "STREAM") )	
			{
			op_logic_1 = ( operand1$lexeme in hist_tb? T: F );
			op_logic_2 = ( operand2$lexeme in hist_tb? T: F );
			}
	
		if ( operator$lexeme == "&" )
			{
			result$lexeme = to_lower(fmt("%s",op_logic_1 && op_logic_2));
			result$token = "BOOLEAN";
			}
		else if ( operator$lexeme == "|" )
			{
			result$lexeme = to_lower(fmt("%s",op_logic_1 || op_logic_2));
			result$token = "BOOLEAN";
			}
		}
	else if ( operator$token == "MEMBERSHIP" )
		{
		if ( operand1$lexeme == "n" )
			{
			local crdnlty = ( operand2$lexeme in hist_tb? hist_tb[operand2$lexeme]$times_seen: 0.0 );
			result$lexeme = fmt("%s",crdnlty);
			result$token = "NUMBER"; 
			}
		else if ( operand1$lexeme == "w" )
			{
			local wt = ( operand2$lexeme in hist_tb? hist_tb[operand2$lexeme]$weight: 0.0 );
			result$lexeme = fmt("%s",wt);
			result$token = "NUMBER";
			} 
		}
	#print fmt( "%s %s %s results in %s",operand1$lexeme, operator$lexeme, operand2$lexeme, result$lexeme );
	return result;
	}

## This function parses and evaluates the expression
## returns: a boolean value that says whether or not the expression 
##	    part of the correlation rule holds
function parse_expr( expr_RPN: vector of Parser::LexemeVal, hist_tb: table[string] of StreamData ): bool
	{
	local stack_tmp: Stack::Stack;
	stack_tmp = Stack::init( [] );

	for ( idx in expr_RPN )
		{ 
		local lexeme = expr_RPN[idx];
		# If the lexeme is not an operator
		if ( lexeme$token != "MULTIPLY" && lexeme$token != "ADD" && 
			lexeme$token != "LOGICAL" && lexeme$token != "MEMBERSHIP" && 
				lexeme$token != "COMPARISON"  )
			Stack::push( stack_tmp, lexeme );
		else
			{
			# In a stack, the order in which operands are popped
			# is right to left, and we have left to right precedence
			# so the first operand popped is our second operand and 
			# likewise the next one is the first operand
			local operand2 = Stack::pop( stack_tmp );
			local operand1 = Stack::pop( stack_tmp );
			local operator = lexeme;
			#print fmt("%s -- %s --%s",type_name(operand1),type_name(operand2),type_name(operator));	
			local ret = do_operation_expr( operand1, operand2, operator, hist_tb );
			Stack::push( stack_tmp, ret );
			}
		}
	# When expression has been evaluated, the last element in the stack
	# will represent the final result
	local result: Parser::LexemeVal;
	result = Stack::pop( stack_tmp );

	if ( result$token == "BOOLEAN" )
		{
		if ( result$lexeme == "t" )
			return T;
		else if ( result$lexeme == "f" )
			return F;
		}

	return F;
	}

## This function checks syntax of the expression part of a 
## correlation rule
## returns: a boolean indicating whether or not the syntax of 
##	    expression part of the correlation rule is correct
function check_syntax_expr( expr_RPN: vector of Parser::LexemeVal ): bool
	{
	local stack_tmp: Stack::Stack;
	stack_tmp = Stack::init( [] );
	local result_token = "";

	for ( idx in expr_RPN )
		{ 
		local lexeme = expr_RPN[idx];
		# If the lexeme is not an operator
		if ( lexeme$token != "MULTIPLY" && lexeme$token != "ADD" && 
			lexeme$token != "LOGICAL" && lexeme$token != "MEMBERSHIP" && 
				lexeme$token != "COMPARISON"  )
			Stack::push( stack_tmp, lexeme$token );
		else
			{
			# In a stack, the order in which operands are popped
			# is right to left, and I have left to right precedence
			# so the first operand popped is our second operand and 
			# likewise the next one is the first operand
			local operand2_token = Stack::pop( stack_tmp );
			local operand1_token = Stack::pop( stack_tmp );
			local operator = lexeme;
			
			# If any of these are bool, it means that the stack was empty 
			# and nothing was popped
			if ( type_name(operand1_token)!="bool" && type_name(operand2_token)!="bool" )
				{
				local operands = [$op1_token=operand1_token, $op2_token=operand2_token];
				local rules_op = expr_syntax_rules[operator$token];
				if ( operands in rules_op )
					{
					result_token = rules_op[operands];	
					Stack::push( stack_tmp, result_token );
					}
				else
					{
					print fmt("Parser Error: Incorrect syntax in expression part of correlation rule-->Invalid operation (%s%s%s)",operand1_token,operator$lexeme,operand2_token);
					return F;
					}
				}
			else
				print "Parser Error: Incorrect syntax in expression part of correlation rule-->Want more operands.";
			}
		}
	# When expression has been evaluated,  the last element in the stack
	# will represent the final result
	result_token = Stack::pop( stack_tmp );
	if ( Stack::len( stack_tmp ) > 0 )
		{
		print "Parser Error: Incorrect syntax in expression part of correlation rule-->Too many operands.";
		return F;
		} 
	else if ( result_token != "BOOLEAN" )
		{
		print "Parser Error: Expression part of the correlation rule must evaluate to a BOOLEAN value.";
		return F;
		}

	return T;
	}


function init_expr_syntax_rules()
	{
	# Initializing Parser::expr_syntax_rules
	local syntax_info_mul: Parser::SyntaxInfo;
	syntax_info_mul[[$op1_token="NUMBER",$op2_token="NUMBER"]]="NUMBER";
	syntax_info_mul[[$op1_token="NUMBER",$op2_token="STREAM"]]="NUMBER";
	syntax_info_mul[[$op1_token="STREAM",$op2_token="NUMBER"]]="NUMBER";
	expr_syntax_rules["MULTIPLY"] = syntax_info_mul;

	local syntax_info_add: Parser::SyntaxInfo;
	syntax_info_add[[$op1_token="NUMBER",$op2_token="NUMBER"]]="NUMBER";
	expr_syntax_rules["ADD"] = syntax_info_mul;

	local syntax_info_comp: Parser::SyntaxInfo;
	syntax_info_comp[[$op1_token="NUMBER", $op2_token="NUMBER"]]="BOOLEAN";	
	expr_syntax_rules["COMPARISON"] = syntax_info_comp;

	local syntax_info_logic: Parser::SyntaxInfo;
	syntax_info_logic[[$op1_token="BOOLEAN", $op2_token="BOOLEAN"]]="BOOLEAN";
	syntax_info_logic[[$op1_token="STREAM", $op2_token="STREAM"]]="BOOLEAN";	
	expr_syntax_rules["LOGICAL"] = syntax_info_logic;

	local syntax_info_mem: Parser::SyntaxInfo;
	syntax_info_mem[[$op1_token="KEYWORD", $op2_token="STREAM"]]="NUMBER";	
	expr_syntax_rules["MEMBERSHIP"] = syntax_info_mem;
	}
