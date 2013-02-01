##! A LIFO stack.

module Stack;

export {
	## Settings for initializing the stack.
	type Settings: record {
		## If a maximum length is set for the stack
		## it will maintain itself at that 
		## maximum length automatically.
		max_len: count &optional;
	};

	## The internal data structure for the stack.
	type Stack: record {};

	## Initialize a stack record structure.
	## 
	## s: A :bro:record:`Settings` record configuring the stack.
	##
	## Returns: An opaque stack record.
	global init:       function(st: Settings): Stack;

	## Push a string to the top of a stack.
	## 
	## s: The stack to push the string into.
	## 
	## val: The string to push 
	global push:       function(s: Stack, val: any);

	## Pop a string from the top of a stack.
	##
	## s: The stack to pop the string from.
	##
	## Returns: The string popped from the stack.
	global pop:        function(s: Stack): any;

	## :Not Implemented:
	## Merge two stack's together.  If any settings are applied 
	## to the stacks, the settings from q1 are used for the new
	## merged stack.
	## 
	## s1: The first stack.  Settings are taken from here.
	##
	## s2: The second stack.
	## 
	## Returns: A new stack from merging the other two together.
	#global merge:      function(s1: Stack, s2: Stack): stack;

	## Get the number of items in a stack.
	## 
	## s: The stack.
	##
	## Returns: The length of the stack.
	global len:     function(s: Stack): count;

	## Get the top element of a stack.
	## 	
	## s: The stack.
	##
	## Returns: Top element of the stack.
	global peek:     function(s: Stack): count;
	
	## Copy the contents of the stack to a vector provided in 
	## function arguments starting at :idx:.
	## 
	## s: The stack.
	##
	## v: A vector supplied by user in function arguments. The stack 
	## contents will be added to it
	global get_stack_as_vector: function(s: Stack, v: vector of any, idx: int);
	global get_stack_as_vector_till_op: function(s: Stack, v: vector of any, idx: int);
	global get_stack_as_vector_till_lparanthesis: function(s: Stack, v: vector of any, idx: int);

	## :Not Implemented:
	## Get the contents of the stack as a count vector.  Use care
	## with this function.  If the data put into the stack wasn't 
	## integers you will get conversion errors.
	## 
	## s: The stack.
	##
	## Returns: A :bro:type:`vector of count` containing the 
	##          current contents of s.
	global get_cnt_vector: function(s: Stack): vector of count;
}

redef record Stack += {
	# Indicator for if the stack was appropriately initialized.
	initialized: bool                   &default=F;
	# The values are stored here.
	vals:        table[count] of any &optional;
	# Settings for the stack.
	settings:    Settings               &optional;
	# The top value in the vals table.
	top:         count                  &default=0;
	# The bottom value in the vals table.
	bottom:      count                  &default=0;
	# The number of bytes in the stack.
	size:        count                  &default=0;
};

function init(st: Settings): Stack
	{
	local s: Stack;
	s$vals=table();
	s$settings = copy(st);
	s$initialized=T;
	return s;
	}

function push(s: Stack, val: any)
	{
	if ( s$settings?$max_len && len(s) >= s$settings$max_len )
		pop(s);
	s$vals[s$top] = val;
	++s$top;
	#print s$vals;
	}

function pop(s: Stack): any
	{
	if ( |s$vals| == 0 )
		{
		#print "Stack Error: Cannot pop an empty stack.";
		# dummy stmt to silence the above error
		local a = T;
		}
	else
		{
		if ( s$top > s$bottom )
			--s$top;

		local ret = s$vals[s$top];
		delete s$vals[s$top];
		return ret;
		}
	return F;
	}


function len(s: Stack): count
	{
	return |s$vals|;
	}

function peek(s: Stack): any
	{
	if ( |s$vals| == 0 )
		return F;
	return s$vals[(s$top)-1];
	}

function get_stack_as_vector( s: Stack, v: vector of any, idx: int )
	{
	local ret = Stack::pop(s);

	if (type_name(ret)=="bool" )
		return;

	if (idx >= 0)
		{
		v[idx] = ret;
		++idx;
		get_stack_as_vector(s,v,idx);
		}
	}



