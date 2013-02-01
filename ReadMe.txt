==================================
A correlation framework for Bro
==================================

This framework facilitates correlating Bro events on the fly. While this
task can also be done offline by post-processing logs, the correlation
framework allows putting some sense into thousands of events spewed during
live analysis and reacting to those in real time; the reaction being raising 
a threshold, kick-starting another correlation, invoking a bash script and so on.

A really cool feature of the correlation framework is the ability to trace 
back events that led to the correlation rule yielding true. For example, suppose 
we know that events A,B and C contribute to correlation X. If correlation
rule for X is met, the framework will tell you which combination of A, B and 
C triggered the rule.

==================================
How to use the correlation framework 
==================================

1. Correlation framework is a directory (avalilable at https://github.com/sheharbano/correlation) 
   which you need to put in a place of your choice. Once done, load the main correlation scripts in 
   your script paying attention to paths.
   ----------------------
   @load correlation.bro
   @load non-cluster.bro
   ----------------------

2. Next, you need to add your correlation item to the framework. Usually, this should be done in
   event bro_init but it's possible to do this in a code block that is invoked in reaction to some
   other event.
    
   ----------------------------------------
   function correlated_func(index: Correlation::Index, val: Correlation::Val)
	{
	print "This function will be called when my correlation rule is met.";
	}
   local str_rule = "<SOME RULE THAT I WILL SHORTLY DESCRIBE>";

   local done = Correlation::add_correlation_item("correlation1",[$name="filter1",
                                                  $every=5mins,
                                                  $rule=str_rule,
						  $log=T,
                                                  $correlated=correlated_func] ); 
   if ( !done )
           print "Correlation Framework Error: Failed to add filter."; 

   -------------------------------------------

   Lets discuss the different fields one by one.

	* done
 	  A Boolean value that indicates if the filter was successfully added to the correlarion framework.

        * add_correlation_item
          A function that adds a correlation item to the framework. 

          Correlation ID:
          The first parameter here is the correlation ID ("correlation1").

	  Filter name ($name):
   	  The second parameter is the filter name ("filter1"). A filter together with the correlation ID 
          uniquely identifies a correlation item. A correlation ID can potentially have many filters associated 
          with it. Confused? Suppose our correlation item is malware C&C communication (correlation id = "CNC").
          You could have two filters for it with different rules (rule_filter_1=<Blacklist match and Talked to 
          hosts based in Timbuktu>, rule_filter_2=<Blacklist matched 2 times>). Yes, it's possible to express
	  this in a single rule by placing an <or> between the individual rules. Why need two filters then? What
          if we want to say that filter_rule_1 should be observed for 1 hour duration, but filter_rule_2 should 
          be reported only if the two blacklist matches are made in 5 minutes? Essenrially, the filter provides
          different perspectives on the same correlation entity.    
	
	  Observation interval ($every):
	  How long to watch for the correlation rule being met after which the framework will wipe out previous
	  state and start fresh observation. You want to have some temporal boundaries on your correlation. Mostly,
          higher observation intervals indicate less stringent correlation criteria and vice versa. For example, 
	  it is more likely to observe a host that makes DNS query for a blacklisted host and then establishes an
	  HTTP connection with it in 5 hours than 1 second.

	  Correlation rule ($rule):
          A rule that applies to the events that contribute to the correlation in question. For example, 
          ( event A and event B ) describes a very simple rule. I will discuss rule in more detail in the
          next bullet (3).

          Logging enable/diable ($log):
          A boolean value that indicates whether or not to log the results when a correlation rule is met. We
          will discuss what is logged in point 5.

	  Correlation function ($correlated):
  	  If defined, this function will be called whenever a correlation rule is met. The idea is to give users
          a chance to implement additional functionality in response to something being correlated. The function
	  is optional and you can skip it if you have no such requirements. The function must have the signature
          (index: Correlation::Index, val: Correlation::Val). When correlation rule is met, the framework will 
	  invoke this function filling :index: and :val: with appropriate values. While index is self explanatory,
          :val: is the same as what is logged and will be described in point 5.  

3. Lets turn our attention to the correlation rule now. You need to supply a correlation rule in $rule in 
   Correlation::ad__correlation_item(*), but how? Well, the correlation rule is a string as far as the user is
   concerned but internally, it is parsed and interpreted as an expression. The correlation rule has the form
   <order>;<join>;<expression> where you can optionally skip either <order> and <join>, or <join> and <expression>.

	* order
 	  This statement correlates events based on their order of occurence. So if your correlation rule is of the
	  type (A happens followed by B followed by C), you want to express it as an order statement. The order statement
	  has the syntax <cardinality><event_name>:<cardinality><event_name> and so on. 

	  <cardinality>:
	  A non-negative number. If you don't care about cardinality of the event in question, you can use a dot (.) to
          indicate any number.

	  <stream_name>:
	  Name of the event. It must contain only capital English alphabets and/or underscore (_).

	  Examples: 2SCAN:.CONNECTION_ESTABLISHED_TIMBUKTU  


        * join      
	  If both order and expression parts of the correlation rule are present, this statement describes how to combine
	  them. It can have two values as of now; <and> and <or>  

          Example: <the order statement>; and ; <the expression statement>

	* expression
	  This statement performs arithmetic/logical calculation to correlate the event streams. Regardless of the kind of
          calculations within the statement, the final result should be a BOOLEAN type.    

	  =======	===========      ======================   ====================       ==============
	  OP            SYNTAX           VALID PRECEDING TYPES    VALID FOLLOWING TYPES      TYPE OF RESULT
	  ======= 	===========      =======================  =====================      ===============
	  MULTIPLY      *                NUMBER                   NUMBER                     NUMBER 
                                         STREAM                   NUMBER                     NUMBER
                                         NUMBER                   STREAM                     NUMBER
          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
          ADD           +   		 NUMBER		          NUMBER                     NUMBER
          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
          COMPARISON    > < =            NUMBER                   NUMBER                     BOOLEAN
          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
          LOGICAL       & |              BOOLEAN                  BOOLEAN                    BOOLEAN
                                         STREAM                   STREAM                     BOOLEAN
          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
          MEMBERSHIP    $                KEYWORD                  STREAM                     NUMBER
         
          ==> The above represent operators
          

	  =======	==========================================        ==================================     
	  OPERAND       SYNTAX                                            DESCRIPTION
	  ======= 	==========================================        ==================================

          STREAM        Any combination of Capital English alphabets      If used with MULTIPLY operator, its value 
                        and the underscore symbol (_)                     will be set to 1 if the stream was seen, 
                                                                          otherwise its value will be 0.
                                                                          If used with BOOLEAN operator, its value  
									  will be set to t if the stream was seen, 
                                                                          otherwise its value will be f.
                                                                          If used with MEMBERSHIP operator, it represents 
									  the event stream to which the keyword pertains.
                                                                          e.g. n$STREAM_X will be replaced with the number
                                                                          of times STREAM_X was seen by the framework.
									  Similarly, w$STREAM_X will be replaced by the 
									  highest weight seen for this event by the framework 

	  KEYWORD       n~~~~~~refers to cardinality of an event
                               stream i.e. how many times it was 
                               seen
                        w~~~~~~refers to weight of an event stream
 
          NUMBER        Any combination of 0-9 with or without decimal
                        point 

          BOOLEAN       f~~~~~~False
                        t~~~~~~True   

          =======	==========================================        ==================================     
	  OTHERS        SYNTAX                                             DESCRIPTION
	  ======= 	==========================================        ==================================
          PRECEDENCE    ( )                                               Typical expression evaluation style
                                                                          is left to right, with all the operators
                                                                          enjoying equal precedence. You can priori-
                                                                          -tize evaluation of specific sub-expressions
									  by placing them between (). 
         
    
   Additionally, and this holds for all types of rule statements (order,join,expression), you can use '{' and '}' symbols 
   to improve readability of the rule. Rule parser will ignore '{' and '}' symbols.

   Example rules: 
   
   { .STREAM_ONE:2STREAM_TWO }:{or}:{ w$STREAM_ONE > 0.5 }
   - Any number of STREAM_ONE followed by exactly two instances of STREAM_TWO or if the weight of STREAM_ONE is greater
     than 0.5   

   ; ; { w$STREAM_TWO=1.0 & ( n$STREAM_ONE > 2 | w$STREAM_ONE > 0.5 ) }
   - Weight of STREAM_TWO is 1.0 and ( STREAM_ONE was seen more than two times or its weight exceeded 0.5 )

4. After adding the correlation item, the next task is to feed event streams to the correlation framework. So far, we have 
   just prepared the correlation framework to hanlde event streams fed to it in a certain way (defined by the correlation rule).
   Now, we are actually going to supply the event streams to the framework. For this, we will hanlde the events that we want
   to feed to the correlation framework, and call the following function in it:
   function add_stream(id: string, filter_name: string, index: Correlation::Index, name: string, weight: double ) 


        * Correlation ID (id)	
          The correlation ID to which the event stream corresponds 

	* Filter name (filter_name)	
          The correlation ID to which the event stream corresponds 

	* Index (index)
	  The index to which the event stream corresponds. The index is a :Bro:Record type of the following format.
	  type Index: record {
		## The IP address if the correlation is about an IP address.
		host:        addr           &optional;
		## The network if the correlation is about a CIDR block.
		net:         subnet         &optional;
		## The string if the correlation is about a string.
		str:         string         &optional;
		## The type of data that is in the string if the $str field is set.
		str_type:    StrType        &optional;
	  }

        * Name of the event stream (name) 
	  The name of the event stream. It should be the same as the one you specified for it  in the correlation rule; otherwise
          the framework will ignore it as it does not know what to do with it.

	* Weight of the event stream (weight)
	  Weight of the event stream. If not required, you can supply a dummy value and then simply ignore it in your definition of
          the correlation rule. Weight comes in handy when an event stream itself is the result of another correlation. This means
          that multiple sub-streams can contribute to the event stream and you can differentiate among them by assigning different
          weights to reflect their significance. For example, you can assign greater weight to match against a trusted blacklist than
          with one that has a history of too many false positives.  
	
	* History string (str_history)
	  A string that represents the events that ramped up to triggering the correlation rule
	  e.g. 2SUCCESSFUL_CONN:1DNS_A_QUERY:1SUCCESSFUL_CONN:

5. Finally, lets talk about the information you will get if the correlation rule turns true. This information can be inspected
   at a later stage by enabling logging in Correlation::add_correlation_item. Also, it can be obtained by defining a function
   corresponding to $correlated in Correlation::add_correlation_item.   

        * Timestamp (ts)	
          When this information was generetaed

	* Index (index)
	  The index to which the information corresponds

        * Correlation start time (begin)
	  When the first event stream was seen for this index

	* Correlation end time (end)
	  When the last event stream was seen for this index
	
	* History string (str_history)
	  A string that represents the events that ramped up to triggering the correlation rule
	  e.g. 2SUCCESSFUL_CONN:1DNS_A_QUERY:1SUCCESSFUL_CONN:

6. There is a demo script (test.bro) in correlation framework directory that nicely summarizes the entire discussion. Run using the 
   command 'bro -r test.pcap test.bro'. Have fun!

<==================================>

Feedback/queries are welcome. A shout-out to Seth Hall (http://www.icir.org/seth/) for discussions and support. Many thanks to Affan A. Syed (http://www.isb.nu.edu.pk/sysnet/contact_us.html) and Syed Ali Khayam (http://www.xgridtech.com/#!Ali-Khayam/zoom/mainPage/image1jgm) for their useful feedback.

-Sheharbano
(sheharbano.k@gmail.com)
 
