#!/usr/bin/perl
use strict;
use warnings;

# simple perl script to create a data file containing the modsecurity rule ID, table name and severity from the CRS rule files
# ./crs_to_rulesdata.pl /usr/share/modsecurity-crs rulesdata.conf

my $debug = 0;

if (scalar @ARGV ne 2) {
	print "You must pass the script the CRS directory path and output file as arguments:\n";
	print "1st argument must be the CRS directory path\n";
	print "2nd argument must be the output file\n";
	print "Example usage:\n";
	print "perl crs_to_rulesdata.pl /usr/share/modsecurity-crs/ rulesdata.conf \n";
	die;
}



# open the output file writeable
open (OUTFILE, ">> $ARGV[1]") || die "problem opening $ARGV[1]\n";

# print a header line to the file
print OUTFILE "\#RULE_ID TABLENAME ANOMALY_SCORE SQL_SCORE XSS_SCORE TROJAN_SCORE OUTBOUND_ANOMALY_SCORE AUTOMATION_SCORE PROFILER_SCORE \n";


# look up a list of configuration files in the specified directory
if ($debug) {print "searching for configuration files in $ARGV[0] \n";}

my @files = list($ARGV[0]);

if ($debug) {
    print "found the following files: \n";
    for my $file (@files) {
        print "$file \n";
    }
}


for my $filename (@files) {  
    # determine the table name from the filename
    if ($debug) {print "determining table name for filename $filename ...";}  
    if ($filename =~ m/^.*modsecurity_(crs_[0-9]+_[\w|_]+)\.conf$/) {
        my $TABLENAME = $1;
        if ($debug) {print "Table name is $TABLENAME \n";}
        
        # if table name is less than 25 chars, pad it out to make config file easier to read
        my $TABLECHARS = length ( $TABLENAME );
        if ( $TABLECHARS < 25 ) {
            $TABLENAME .= (" " x (25 - $TABLECHARS))
        }
        
        # open the input file read only
        open (INFILE, "$filename") || die "problem opening $filename \n";

        ## types of score data to extract:
        # anomaly score
        # sql score
        # xss score
        # trojan score
        # outbound anomaly score
        # automation score
        # profiler score

        # variables for holding temporary data
        my $RULE_ID = "";
        
        #my $SEVERITY = "0";
        #my $MATURITY = "0";
        #my $ACCURACY = "0";
        
        my $ANOMALY_SCORE = "0";
        my $SQL_SCORE = "0";
        my $XSS_SCORE = "0";
        my $TROJAN_SCORE = "0";
        my $OUTBOUND_ANOMALY_SCORE = "0";
        my $AUTOMATION_SCORE = "0";
        my $PROFILER_SCORE = "0";
        
        my $CHAIN = 0;
        my $AFTERID = 0;
        
        my $LASTDATA = 0;
        
        my $LINEDATA = "";
        my $RULEDATA = "";
        
        while (<INFILE>) {
            
            # We want the data starting with the SecRule statement after end of the last rule,
            # including the rule ID, and ending at the next SecRule statement (unless the previous SecRule started a chain)
            
            # extract rule data first as one long string, then search within it for score data
            
            # store the line data in a variable ($_ will be cleared later on when other regexes are tested)
            $LINEDATA = $_ ;
            
            # use a variable to store whether the linedata matches any of the regexes
            my $match = 0;
            
            # check for SecRule
            if (m/.*SecRule.*/) {
            
                # if this line is after the RuleID statement, it is the end of the rule data, unless it's part of a chain. If not, it's part of the rule data
                if ( $AFTERID == 1 && $CHAIN == 1 ) {
                    # this line is part of the rule data
                    
                    # reset chain to 0 (chain only affects next SecRule statement)
                    $CHAIN = 0;
                    # check for another chain on this line
                    if ( $LINEDATA =~m/^.*chain.*$/ ) {
                        $CHAIN = 1;
                    }
                    
                    # append the linedata to the ruledata string
                    $RULEDATA .= $LINEDATA;
                    
                } else { 
                    # this is the end of the rule data
                    # search through the rule data string for submatches
                    
                    # extract rule ID
                    if ($RULEDATA =~ m/.*id:'?(\d{6,7})'?.*/) {
                        $RULE_ID = $1;
                        if ($debug) {print "rule ID matched: $RULE_ID \n";}
                    }
                    
                    # extract anomaly score, looking for data like:
                    # setvar:tx.anomaly_score=+{tx.error_anomaly_score}
                    # setvar:tx.anomaly_score=+%{tx.error_anomaly_score}
                    # setvar:tx.anomaly_score=-5
                    
                    # assign variables for submatches within the regex, see: http://www.perlcity.com/perl-regular-expressions.html search for (?{ code })
                    {
                    my $SIGN = "";
                    my $NUMBER = "";
                    if ($RULEDATA =~ m/.*setvar:tx.anomaly_score=([+-])(?{ $SIGN = $^N })%?{(.*?)(?{ $NUMBER = $^N })}.*|.*setvar:tx.anomaly_score=([+-])(?{ $SIGN = $^N })(\d+)(?{ $NUMBER = $^N }).*/) {
                        
                        if ($NUMBER eq "tx.critical_anomaly_score") {
                            #print "$NUMBER is equivalent to 5 \n";
                            $NUMBER = 5;
                        } elsif ($NUMBER eq "tx.error_anomaly_score") {
                            #print "$NUMBER is equivalent to 4 \n";
                            $NUMBER = 4;
                        } elsif ($NUMBER eq "tx.warning_anomaly_score") {
                            #print "$NUMBER is equivalent to 3 \n";
                            $NUMBER = 3;
                        } elsif ($NUMBER eq "tx.notice_anomaly_score") {
                            #print "$NUMBER is equivalent to 2 \n";
                            $NUMBER = 2;
                        }
                        $ANOMALY_SCORE = $SIGN . $NUMBER;
                        if ($debug) {print "Anomaly score is $ANOMALY_SCORE \n";}
                    }
                    }
                    
                    # sql score
                    {
                    my $SIGN = "";
                    my $NUMBER = "";
                    if ($RULEDATA =~ m/.*setvar:tx.sql_injection_score=([+-])(?{ $SIGN = $^N })%?{(.*?)(?{ $NUMBER = $^N })}.*|.*setvar:tx.sql_injection_score=([+-])(?{ $SIGN = $^N })(\d+)(?{ $NUMBER = $^N }).*/) {
                        
                        if ($NUMBER eq "tx.critical_anomaly_score") {
                            #print "$NUMBER is equivalent to 5 \n";
                            $NUMBER = 5;
                        } elsif ($NUMBER eq "tx.error_anomaly_score") {
                            #print "$NUMBER is equivalent to 4 \n";
                            $NUMBER = 4;
                        } elsif ($NUMBER eq "tx.warning_anomaly_score") {
                            #print "$NUMBER is equivalent to 3 \n";
                            $NUMBER = 3;
                        } elsif ($NUMBER eq "tx.notice_anomaly_score") {
                            #print "$NUMBER is equivalent to 2 \n";
                            $NUMBER = 2;
                        }
                        $SQL_SCORE = $SIGN . $NUMBER;
                        if ($debug) {print "SQL injection score is $SQL_SCORE \n";}
                    }
                    }
                    
                    # xss score
                    {
                    my $SIGN = "";
                    my $NUMBER = "";
                    if ($RULEDATA =~ m/.*setvar:tx.xss_score=([+-])(?{ $SIGN = $^N })%?{(.*?)(?{ $NUMBER = $^N })}.*|.*setvar:tx.xss_score=([+-])(?{ $SIGN = $^N })(\d+)(?{ $NUMBER = $^N }).*/) {
                        
                        if ($NUMBER eq "tx.critical_anomaly_score") {
                            #print "$NUMBER is equivalent to 5 \n";
                            $NUMBER = 5;
                        } elsif ($NUMBER eq "tx.error_anomaly_score") {
                            #print "$NUMBER is equivalent to 4 \n";
                            $NUMBER = 4;
                        } elsif ($NUMBER eq "tx.warning_anomaly_score") {
                            #print "$NUMBER is equivalent to 3 \n";
                            $NUMBER = 3;
                        } elsif ($NUMBER eq "tx.notice_anomaly_score") {
                            #print "$NUMBER is equivalent to 2 \n";
                            $NUMBER = 2;
                        }
                        $XSS_SCORE = $SIGN . $NUMBER;
                        if ($debug) {print "XSS score is $XSS_SCORE \n";}
                    }
                    }
                    
                    # trojan score
                    {
                    my $SIGN = "";
                    my $NUMBER = "";
                    if ($RULEDATA =~ m/.*setvar:tx.trojan_score=([+-])(?{ $SIGN = $^N })%?{(.*?)(?{ $NUMBER = $^N })}.*|.*setvar:tx.trojan_score=([+-])(?{ $SIGN = $^N })(\d+)(?{ $NUMBER = $^N }).*/) {
                        
                        if ($NUMBER eq "tx.critical_anomaly_score") {
                            #print "$NUMBER is equivalent to 5 \n";
                            $NUMBER = 5;
                        } elsif ($NUMBER eq "tx.error_anomaly_score") {
                            #print "$NUMBER is equivalent to 4 \n";
                            $NUMBER = 4;
                        } elsif ($NUMBER eq "tx.warning_anomaly_score") {
                            #print "$NUMBER is equivalent to 3 \n";
                            $NUMBER = 3;
                        } elsif ($NUMBER eq "tx.notice_anomaly_score") {
                            #print "$NUMBER is equivalent to 2 \n";
                            $NUMBER = 2;
                        }
                        $TROJAN_SCORE = $SIGN . $NUMBER;
                        if ($debug) {print "Trojan score is $TROJAN_SCORE \n";}
                    }
                    }
                    
                    # outbound anomaly score
                    {
                    my $SIGN = "";
                    my $NUMBER = "";
                    if ($RULEDATA =~ m/.*setvar:tx.outbound_anomaly_score=([+-])(?{ $SIGN = $^N })%?{(.*?)(?{ $NUMBER = $^N })}.*|.*setvar:tx.outbound_anomaly_score=([+-])(?{ $SIGN = $^N })(\d+)(?{ $NUMBER = $^N }).*/) {
                        
                        if ($NUMBER eq "tx.critical_anomaly_score") {
                            #print "$NUMBER is equivalent to 5 \n";
                            $NUMBER = 5;
                        } elsif ($NUMBER eq "tx.error_anomaly_score") {
                            #print "$NUMBER is equivalent to 4 \n";
                            $NUMBER = 4;
                        } elsif ($NUMBER eq "tx.warning_anomaly_score") {
                            #print "$NUMBER is equivalent to 3 \n";
                            $NUMBER = 3;
                        } elsif ($NUMBER eq "tx.notice_anomaly_score") {
                            #print "$NUMBER is equivalent to 2 \n";
                            $NUMBER = 2;
                        }
                        $OUTBOUND_ANOMALY_SCORE = $SIGN . $NUMBER;
                        if ($debug) {print "Outbound anomaly score is $OUTBOUND_ANOMALY_SCORE \n";}
                    }
                    }
                    
                    # automation score
                    {
                    my $SIGN = "";
                    my $NUMBER = "";
                    if ($RULEDATA =~ m/.*setvar:tx.automation_score=([+-])(?{ $SIGN = $^N })%?{(.*?)(?{ $NUMBER = $^N })}.*|.*setvar:tx.automation_score=([+-])(?{ $SIGN = $^N })(\d+)(?{ $NUMBER = $^N }).*/) {
                        
                        if ($NUMBER eq "tx.critical_anomaly_score") {
                            #print "$NUMBER is equivalent to 5 \n";
                            $NUMBER = 5;
                        } elsif ($NUMBER eq "tx.error_anomaly_score") {
                            #print "$NUMBER is equivalent to 4 \n";
                            $NUMBER = 4;
                        } elsif ($NUMBER eq "tx.warning_anomaly_score") {
                            #print "$NUMBER is equivalent to 3 \n";
                            $NUMBER = 3;
                        } elsif ($NUMBER eq "tx.notice_anomaly_score") {
                            #print "$NUMBER is equivalent to 2 \n";
                            $NUMBER = 2;
                        }
                        $AUTOMATION_SCORE = $SIGN . $NUMBER;
                        if ($debug) {print "Outbound anomaly score is $AUTOMATION_SCORE \n";}
                    }
                    }
                    
                    # profiler score
                    {
                    my $SIGN = "";
                    my $NUMBER = "";
                    if ($RULEDATA =~ m/.*setvar:tx.profiler_score=([+-])(?{ $SIGN = $^N })%?{(.*?)(?{ $NUMBER = $^N })}.*|.*setvar:tx.profiler_score=([+-])(?{ $SIGN = $^N })(\d+)(?{ $NUMBER = $^N }).*/) {
                        
                        if ($NUMBER eq "tx.critical_anomaly_score") {
                            #print "$NUMBER is equivalent to 5 \n";
                            $NUMBER = 5;
                        } elsif ($NUMBER eq "tx.error_anomaly_score") {
                            #print "$NUMBER is equivalent to 4 \n";
                            $NUMBER = 4;
                        } elsif ($NUMBER eq "tx.warning_anomaly_score") {
                            #print "$NUMBER is equivalent to 3 \n";
                            $NUMBER = 3;
                        } elsif ($NUMBER eq "tx.notice_anomaly_score") {
                            #print "$NUMBER is equivalent to 2 \n";
                            $NUMBER = 2;
                        }
                        $PROFILER_SCORE = $SIGN . $NUMBER;
                        if ($debug) {print "Profiler anomaly score is $PROFILER_SCORE \n";}
                    }
                    }
                    
                    # if the rule number is not empty, print the data to the config file
                    if ( $RULE_ID ne "") {
                        print "Printing data for rule $RULE_ID from file $TABLENAME \n";
                        print OUTFILE "$RULE_ID\t$TABLENAME\t\t$ANOMALY_SCORE\t$SQL_SCORE\t$XSS_SCORE\t$TROJAN_SCORE\t$OUTBOUND_ANOMALY_SCORE\t$AUTOMATION_SCORE\t$PROFILER_SCORE \n";
                    }
                    
                    # now that all the submatches are done, reset the ruledata string to the current line only
                    $RULEDATA = $LINEDATA;
                    
                    # reset all the rule data variables for the next rule
                    $ANOMALY_SCORE = "0";
                    $SQL_SCORE = "0";
                    $XSS_SCORE = "0";
                    $TROJAN_SCORE = "0";
                    $OUTBOUND_ANOMALY_SCORE = "0";
                    $AUTOMATION_SCORE = "0";
                    $PROFILER_SCORE = "0";
                    
                    # reset after ID and chain booleans to 0
                    $AFTERID = 0;
                    $CHAIN = 0;
                }
                
                # set a flag so we know this rule matched the regex
                $match = 1;
                
            }
            
            if (m/.*id:'?\d{6,7}'?.*$/) {
                
                # change the rule ID switch
                $AFTERID = 1;
                
                # check for chain (not always on the same line as the SecRule statement)
                if ( $LINEDATA =~m/^.*chain.*$/ ) {
                    $CHAIN = 1;
                }
                
                # append the line data to the rule data
                $RULEDATA .= $LINEDATA;
                $match = 1;
                
            } 
            
            # if none of the previous matches have been made
            if ($match == 0) {
            
                # check for chain (not always on the same line as the SecRule statement)
                if ( $LINEDATA =~m/^.*chain.*$/ ) {
                    $CHAIN = 1;
                }
                
                # this line is just a part of the rule data
                $RULEDATA .= $LINEDATA;
                
            }
            
            
        }


        close(INFILE);
    
        # extract and print the last set of data

        # extract rule ID
        if ($RULEDATA =~ m/.*id:'?(\d{6,7})'?.*/) {
            $RULE_ID = $1;
            if ($debug) {print "rule ID matched: $RULE_ID \n";}
        }
        
        # extract anomaly score
        # setvar:tx.anomaly_score=+%{tx.error_anomaly_score}
        # setvar:tx.anomaly_score=-5
        
        # assign variables for submatches within the regex, see: http://www.perlcity.com/perl-regular-expressions.html search for (?{ code })
        
        {
        my $SIGN = "";
        my $NUMBER = "";
        if ($RULEDATA =~ m/.*setvar:tx.anomaly_score=([+-])(?{ $SIGN = $^N })%?{(.*?)(?{ $NUMBER = $^N })}.*|.*setvar:tx.anomaly_score=([+-])(?{ $SIGN = $^N })(\d+)(?{ $NUMBER = $^N }).*/) {
            
            if ($NUMBER eq "tx.critical_anomaly_score") {
                #print "$NUMBER is equivalent to 5 \n";
                $NUMBER = 5;
            } elsif ($NUMBER eq "tx.error_anomaly_score") {
                #print "$NUMBER is equivalent to 4 \n";
                $NUMBER = 4;
            } elsif ($NUMBER eq "tx.warning_anomaly_score") {
                #print "$NUMBER is equivalent to 3 \n";
                $NUMBER = 3;
            } elsif ($NUMBER eq "tx.notice_anomaly_score") {
                #print "$NUMBER is equivalent to 2 \n";
                $NUMBER = 2;
            }
            $ANOMALY_SCORE = $SIGN . $NUMBER;
            if ($debug) {print "Anomaly score is $ANOMALY_SCORE \n";}
        }
        }
        
        # sql score
        {
        my $SIGN = "";
        my $NUMBER = "";
        if ($RULEDATA =~ m/.*setvar:tx.sql_injection_score=([+-])(?{ $SIGN = $^N })%?{(.*?)(?{ $NUMBER = $^N })}.*|.*setvar:tx.sql_injection_score=([+-])(?{ $SIGN = $^N })(\d+)(?{ $NUMBER = $^N }).*/) {
            
            if ($NUMBER eq "tx.critical_anomaly_score") {
                #print "$NUMBER is equivalent to 5 \n";
                $NUMBER = 5;
            } elsif ($NUMBER eq "tx.error_anomaly_score") {
                #print "$NUMBER is equivalent to 4 \n";
                $NUMBER = 4;
            } elsif ($NUMBER eq "tx.warning_anomaly_score") {
                #print "$NUMBER is equivalent to 3 \n";
                $NUMBER = 3;
            } elsif ($NUMBER eq "tx.notice_anomaly_score") {
                #print "$NUMBER is equivalent to 2 \n";
                $NUMBER = 2;
            }
            $SQL_SCORE = $SIGN . $NUMBER;
            if ($debug) {print "SQL injection score is $SQL_SCORE \n";}
        }
        }
        
        # xss score
        {
        my $SIGN = "";
        my $NUMBER = "";
        if ($RULEDATA =~ m/.*setvar:tx.xss_score=([+-])(?{ $SIGN = $^N })%?{(.*?)(?{ $NUMBER = $^N })}.*|.*setvar:tx.xss_score=([+-])(?{ $SIGN = $^N })(\d+)(?{ $NUMBER = $^N }).*/) {
            
            if ($NUMBER eq "tx.critical_anomaly_score") {
                #print "$NUMBER is equivalent to 5 \n";
                $NUMBER = 5;
            } elsif ($NUMBER eq "tx.error_anomaly_score") {
                #print "$NUMBER is equivalent to 4 \n";
                $NUMBER = 4;
            } elsif ($NUMBER eq "tx.warning_anomaly_score") {
                #print "$NUMBER is equivalent to 3 \n";
                $NUMBER = 3;
            } elsif ($NUMBER eq "tx.notice_anomaly_score") {
                #print "$NUMBER is equivalent to 2 \n";
                $NUMBER = 2;
            }
            $XSS_SCORE = $SIGN . $NUMBER;
            if ($debug) {print "XSS score is $XSS_SCORE \n";}
        }
        }
        
        # trojan score
        {
        my $SIGN = "";
        my $NUMBER = "";
        if ($RULEDATA =~ m/.*setvar:tx.trojan_score=([+-])(?{ $SIGN = $^N })%?{(.*?)(?{ $NUMBER = $^N })}.*|.*setvar:tx.trojan_score=([+-])(?{ $SIGN = $^N })(\d+)(?{ $NUMBER = $^N }).*/) {
            
            if ($NUMBER eq "tx.critical_anomaly_score") {
                #print "$NUMBER is equivalent to 5 \n";
                $NUMBER = 5;
            } elsif ($NUMBER eq "tx.error_anomaly_score") {
                #print "$NUMBER is equivalent to 4 \n";
                $NUMBER = 4;
            } elsif ($NUMBER eq "tx.warning_anomaly_score") {
                #print "$NUMBER is equivalent to 3 \n";
                $NUMBER = 3;
            } elsif ($NUMBER eq "tx.notice_anomaly_score") {
                #print "$NUMBER is equivalent to 2 \n";
                $NUMBER = 2;
            }
            $TROJAN_SCORE = $SIGN . $NUMBER;
            if ($debug) {print "Trojan score is $TROJAN_SCORE \n";}
        }
        }
        
        # outbound anomaly score
        {
        my $SIGN = "";
        my $NUMBER = "";
        if ($RULEDATA =~ m/.*setvar:tx.outbound_anomaly_score=([+-])(?{ $SIGN = $^N })%?{(.*?)(?{ $NUMBER = $^N })}.*|.*setvar:tx.outbound_anomaly_score=([+-])(?{ $SIGN = $^N })(\d+)(?{ $NUMBER = $^N }).*/) {
            
            if ($NUMBER eq "tx.critical_anomaly_score") {
                #print "$NUMBER is equivalent to 5 \n";
                $NUMBER = 5;
            } elsif ($NUMBER eq "tx.error_anomaly_score") {
                #print "$NUMBER is equivalent to 4 \n";
                $NUMBER = 4;
            } elsif ($NUMBER eq "tx.warning_anomaly_score") {
                #print "$NUMBER is equivalent to 3 \n";
                $NUMBER = 3;
            } elsif ($NUMBER eq "tx.notice_anomaly_score") {
                #print "$NUMBER is equivalent to 2 \n";
                $NUMBER = 2;
            }
            $OUTBOUND_ANOMALY_SCORE = $SIGN . $NUMBER;
            if ($debug) {print "Outbound anomaly score is $OUTBOUND_ANOMALY_SCORE \n";}
        }
        }
        
        # automation score
        {
        my $SIGN = "";
        my $NUMBER = "";
        if ($RULEDATA =~ m/.*setvar:tx.automation_score=([+-])(?{ $SIGN = $^N })%?{(.*?)(?{ $NUMBER = $^N })}.*|.*setvar:tx.automation_score=([+-])(?{ $SIGN = $^N })(\d+)(?{ $NUMBER = $^N }).*/) {
            #my $SIGN = $1;
            #my $NUMBER = $2;
            #print "sign is $SIGN, number is $NUMBER \n";
            
            if ($NUMBER eq "tx.critical_anomaly_score") {
                #print "$NUMBER is equivalent to 5 \n";
                $NUMBER = 5;
            } elsif ($NUMBER eq "tx.error_anomaly_score") {
                #print "$NUMBER is equivalent to 4 \n";
                $NUMBER = 4;
            } elsif ($NUMBER eq "tx.warning_anomaly_score") {
                #print "$NUMBER is equivalent to 3 \n";
                $NUMBER = 3;
            } elsif ($NUMBER eq "tx.notice_anomaly_score") {
                #print "$NUMBER is equivalent to 2 \n";
                $NUMBER = 2;
            }
            $AUTOMATION_SCORE = $SIGN . $NUMBER;
            if ($debug) {print "Outbound anomaly score is $AUTOMATION_SCORE \n";}
        }
        }
        
        # profiler score
        {
        my $SIGN = "";
        my $NUMBER = "";
        if ($RULEDATA =~ m/.*setvar:tx.profiler_score=([+-])(?{ $SIGN = $^N })%?{(.*?)(?{ $NUMBER = $^N })}.*|.*setvar:tx.profiler_score=([+-])(?{ $SIGN = $^N })(\d+)(?{ $NUMBER = $^N }).*/) {
            #my $SIGN = $1;
            #my $NUMBER = $2;
            #print "sign is $SIGN, number is $NUMBER \n";
            
            if ($NUMBER eq "tx.critical_anomaly_score") {
                #print "$NUMBER is equivalent to 5 \n";
                $NUMBER = 5;
            } elsif ($NUMBER eq "tx.error_anomaly_score") {
                #print "$NUMBER is equivalent to 4 \n";
                $NUMBER = 4;
            } elsif ($NUMBER eq "tx.warning_anomaly_score") {
                #print "$NUMBER is equivalent to 3 \n";
                $NUMBER = 3;
            } elsif ($NUMBER eq "tx.notice_anomaly_score") {
                #print "$NUMBER is equivalent to 2 \n";
                $NUMBER = 2;
            }
            $PROFILER_SCORE = $SIGN . $NUMBER;
            if ($debug) {print "Profiler anomaly score is $PROFILER_SCORE \n";}
        }
        }
        
        # if the rule number is not empty, print the data to the config file
        if ( $RULE_ID ne "") {
            print "Printing data for rule $RULE_ID from file $TABLENAME \n";
            print OUTFILE "$RULE_ID\t$TABLENAME\t\t$ANOMALY_SCORE\t$SQL_SCORE\t$XSS_SCORE\t$TROJAN_SCORE\t$OUTBOUND_ANOMALY_SCORE\t$AUTOMATION_SCORE\t$PROFILER_SCORE \n";
        }
        
        # now that all the submatches are done, reset the ruledata string to the current line only
        $RULEDATA = $LINEDATA;
        
        # reset all the rule data variables for the next rule
        $ANOMALY_SCORE = "0";
        $SQL_SCORE = "0";
        $XSS_SCORE = "0";
        $TROJAN_SCORE = "0";
        $OUTBOUND_ANOMALY_SCORE = "0";
        $AUTOMATION_SCORE = "0";
        $PROFILER_SCORE = "0";
        
        # reset after ID and chain booleans to 0
        $AFTERID = 0;
        $CHAIN = 0;
                
    }
}
close(OUTFILE);

print "done\n";



# this sub returns a list of modsecurity crs config files in a directory
sub list {
  # define the top dir and check it really is a directory
  my ($dir) = @_; # "@_" is the subroutine argument
  return unless -d $dir;
  
  # create an array to hold all of the filenames
  my @files;
  if (opendir my $dh, $dir) {
    my @list; # array to hold a list of the files in dir
    my $file;

    while ($file = readdir $dh) {
      next if $file eq '.' || $file eq '..'; # ignore unix "this folder" and "parent folder"
      push @list, $file; # push each file into the list array
    }
    # close the top level directory
    closedir $dh;
    
    # for each file in the list, assemble the complete filename and push it to the files array
    for $file (@list) {
      if (-f "$dir/$file") {
	if ($file =~ m/^modsecurity_crs.*\.conf$/) {
	  push @files, "$dir/$file";
	} else {
	  # do nothing - the file didn't match the regex
	}
      } else {
	# if $file is a directory, call this subroutine again with the directory as the search path
	push @files, list ("$dir/$file") if -d "$dir/$file"; 
      }
    }
  }

  return @files;
}



exit 0;