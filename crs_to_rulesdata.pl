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
    
    # open the input file read only
    open (INFILE, "$filename") || die "problem opening $filename \n";

    # variables for holding temporary data
    my $line = 0;
    my $RULE_ID = "";
    my $SEVERITY = "0";
    my $PRINTED = 0;

    # search severity and ruleid in different combinations
    while (<INFILE>) {
    ++$line;
      # if the line starts with SecRule, clear the variables
      if (m/^\s*SecRule.*$/) {
	# some SecRule statements don't set a severity (e.g. select_statement_count rules in SQLI ruleset), so print if with the default severity of 0 if it hasn't already been printed
	if (($RULE_ID ne "") && ($PRINTED != 1)) {
	  print "writing data for rule ID $RULE_ID, table $TABLENAME, severity unknown \n";
	  print OUTFILE "$RULE_ID $TABLENAME $SEVERITY \n";
	}
	if ($debug) {print "SecRule detected on line $line, clearing variables \n";}
	$SEVERITY = "0";
	$RULE_ID = "";
	$PRINTED = 0;
      }
      
      # possibilities:
      # 1. severity and ID on one line, in that order
      # 2. ID and severity on one line, in that order
      # 3. severity on its own
      # 4. ID on its own
      
      # try each possibility in turn, check after each line to see if we have both variables
      if (m/^.*severity:\'([0-9])\'.*id:\'([0-9]{6})\'.*$/) {
	$SEVERITY = $1;
	$RULE_ID = $2;
      } elsif (m/^.*id:\'([0-9]{6})\'.*severity:\'([0-9])\'.*$/) {
	$SEVERITY = $2;
	$RULE_ID = $1;
      } elsif (m/^.*severity:\'([0-9])\'.*$/) {
	$SEVERITY = $1;
      } elsif (m/^.*id:\'([0-9]{6})\'.*$/) {
	$RULE_ID = $1;
      }
      
      # if rule ID and severity have both been matched and not printed already, print the data to the output file
      if (($RULE_ID ne "") && ($SEVERITY ne "0") && ($PRINTED != 1)) {
	print "writing data for rule ID $RULE_ID, table $TABLENAME, severity $SEVERITY \n";
	print OUTFILE "$RULE_ID $TABLENAME $SEVERITY\n";
	$PRINTED = 1;
      }
    }
    
    # capture last variables that may not have been printed yet
    if (($RULE_ID ne "") && ($PRINTED != 1)) {
	  print "writing data for rule ID $RULE_ID, table $TABLENAME, severity unknown \n";
	  print OUTFILE "$RULE_ID $TABLENAME $SEVERITY \n";
    }

    close(INFILE);
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