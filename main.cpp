/*
    This file is part of auditlog2db.

    auditlog2db is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    auditlog2db is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with auditlog2db.  If not, see <http://www.gnu.org/licenses/>.
*/

// inlcude 3rd party libraries
#include <iostream>
#include <string>
#include <boost/regex.hpp>
#include <sqlite3.h>
#include <fstream>
#include <vector>

// include other bits of this program
#include "headerlines_vector_pair.h"
#include "prompt_inputs.h"
#include "logchop.h"


using namespace std;
using std::vector;

bool debug = 0; // debugging defaults to off
bool force = 0; // force option defaults to off

//========================================================================================================
// 1. Parse commandline arguments
// 2. Check if database name and logfile name were specified with command line option, if not prompt user
// 3. Run headerlines function to get a list of header locations within the log file
// 4. Run logchop function to read log file and split at header locations, insert into database
//========================================================================================================



// main function has two arguments: first (argc) is the number of commandline arguments
// second (argv) is an array of pointers to the options. NB: argv[0] is the program name


int main (int argc , char **argv) {
  // =======================================================================================================
  // 1. Parse command line arguments
  // =======================================================================================================

  // store command line arguments as variables
  string progname = argv[0]; // program name is always argv[0]
  string database;
  string logfile;

  
  for ( int arg = 1; arg < argc; ++arg) {
    if (argv[arg] == string("-d")) {
      debug = 1;
      cout << "Commandline option - debugging is ON" << endl;
    } else if (argv[arg] == string("-f")) {
      force = 1;
      cout << "Commandline option - force is ON" << endl;
    } else if (argv[arg] == string("-o") && arg < argc -1) { // if -o option is used and it is not the last argument
      database = argv[arg+1]; // set database equal to the argument following -o
      cout << "Commandline option - database location is: " << database << endl;
    } else if (argv[arg] == string("-i") && arg < argc -1) { // if -i option is used and it is not the last argument
      logfile = argv[arg+1]; // set logfile equal to the argument following -i
      cout << "Commandline option - logfile is: " << logfile << endl;
    } else if (argv[arg-1] != string("-o") && argv[arg-1] != string("-i") ) { // if argument does not match one of the above, it's either the second part of a command like -o or -i, or it's unexpected
      cerr << "Unexpected commandline argument (will be ignored): " << argv[arg] << endl;
    }
  }

  
  
  // =======================================================================================================
  // 2. Check if database name and logfile name were specified with command line option, if not prompt user
  // =======================================================================================================
  
  // the declarations and definitions for setdblocation and setlogfile are in prompt_inputs.cpp and prompt_inputs.h
  if (database == "") {
    cout << "Database location has not been specified" << endl;
    database = setdblocation(debug);
  }
  
  if (logfile == "") {
    cout << "Logfile location has not been specified" << endl;
    logfile = setlogfile(debug);
  }
  
  
  
  // =======================================================================================================
  // 3. Run headerlines function to get a list of header locations within the log file
  // =======================================================================================================
  
  // the declaration and definition for headerlines_vector_pair is in headerlines_vector_pair.cpp and headerlines_vector_pair.h
  vector<pair<int,string>> results = headerlines_vector_pair(logfile, debug);

  
  // =======================================================================================================
  // 4. Run logchop function to read log file and split at header locations, insert into database
  // =======================================================================================================
  
  
  int logchop_status = logchop(database, logfile, results, debug, force);
  
  
  
  return 0;
}