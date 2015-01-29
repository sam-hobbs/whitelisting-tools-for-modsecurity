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

#include <iostream>
#include <string>
#include <boost/regex.hpp>
#include <fstream>

using namespace std;

string setlogfile (bool debug) {
  
  string logfile; // string to store the name of the logfile that will be processed
  cout << "Please type the full path to the logfile you want to process: ";
  getline (cin, logfile); // store the line that was typed as the string "logfile" 
  
  boost::regex logregex("[\\w\\/]+\\.log");
  
  while (! boost::regex_match(logfile, logregex)) {
    cout << "Not a valid log file, expected something like /path/to/logfile.log" << endl;
    cout << "Try again: ";
    getline (cin, logfile);
  }
  if (debug) { cout << "OK. Logfile is " << logfile << endl;}
  return logfile;
}








string setdblocation (bool debug) {
  string database; // string to store location of database
  cout << "Please type the full path to your chosen database location: ";
  getline (cin, database); // store input line as string "db"
  boost::regex dbregex("[a-z|\\/]+\\.db");
  while (! boost::regex_match(database, dbregex)) {
    cout << "Not a valid database file, expected something like /path/to/database.db" << endl;
    cout << "Try again: ";
    getline (cin, database);
  }
  if (debug) { cout << "OK. Database location is " << database << endl;}
  return database;
}