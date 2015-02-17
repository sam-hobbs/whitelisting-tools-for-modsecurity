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

// returns a 2D vector of the line numbers containing headers

#include <iostream>
#include <string>
#include <boost/regex.hpp>
#include <vector>
#include <fstream>

#include "headerlines.h"

using namespace std;
using std::vector;

vector<pair<int,string>> headerlines(string logfile, int debug) {
  
  // 2D vector to hold results
  vector<pair<int,string>> results;
  
  // search through modsecurity log file for line numbers of headers, save them along with the line numbers they appear on
  boost::regex headerregex("(^\\-\\-\\w{8}\\-[A-Z]\\-\\-)");
  
  int line = 0;
  int id = 0;
  string str;
  ifstream in(logfile);
  boost::cmatch matches;


  while (getline(in, str)) {
    ++line;
    // if the current line is a header, add a new pair to the vector
    if (boost::regex_match(str.c_str(), matches, headerregex)) {
      //matches[0] contains the original string. matches[n] contains a submatch for each matching subexpression
      if (debug) { cout << "header matched on line " << line << " : " << matches[0] << endl;}
      string header = matches[0];
      
      // create a pair from the line number and the header data
      pair<int,string> linedata = {line, header};
      
      // push the linedata pair to the end of the results vector
      results.push_back(linedata);
    }
  }
  return results;
}
