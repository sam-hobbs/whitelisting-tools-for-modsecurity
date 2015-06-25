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

// use a guard to avoid multiple definitions
// if logchop hasn't been defined already
#ifndef LOGCHOP
#define LOGCHOP

// Definition of chop
#include <iostream>
#include <string>
#include <cstring>
#include <sqlite3.h>
#include <vector>
#include <fstream>
#include <boost/regex.hpp>
#include <chrono>




// standard library header for ordered map
#include <unordered_map>
#include <get_unordered_map.h> // part of this program



using namespace std;
using std::vector;
using std::unordered_map;


int logchop(string database, string logfile, string rulesdatafile, vector<pair<int,string>> results, int debug, int force);

#endif