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


#ifndef GET_UNORDERED_MAP
#define GET_UNORDERED_MAP


#include <iostream>
#include <string>
#include <cstring> // need this for strlen, which is used in rc = on line ~42
#include <sqlite3.h>
//#include <vector>
#include <unordered_map>

#include "get_unordered_map.h"

using namespace std;
using std::unordered_map;

// this function takes the database name and sql statement to be executed and returns an unordered map of the results
unordered_map<string,int> get_unordered_map(string database, const char* sql, bool debug);


#endif