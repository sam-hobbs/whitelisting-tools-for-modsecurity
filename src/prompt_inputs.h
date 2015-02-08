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
// if prompt_inputs hasn't been defined already

#ifndef PROMPT_INPUTS
#define PROMPT_INPUTS


#include <iostream>
#include <string>
#include <boost/regex.hpp>
#include <fstream>

using namespace std;

string setlogfile (bool debug);
string setdblocation (bool debug);

#endif