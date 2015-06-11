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

using namespace std;

void help() {
  cout << "This program follows the usual GNU command line syntax, with long options starting" << endl;
  cout << "with two dashes (`-'). A summary of options is included below." << endl;

  cout << "\t -c, --configdir" << endl;
  cout << "\t\t Use configuration files from a specified directory. Searches for" << endl;
  cout << "\t\t files named `template.sql' and `rulesdata.conf'. Overridden by" << endl;
  cout << "\t\t the use of `--template' and `--rulesdata'." << endl;
  cout << endl;
  cout << "\t -d, --debug" << endl;
  cout << "\t\t Turn on debugging." << endl;
  cout << endl;
  cout << "\t -f, --force" << endl;
  cout << "\t\t Skips through inteactive questions/warnings/prompts (use this if" << endl;
  cout << "\t\t you are running auditlog2db in an script)." << endl;
  cout << endl;
  cout << "\t -h, --help" << endl;
  cout << "\t\t Show summary of options." << endl;
  cout << endl;
  cout << "\t -i, --input" << endl;
  cout << "\t\t Input file (an Apache ModSecurity audit log file)." << endl;
  cout << endl;
  cout << "\t -o, --output" << endl;
  cout << "\t\t Output: a sqlite database. If the database does not currently" << endl;
  cout << "\t\t exist it will be created." << endl;
  cout << endl;
  cout << "\t -q, --quiet" << endl;
  cout << "\t\t Quiet mode; eliminate informational messages." << endl;
  cout << endl;
  cout << "\t -r, --rulesdata" << endl;
  cout << "\t\t Specify a rulesdata file to use (overrides `--configdir')." << endl;
  cout << endl;
  cout << "\t -t, --template" << endl;
  cout << "\t\t Specify a SQL template file for creation of new sqlite databases" << endl;
  cout << "\t\t (overrides `--configdir')" << endl;
  cout << endl;
  cout << "\t -v, --version" << endl;
  cout << "\t\t Show version of program." << endl;
  cout << endl;
  cout << "For more information see the man file e.g. `man auditlog2db'" << endl;
}