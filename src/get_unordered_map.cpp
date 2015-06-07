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
#include <cstring> // need this for strlen, which is used in rc = on line ~42
#include <sqlite3.h>
//#include <vector>
#include <unordered_map>

#include "get_unordered_map.h"

using namespace std;
using std::unordered_map;

// this function takes the database name and sql statement to be executed and returns an unordered map of the results
unordered_map<string,int> get_unordered_map(string database, const char* sql, bool debug) {
  
  // create map to hold results - maps a string value to an integer ID
  unordered_map<string,int> results;
  
  
  sqlite3 *db; // pointer to db memory location
  char *zErrMsg; // pointer to error memory location
  int rc;
  
  // rc is "response code" from sqlite
  rc = sqlite3_open(database.c_str(), &db);
  
  if (rc) {
    cerr << "Can't open the database: " << sqlite3_errmsg(db) << endl;
    sqlite3_close(db);
    exit(1);
  } else {
    if (debug) {cout << "Opened database successfully" << endl;}
  }
  
  const char *pzTail; // sqlite3_prepare compiles first statement only, *pzTail points to uncompiled portion
  sqlite3_stmt *stmt; // pointer to location of compiled statement
 
    
  // update sqlite response code to store result of prepared statement compilation
  rc = sqlite3_prepare(db, sql, strlen(sql), &stmt, &pzTail);
   
   
  // if the compilation failed, print the error message.
  if ( rc == SQLITE_ERROR ) {
    cerr << "SQLite error: " << sqlite3_errmsg(db) << endl;
  }
  // else if the compilation was successful, continue
  else if ( rc == SQLITE_OK ) {
    // execute pre-compiled sqlite command
    int row = 0;
    int column;
    
    rc = sqlite3_step(stmt);
    // possible values returned from step are SQLITE_BUSY, SQLITE_DONE, SQLITE_ROW, SQLITE_ERROR or SQLITE_MISUSE.
    
    while (rc != SQLITE_DONE) {
      // if error or misuse, print the error and end exit
      if ( (rc == SQLITE_ERROR ) || (rc == SQLITE_MISUSE) ) {
	cerr << "SQLite Error or misuse: " << sqlite3_errmsg(db) << endl;
	// end
	break;
      }
      // else if database is busy, print message and continue to loop
      else if (rc == SQLITE_BUSY) {
	cerr << "Database busy" << endl;
      }
      // else if function returned a row, do something with it
      else if (rc == SQLITE_ROW) {
        int column_nos = sqlite3_column_count(stmt);
        
        // map requries two columns in row. If there is more than two columns, something has gone wrong
        if (column_nos != 2) {
            cerr << "Data returned has an unexpected number of columns (expected 2). Aborting..." << endl;
            break;
        } else {
            // add the row data to the results map - first column holds an ID number and the second holds a value which will be the map's key
            int ID = sqlite3_column_int(stmt, 0);
            string keyvalue = reinterpret_cast<const char*>(sqlite3_column_text(stmt,1));
            if (debug) {cout << "ID is " << ID << ", key value is " << keyvalue << endl;}
            results[keyvalue] = ID;
        }
        
        
	// step statement again
	rc = sqlite3_step(stmt);
      }
    }
  }
          
  // now that we are finished with this statement it can be destroyed to free resources
  sqlite3_finalize(stmt);
   
  // close database
  if(db) {
    sqlite3_close(db);
    if (debug) {cout << "Closed database" << endl;}
  }  
 
  return results;
}