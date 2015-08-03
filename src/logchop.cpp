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
#include <cstring>
#include <sqlite3.h>
#include <vector>
#include <fstream>
#include <boost/regex.hpp>
#include <chrono>

#include <time.h>
#include <sstream> // for converting time_t to str

// standard library header for ordered map
#include <unordered_map>
#include <get_unordered_map.h> // part of this program
#include <ruledata.h> // rule data structure



using namespace std;
using std::vector;
using std::unordered_map;

using std::string;
//using std::sstream;
using std::stringstream;

// convert Apache log time to unix time using this function http://www.thejach.com/view/2012/7/apaches_common_log_format_datetime_converted_to_unix_timestamp_with_c
//#include <string>

/*
 * Parses apache logtime into tm, converts to time_t, and reformats to str.
 * logtime should be the format: day/month/year:hour:minute:second zone
 * day = 2*digit
 * month = 3*letter
 * year = 4*digit
 * hour = 2*digit
 * minute = 2*digit
 * second = 2*digit
 * zone = (`+' | `-') 4*digit
 *
 * e.g. 04/Apr/2012:10:37:29 -0500
 */
string logtimeToUnix(const string& logtime) {
  struct tm tm;
  time_t t;
  if (strptime(logtime.c_str(), "%d/%b/%Y:%H:%M:%S %Z", &tm) == NULL)
    return "-";
  
  tm.tm_isdst = 0; // Force dst off
  // Parse the timezone, the five digits start with the sign at idx 21.
  int hours = 10*(logtime[22] - '0') + logtime[23] - '0';
  int mins = 10*(logtime[24] - '0') + logtime[25] - '0';
  int off_secs = 60*60*hours + 60*mins;
  if (logtime[21] == '-')
    off_secs *= -1;

  t = mktime(&tm);
  if (t == -1)
    return "-";
  t -= timezone; // Local timezone
  t += off_secs;

  string retval;
  stringstream stream;
  stream << t;
  stream >> retval;
  return retval;
}








// function to return an ID (used as the primary key in the database) from the C++ map (which is a reverse-map of the database i.e. the key is the value, and the value is the ID)
// using a reference (&) to the unordered_map so that the changes made to the map inside the function are not lost
int ID_from_map(string key, unordered_map<string, int>& mymap, int debug) {
    
    if (key == "") { // if the key is an empty string, return 0 - the bind_ID function will check for this later and not bind anything, resulting in NULL in the database 
        return 0;
    }
    
    auto iterator = mymap.find(key);
    if (iterator == mymap.end()) { // if the key does not exist in the map
        
        if(debug) {cout << "adding key " << key << " to the map";}
        
        // we need to know what the highest ID in the map is before we insert a new pair
        int maxID = 1;
        
        for (auto &it : mymap) { // iterate through map and find highest ID
            if (it.second >= maxID) {
                maxID = it.second + 1; // new ID must be greater than all other IDs in the map
            }
        }
        if(debug) {cout << ", ID is " << maxID << endl;}
        
        mymap.insert({key,maxID}); // add new key & value pair to the map
        return maxID; // return the ID value for the key we just added
        
    } else {
        if(debug){cout << "found key " << key << " in the map, ID is " << iterator->second << endl;}
        return iterator->second;
    }
}







void commit_maps(sqlite3 *db, const char *sql, unordered_map<string, int>& mymap, int debug) {
    
    //sql something like "INSERT INTO table (something_ID, something) VALUES (:id, :value);";
    
    // prepare sql statement
    sqlite3_stmt *stmt;
    const char *pzTail;
    
    int prepare_rc = sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, &pzTail);
    if( prepare_rc != SQLITE_OK ){
      cerr << "SQL error compiling the prepared statement" << endl;
      cerr << "The error was: "<< sqlite3_errmsg(db) << endl;
    } else {
      if (debug) {cout << "Prepared statement was compiled successfully" << endl;}
    }
    
    
    
    
    for (auto &it : mymap) {
        
        // print data in map for debugging
        if (debug) {cout << "Key: " << it.first << " Value: " << it.second << endl;}
        
        // bind variables        
        sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":id"), it.second);
        sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":value"), it.first.c_str(), it.first.length(), 0);
        
        // step statement and report errors, if any
        int step_rc = sqlite3_step(stmt);
        if (step_rc != SQLITE_OK && step_rc != SQLITE_DONE) {
            cerr << "SQLite error stepping statement at key " << it.first << " value " << it.second << " . Code " << sqlite3_errcode(db) << ": " << sqlite3_errmsg(db) << endl;
        } else {
            if (debug) {cout << "Statement was stepped successfully" << endl;}
	}
	
	// reset statement
	int reset_rc = sqlite3_reset(stmt);
	if( reset_rc != SQLITE_OK ){
            cerr << "SQL error resetting the prepared statement, the error was: "<< sqlite3_errmsg(db) << endl;
        } else {
            if (debug) {cout << "Prepared statement was reset successfully" << endl;}
        }
        
        // clear variables        
        int clear_bindings_rc = sqlite3_clear_bindings(stmt);
        if( clear_bindings_rc != SQLITE_OK ){
            cerr << "SQL error clearing the bindings, the error was: "<< sqlite3_errmsg(db) << endl;
        } else {
            if (debug) {cout << "Bindings were cleared successfully" << endl;}
        }
        
        
        
    }
    
    sqlite3_finalize(stmt);
}








// function to bind an ID to a statement if the ID is not 0
void bind_ID (sqlite3_stmt *stmt, const char * colonidstring, int ID, int debug) {
    // check if the ID is zero. If it is, don't bind anything (no data, default value in database is NULL)
    if (ID == 0) {
        if (debug) {cout << "ID integer is zero, not binding anything" << endl;}
    } else {
        if (debug) {cout << "Binding ID" << endl;}
        sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, colonidstring), ID);
    } 
}


              
              
              
map <string, rule_data> generateruledatamap (string ruledatafile, int debug) {
    
    if (debug) {cout << "Rule data file is " << ruledatafile << endl;}
    if (debug) {cout << "Generating ruledata map" << endl;}
    
    map <string, rule_data> results;
       
    //RULE_ID TABLENAME ANOMALY_SCORE SQL_SCORE XSS_SCORE TROJAN_SCORE OUTBOUND_ANOMALY_SCORE AUTOMATION_SCORE PROFILER_SCORE
    boost::regex ruledataregex("^(\\d{6,7})\\s*(\\w+)\\s*(\\+?\\d+)\\s*(\\+?\\d+)\\s*(\\+?\\d+)\\s*(\\+?\\d+)\\s*(\\+?\\d+)\\s*(\\+?\\d+)\\s*(\\+?\\d+).*$");
    
    int line = 0;
    string str;
    ifstream in(ruledatafile);
    boost::cmatch matches;


    while (getline(in, str)) {
        ++line;
        // if the regex matches, add to the map
        if (boost::regex_match(str.c_str(), matches, ruledataregex)) {
            //matches[0] contains the original string. matches[n] contains a submatch for each matching subexpression
            if (debug) { cout << "match on line " << line << " : " << matches[0] << endl;}
            string ruleid = matches[1];
            string rulefile = matches[2];
            // boost cmatch must be converted to a string using the ".str()" function, and then to a const char * using the ".c_str()" function
            signed int anomaly_score = atoi(matches[3].str().c_str());
            signed int sql_score = atoi(matches[4].str().c_str());
            signed int xss_score = atoi(matches[5].str().c_str());
            signed int trojan_score = atoi(matches[6].str().c_str());
            signed int outbound_anomaly_score = atoi(matches[7].str().c_str());
            signed int automation_score = atoi(matches[8].str().c_str());
            signed int profile_score = atoi(matches[9].str().c_str());
            
            if (debug) {cout << "rule id number is: " << ruleid << " rule file is: " << rulefile << " anomaly score is: " << anomaly_score << " sql score is " << sql_score << " xss score is " << sql_score << " trojan_score is " << trojan_score << " outbound anomaly score is " <<  outbound_anomaly_score << " profile score is " << profile_score << endl;}
            
            // create variable of type ruledata to hold all the information extracted on this line
            rule_data lineruledata = {ruleid, rulefile, anomaly_score, sql_score, xss_score, trojan_score, outbound_anomaly_score, automation_score, profile_score};
            
            // insert a new key into the map, value is type ruledata
            results.insert({ruleid,lineruledata});
        } else {
            if (debug) {cout << "No match on line " << line << ", data: " << str << endl;}
        }
    }
    
    return results;
}
              
              

              
              
              
              
              
              
              
              
              
// 1. get size of the vector holding the header strings and line numbers
// 2. perform queries on the database to get information about data already present, so that we can use the same IDs for matches in this log file 
// 3. start on vector row 1. determine the header letter type
// 4. get row line number for current header and row number for next header
// 5. read file, when the line number is >= the current header number and < the next header number, append the line to the data string
// 6. commit string to the correct column in the 'main' table in the database
// 7. use regular expressions to match important parts of this header (e.g. source IP); populate the table for this header with IDs mapping to each unique match, write map of IDs to matches in a separate table   
// 8. move on to next row in results vector              

int logchop(string database, string logfile, string rulesdatafile, vector<pair<int,string>> results, int debug, int force) {
    // set a timer
    std::chrono::time_point<std::chrono::system_clock> start, end;
    start = std::chrono::system_clock::now();
    
    // record counter
    int recordCounter = 0;
    
    // set holding ruleIDs that have already had errors printed
    set<string> printedErrorIDs;
    
    // 1. get size of the vector holding the header strings and line numbers
    // always two columns because each element in the vector is a pair
    int rows = results.size(); 
    

    // open database
    sqlite3 *db;
    int rc = sqlite3_open(database.c_str(), &db);
    if(rc) {
        cerr << "Can't open database" << endl;
    } else {
        if (debug) {cout << "Opened database successfully" << endl;}
    } 

    char *zErrMsg = 0;
    
    
    
    // 2. perform queries on the database to get information about data already present, so that we can use the same IDs for matches in this log file
    
    // A
    // - timestamp
    std::unordered_map<string, int> source_ip_map = get_unordered_map(database,"SELECT source_ip_id, source_ip FROM source_ip;",debug);
    std::unordered_map<string, int> source_port_map = get_unordered_map(database,"SELECT source_port_id, source_port FROM source_port;",debug);
    std::unordered_map<string, int> destination_ip_map = get_unordered_map(database,"SELECT destination_ip_id, destination_ip FROM destination_ip;",debug);
    std::unordered_map<string, int> destination_port_map = get_unordered_map(database,"SELECT destination_port_id, destination_port FROM destination_port;",debug);
    
    // B
    std::unordered_map<string, int> request_method_map = get_unordered_map(database,"SELECT request_method_id, request_method FROM request_method;",debug);
    std::unordered_map<string, int> uri_map = get_unordered_map(database,"SELECT uri_id, uri FROM uri;",debug);
    std::unordered_map<string, int> http_version_b_map = get_unordered_map(database,"SELECT http_version_b_id, http_version_b FROM http_version_b;",debug);
    std::unordered_map<string, int> hosts_map = get_unordered_map(database,"SELECT host_id, host FROM hosts;",debug);
    std::unordered_map<string, int> connection_b_map = get_unordered_map(database,"SELECT connection_b_id, connection_b FROM connection_b;",debug);
    std::unordered_map<string, int> accept_map = get_unordered_map(database,"SELECT accept_id, accept FROM accept;",debug);
    std::unordered_map<string, int> user_agent_map = get_unordered_map(database,"SELECT user_agent_id, user_agent FROM user_agent;",debug);
    std::unordered_map<string, int> dnt_map = get_unordered_map(database,"SELECT dnt_id, dnt FROM dnt;",debug);
    std::unordered_map<string, int> referrer_map = get_unordered_map(database,"SELECT referrer_id, referrer FROM referrer;",debug);
    std::unordered_map<string, int> accept_encoding_map = get_unordered_map(database,"SELECT accept_encoding_id, accept_encoding FROM accept_encoding;",debug);
    std::unordered_map<string, int> accept_language_map = get_unordered_map(database,"SELECT accept_language_id, accept_language FROM accept_language;",debug);
    std::unordered_map<string, int> cookie_map = get_unordered_map(database,"SELECT cookie_id, cookie FROM cookie;",debug);
    std::unordered_map<string, int> x_requested_with_map = get_unordered_map(database,"SELECT x_requested_with_id, x_requested_with FROM x_requested_with;",debug);
    std::unordered_map<string, int> content_type_b_map = get_unordered_map(database,"SELECT content_type_b_id, content_type_b FROM content_type_b;",debug);
    std::unordered_map<string, int> content_length_b_map = get_unordered_map(database,"SELECT content_length_b_id, content_length_b FROM content_length_b;",debug);
    std::unordered_map<string, int> proxy_connection_map = get_unordered_map(database,"SELECT proxy_connection_id, proxy_connection FROM proxy_connection;",debug);
    std::unordered_map<string, int> accept_charset_map = get_unordered_map(database,"SELECT accept_charset_id, accept_charset FROM accept_charset;",debug);
    std::unordered_map<string, int> ua_cpu_map = get_unordered_map(database,"SELECT ua_cpu_id, ua_cpu FROM ua_cpu;",debug);
    std::unordered_map<string, int> x_forwarded_for_map = get_unordered_map(database,"SELECT x_forwarded_for_id, x_forwarded_for FROM x_forwarded_for;",debug);
    std::unordered_map<string, int> cache_control_b_map = get_unordered_map(database,"SELECT cache_control_b_id, cache_control_b FROM cache_control_b;",debug);
    std::unordered_map<string, int> via_map = get_unordered_map(database,"SELECT via_id, via FROM via;",debug);
    std::unordered_map<string, int> if_modified_since_map = get_unordered_map(database,"SELECT if_modified_since_id, if_modified_since FROM if_modified_since;",debug);
    std::unordered_map<string, int> if_none_match_map = get_unordered_map(database,"SELECT if_none_match_id, if_none_match FROM if_none_match;",debug);
    std::unordered_map<string, int> pragma_b_map = get_unordered_map(database,"SELECT pragma_b_id, pragma_b FROM pragma_b;",debug);
    
    // F
    std::unordered_map<string, int> http_version_f_map = get_unordered_map(database,"SELECT http_version_f_id, http_version_f FROM http_version_f;",debug);
    std::unordered_map<string, int> http_status_code_map = get_unordered_map(database,"SELECT http_status_code_id, http_status_code FROM http_status_code;",debug);
    std::unordered_map<string, int> http_status_text_map = get_unordered_map(database,"SELECT http_status_text_id, http_status_text FROM http_status_text;",debug);
    std::unordered_map<string, int> x_powered_by_map = get_unordered_map(database,"SELECT x_powered_by_id, x_powered_by FROM x_powered_by;",debug);
    std::unordered_map<string, int> expires_map = get_unordered_map(database,"SELECT expires_id, expires FROM expires;",debug);
    std::unordered_map<string, int> cache_control_f_map = get_unordered_map(database,"SELECT cache_control_f_id, cache_control_f FROM cache_control_f;",debug);
    std::unordered_map<string, int> pragma_f_map = get_unordered_map(database,"SELECT pragma_f_id, pragma_f FROM pragma_f;",debug);
    std::unordered_map<string, int> vary_map = get_unordered_map(database,"SELECT vary_id, vary FROM vary;",debug);
    std::unordered_map<string, int> content_encoding_map = get_unordered_map(database,"SELECT content_encoding_id, content_encoding FROM content_encoding;",debug);
    std::unordered_map<string, int> content_length_f_map = get_unordered_map(database,"SELECT content_length_f_id, content_length_f FROM content_length_f;",debug);
    std::unordered_map<string, int> connection_f_map = get_unordered_map(database,"SELECT connection_f_id, connection_f FROM connection_f;",debug);
    std::unordered_map<string, int> content_type_f_map = get_unordered_map(database,"SELECT content_type_f_id, content_type_f FROM content_type_f;",debug);
    std::unordered_map<string, int> status_map = get_unordered_map(database,"SELECT status_id, status FROM status;",debug);
    std::unordered_map<string, int> keep_alive_map = get_unordered_map(database,"SELECT keep_alive_id, keep_alive FROM keep_alive;",debug);
    
    // H
    std::unordered_map<string, int> messages_map = get_unordered_map(database,"SELECT messages_id, messages FROM messages;",debug);
    std::unordered_map<string, int> apache_handler_map = get_unordered_map(database,"SELECT apache_handler_id, apache_handler FROM apache_handler;",debug);
    // - stopwatch
    // - stopwatch2
    std::unordered_map<string, int> producer_map = get_unordered_map(database,"SELECT producer_id, producer FROM producer;",debug);
    std::unordered_map<string, int> server_map = get_unordered_map(database,"SELECT server_id, server FROM server;",debug);
    std::unordered_map<string, int> engine_mode_map = get_unordered_map(database,"SELECT engine_mode_id, engine_mode FROM engine_mode;",debug);
    std::unordered_map<string, int> action_map = get_unordered_map(database,"SELECT action_id, action FROM action;",debug);
    std::unordered_map<string, int> apache_error_map = get_unordered_map(database,"SELECT apache_error_id, apache_error FROM apache_error;",debug);
    std::unordered_map<string, int> xml_parser_error_map = get_unordered_map(database,"SELECT xml_parser_error_id, xml_parser_error FROM xml_parser_error;",debug);
    
    
    // get a map of rule ID strings to rule ID data from the user-supplied config file
    cout << "Generating rule data map from the rule data config file " << rulesdatafile; 
    map <string, rule_data> ruledatamap = generateruledatamap (rulesdatafile, debug);
    cout << " ...done" << endl;
    
    
    // generate a map from the rule filename string to a counter
    
    map <string, int> rulefiletocountermap;
    
    for (const auto &iterator : ruledatamap) {
        // add the current rule file string to the set 
        int foo;
        string ruledatafile = (iterator.second).table_name;
        rulefiletocountermap.insert ({ruledatafile, foo});
    }
    
    // print the map
    if (debug) {
        for (const auto &iterator : rulefiletocountermap) {
            cout << "Rule file " << iterator.first << " maps to integer " << iterator.second << endl; 
        }
    }
    
    
    
    
    
    
    
    
    
    
    
    // stuff for boost regex matching
    boost::cmatch match; // cmatch type to hold matches
    
    // matches for section A, example data:
    // [25/Feb/2014:14:00:43 +0000] UwyiC38AAQEAAEx4slsAAAAG 125.210.204.242 40996 192.168.1.103 80
    // [25/May/2014:08:59:09 +0100] U4GizX8AAQEAAFR-SSYAAAAH ::1 51898 ::1 80
    
    // 1st match is TIMESTAMP, 2nd match is APACHE_UID, 3rd match is SOURCE_IP, 4th match is SOURCE_PORT, 5th match is DESTINATION_IP, 6th match is DESTINATION_PORT
    boost::regex A_regex("^\\[(.*)\\]\\s(.{24})\\s(\\d+\\.\\d+\\.\\d+\\.\\d+|::1)\\s(\\d+)\\s(\\d+\\.\\d+\\.\\d+\\.\\d+|::1)\\s(\\d+).*"); 
    

    
    
    // matches for section B (request headers)
    boost::regex B_regex("^(\\w+)\\s(.*)\\s(HTTP\\/\\d\\.\\d).*"); // 1st match is request method, 2nd match is URI, 3rd match is HTTP version
    boost::regex B_regex_host("^Host:(.*?)$");
    boost::regex B_regex_connection("^Connection:(.*?)$");
    boost::regex B_regex_accept("^Accept:(.*?)$");
    boost::regex B_regex_useragent("^User-Agent:(.*?)$"); // match for user agent string for use with regex_search
    boost::regex B_regex_DNT("^DNT:(.*?)$");
    boost::regex B_regex_referrer("^Referrer:(.*?)$");
    boost::regex B_regex_accept_encoding("^Accept-Encoding:(.*?)$");
    boost::regex B_regex_accept_language("^Accept-Language:(.*?)$");
    boost::regex B_regex_cookie("^Cookie:(.*?)$");
    boost::regex B_regex_x_requested_with("^X-Requested-With:(.*?)$");
    boost::regex B_regex_content_type("^Content-Type:(.*?)$");
    boost::regex B_regex_content_length("^Content-Length:(.*?)$");
    boost::regex B_regex_proxy_connection("^Proxy-Connection:(.*?)$");
    boost::regex B_regex_accept_charset("^Accept-Charset:(.*?)$");
    boost::regex B_regex_UA_CPU("^UA-CPU:(.*?)$");
    boost::regex B_regex_x_forwarded_for("^X-Forwarded-For:(.*?)$");
    boost::regex B_regex_cache_control("^Cache-Control:(.*?)$");
    boost::regex B_regex_via("^Via:(.*?)$");
    boost::regex B_regex_if_modified_since("^If-Modified-Since:(.*?)$");
    boost::regex B_regex_if_none_match("^If-None-Match:(.*?)$");
    boost::regex B_regex_pragma("^Pragma:(.*?)$");
    
    
    // matches for section C (request body)
    // (none)
    
    // section D not implemented by modsecurity
    // (none)
    
    // matches for section E (intermediary response body)
    // (none)
    
    // matches for section F (final response headers)
    boost::regex F_regex("^(HTTP\\/\\d\\.\\d)\\s(\\d+)\\s(.*?)$"); // 1st match is HTTP version, 2nd match is HTTP code, 3rd match is HTTP code description
    boost::regex F_regex_x_powered_by("^X-Powered-By:(.*?)$");
    boost::regex F_regex_expires("^Expires:(.*?)$");
    boost::regex F_regex_cache_control("^Cache-Control:(.*?)$");
    boost::regex F_regex_pragma("^Pragma:(.*?)$");
    boost::regex F_regex_vary("^Vary:(.*?)$");
    boost::regex F_regex_content_encoding("^Content-Encoding:(.*?)$");
    boost::regex F_regex_content_length("^Content-Length:(.*?)$");
    boost::regex F_regex_connection("^Connection:(.*?)$");
    boost::regex F_regex_content_type("^Content-Type:(.*?)$");
    boost::regex F_regex_status("^Status:(.*?)$");
    boost::regex F_regex_keep_alive("^Keep-Alive:(.*?)$");
    
    // section G not implemented by modsecurity
    // (none)
    
    // matches for section H (audit log trailer)
    boost::regex H_regex_messages("^Message:(.*?)$");
    boost::regex H_regex_apache_handler("^Apache-Handler:(.*?)$");
    boost::regex H_regex_apache_error("^Apache-Error:(.*?)$");
    boost::regex H_regex_stopwatch("^Stopwatch:(.*?)$");
    boost::regex H_regex_stopwatch2("^Stopwatch2:(.*?)$");
    //boost::regex H_regex_response_body_transformed("^Apache-Handler:(.*?)$");
    boost::regex H_regex_producer("^Producer:(.*?)$");
    boost::regex H_regex_server("^Server:(.*?)$");
    boost::regex H_regex_engine_mode("^Engine-Mode:\\s\"(.*?)\"$");
    boost::regex H_regex_action("^Action:(.*?)$");
    boost::regex H_regex_xml_parser_error("^Message: XML parser error:(.*?)$");
    
    // matches for any rule ID
    boost::regex H_regex_any_rule("\\[id\\s\"(\\d{6,7})\"\\]");
    
    
    // matches for section I (a replacement for part C)
    // (none)
    
    // matches for section J (contains information about files uploaded using multipart/form-data encoding)
    // (none)
    
    // matches for section K (list of every rule that matched, one per line, in the order they were matched)
    // (none)
    
    // matches for error reporting
    boost::regex table_exists_regex("table \\w+ already exists");
    
    // create the SQL statements that can be used to commit the values to the database
    map <string, tuple<const char *, sqlite3_stmt **>> prepared_statements_map;
    
    
    // NB: unbound values in prepared statements are NULL
    const char *sql_insert_main = "INSERT INTO main (UNIQUE_ID, HEADER, A, B, C, D, E, F, G, H, I, J, K) VALUES (:UNIQUE_ID, :HEADER, :A, :B, :C, :D, :E, :F, :G, :H, :I, :J, :K);";
    sqlite3_stmt *stmt_insert_main; // compiled statement handle (pointer of type sqlite3_stmt)
    prepared_statements_map.insert({"sql_insert_main",	make_tuple(sql_insert_main, &stmt_insert_main)});
    
    const char *sql_insert_A = "INSERT INTO A (UNIQUE_ID, TIMESTAMP, UNIXTIME, SOURCE_IP_ID, SOURCE_PORT_ID, DESTINATION_IP_ID, DESTINATION_PORT_ID) VALUES (:UNIQUE_ID, :TIMESTAMP, :UNIXTIME, :SOURCE_IP_ID, :SOURCE_PORT_ID, :DESTINATION_IP_ID, :DESTINATION_PORT_ID);";
    sqlite3_stmt *stmt_insert_A;
    prepared_statements_map.insert({"sql_insert_A", make_tuple(sql_insert_A, &stmt_insert_A)});
    
    const char *sql_insert_B = "INSERT INTO B (UNIQUE_ID, REQUEST_METHOD_ID, URI_ID, HTTP_VERSION_ID, HOST_ID, CONNECTION_ID, ACCEPT_ID, USER_AGENT_ID, DNT_ID, REFERRER_ID, ACCEPT_ENCODING_ID, ACCEPT_LANGUAGE_ID, COOKIE_ID, X_REQUESTED_WITH_ID, CONTENT_TYPE_ID, CONTENT_LENGTH_ID, PROXY_CONNECTION_ID, ACCEPT_CHARSET_ID, UA_CPU_ID, X_FORWARDED_FOR_ID, CACHE_CONTROL_ID, VIA_ID, IF_MODIFIED_SINCE_ID, IF_NONE_MATCH_ID, PRAGMA_ID) VALUES (:UNIQUE_ID, :REQUEST_METHOD_ID, :REQUEST_URI_ID, :REQUEST_HTTP_VERSION_ID, :REQUEST_HOST_ID, :REQUEST_CONNECTION_ID, :REQUEST_ACCEPT_ID, :REQUEST_USER_AGENT_ID, :REQUEST_DNT_ID, :REQUEST_REFERRER_ID, :REQUEST_ACCEPT_ENCODING_ID, :REQUEST_ACCEPT_LANGUAGE_ID, :REQUEST_COOKIE_ID, :REQUEST_X_REQUESTED_WITH_ID, :REQUEST_CONTENT_TYPE_ID, :REQUEST_CONTENT_LENGTH_ID, :REQUEST_PROXY_CONNECTION_ID, :REQUEST_ACCEPT_CHARSET_ID, :REQUEST_UA_CPU_ID, :REQUEST_X_FORWARDED_FOR_ID, :REQUEST_CACHE_CONTROL_ID, :REQUEST_VIA_ID, :REQUEST_IF_MODIFIED_SINCE_ID, :REQUEST_IF_NONE_MATCH_ID, :REQUEST_PRAGMA_ID);";
    sqlite3_stmt *stmt_insert_B;
    prepared_statements_map.insert({"sql_insert_B", make_tuple(sql_insert_B, &stmt_insert_B)});
    
    const char *sql_insert_F = "INSERT INTO F (UNIQUE_ID, HTTP_VERSION_ID, HTTP_STATUS_CODE_ID, HTTP_STATUS_TEXT_ID, X_POWERED_BY_ID, EXPIRES_ID, CACHE_CONTROL_ID, PRAGMA_ID, VARY_ID, CONTENT_ENCODING_ID, CONTENT_LENGTH_ID, CONNECTION_ID, CONTENT_TYPE_ID, STATUS_ID, KEEP_ALIVE_ID) VALUES (:UNIQUE_ID, :RESPONSE_HTTP_VERSION_ID, :RESPONSE_HTTP_STATUS_CODE_ID, :RESPONSE_HTTP_STATUS_TEXT_ID, :RESPONSE_X_POWERED_BY_ID, :RESPONSE_EXPIRES_ID, :RESPONSE_CACHE_CONTROL_ID, :RESPONSE_PRAGMA_ID, :RESPONSE_VARY_ID, :RESPONSE_CONTENT_ENCODING_ID, :RESPONSE_CONTENT_LENGTH_ID, :RESPONSE_CONNECTION_ID, :RESPONSE_CONTENT_TYPE_ID, :RESPONSE_STATUS_ID, :RESPONSE_KEEP_ALIVE_ID);";
    sqlite3_stmt *stmt_insert_F;
    prepared_statements_map.insert({"sql_insert_F",make_tuple(sql_insert_F, &stmt_insert_F)});
    
    

    
    // create a set of table names from the ruledatamap
    set<string> tablenames;
    if (debug) {cout << "Reading table names from the user input map" << endl;}
    for (auto &ruleID : ruledatamap) {
        if (debug) {cout << "Read table name: " << ruleID.second.table_name << endl;}
        tablenames.insert(ruleID.second.table_name);
    }
    
    if (debug) {
        cout << "The following tables will be created:" << endl;
        for (const auto &table : tablenames) {
            cout << table << endl;
        }
    }    
    
    
    
    // start a transaction - all of the statements from here until END TRANSACTION will be queued and executed at once,
    // reducing the overhead associated with committing to the database multiple times (massive speed improvement)
    sqlite3_exec(db, "BEGIN TRANSACTION", 0, 0, 0);
    
    const char *pzTail; // pointer to uncompiled portion of statement
    
    

    
    // table H has some columns that are created based on the user-supplied rule file data (one column for each rule file name)
    // create a statement to create table H
    string sql_create_H = "CREATE TABLE h (unique_id TEXT PRIMARY KEY,    messages_id INTEGER DEFAULT NULL,  apache_handler_id INTEGER DEFAULT NULL, 	stopwatch TEXT, stopwatch2 TEXT, producer_id INTEGER DEFAULT NULL, server_id INTEGER DEFAULT NULL, engine_mode_id INTEGER DEFAULT NULL, action_id INTEGER DEFAULT NULL, apache_error_id INTEGER DEFAULT NULL, xml_parser_error_id INTEGER DEFAULT NULL";
    for (const auto &table : tablenames) {
        sql_create_H.append(", " + table + "_messages_id INTEGER DEFAULT NULL"); 
    }
    sql_create_H.append(");");
    if (debug) {cout << "Finished SQL create table statement for H is: " << sql_create_H << endl;}
    
    
    // execute the statement to create table H
    rc = sqlite3_exec(db, sql_create_H.c_str(), 0, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
        if (!boost::regex_match(zErrMsg, match, table_exists_regex)) { // check if the error string is about table already existing
            cerr << "SQL error creating anomaly scores table, error message: " << zErrMsg << endl;
        }
    } else {
        if (debug) {cout << "Table H was created successfully." << endl;}
    }

    
    
    
    
    
    // now create a sql statement for inserting data into table H
    string sql_insert_H = "INSERT INTO H (UNIQUE_ID, MESSAGES_ID, APACHE_HANDLER_ID, APACHE_ERROR_ID, STOPWATCH, STOPWATCH2, PRODUCER_ID, SERVER_ID, ENGINE_MODE_ID, ACTION_ID, XML_PARSER_ERROR_ID";
    for (const auto &table : tablenames) {
        sql_insert_H.append(", " + table + "_messages_id"); 
    }
    sql_insert_H.append(") VALUES (:UNIQUE_ID, :TRAILER_MESSAGES_ID, :TRAILER_APACHE_HANDLER_ID, :TRAILER_APACHE_ERROR_ID, :TRAILER_STOPWATCH, :TRAILER_STOPWATCH2, :TRAILER_PRODUCER_ID, :TRAILER_SERVER_ID, :TRAILER_ENGINE_MODE_ID, :TRAILER_ACTION_ID, :TRAILER_XML_PARSER_ERROR_ID");
    for (const auto &table : tablenames) {
        sql_insert_H.append(", :" + table ); 
    }    
    sql_insert_H.append(");");
    
    if (debug) {cout << "Finished SQL insert statement for H is: " << sql_insert_H << endl;}    
    
    const char *sql_insert_H_ptr = sql_insert_H.c_str();
    sqlite3_stmt *stmt_insert_H;
    prepared_statements_map.insert({"sql_insert_H",make_tuple(sql_insert_H_ptr, &stmt_insert_H)});
    
    
    // anomaly scores table has unique id, total score, and one column for each rule file name in the user-supplied rule data
    
    // CREATE TABLE anomaly_scores (unique_id TEXT PRIMARY KEY, TOTAL_SCORE INTEGER DEFAULT 0, CRS_10_SETUP INTEGER DEFAULT 0 ... );
    string sql_create_anomaly_scores = "CREATE TABLE anomaly_scores (UNIQUE_ID TEXT PRIMARY KEY, TOTAL_SCORE INTEGER DEFAULT 0";
    for (const auto &table : tablenames) {
        sql_create_anomaly_scores.append(", " + table + " INTEGER DEFAULT 0"); 
    }
    sql_create_anomaly_scores.append(");");
    if (debug) {cout << "Finished SQL insert statement is: " << sql_create_anomaly_scores << endl;}
    
    // execute the statement to create the table
    rc = sqlite3_exec(db, sql_create_anomaly_scores.c_str(), 0, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
        if (!boost::regex_match(zErrMsg, match, table_exists_regex)) { // check if the error string is about table already existing
            cerr << "SQL error creating anomaly scores table, error message: " << zErrMsg << endl;
        }
    } else {
        if (debug) {cout << "Anomaly scores table was created successfully." << endl;}
    }
    
    
    
    
    // create an sql insert statement for binding anomaly scores to the anomaly score table
    // example statement:
    //INSERT INTO ANOMALY_SCORES (UNIQUE_ID, TOTAL_SCORE, CRS_10_SETUP ... ) VALUES (:UNIQUE_ID, :total_score, :crs_10_setup ...);
    
    string sql_insert_anomaly_scores = "INSERT INTO ANOMALY_SCORES (UNIQUE_ID, TOTAL_SCORE";
    for (const auto &table : tablenames) {
        sql_insert_anomaly_scores.append(", " + table); 
    }
    sql_insert_anomaly_scores.append(") VALUES (:UNIQUE_ID, :total_score");
    for (const auto &table : tablenames) {
        sql_insert_anomaly_scores.append(", :" + table); 
    }
    sql_insert_anomaly_scores.append(");");
    if (debug) {cout << "Finished SQL insert statement is: " << sql_insert_anomaly_scores << endl;}
    
    sqlite3_stmt *stmt_insert_anomaly_scores;
    prepared_statements_map.insert({"sql_insert_anomaly_scores",make_tuple(sql_insert_anomaly_scores.c_str(), &stmt_insert_anomaly_scores)});
    
    
    
    
    
    
    // generate a "create table" sql statement for each table name in the rulesdata.conf file, using the ruledatamap that was created from it
    // create a map of "table name strings" to "pointers to compiled sqlite3 statements"
    map<string,sqlite3_stmt*> insert_statements_map;
    
    // for each table name in the set, create a set of rule IDs, use it to generate the "create table" SQL statement and execute it,
    // use the same set to generate the "insert into" statement and compile it ready to bind values to later.
    for (const auto &table : tablenames) {
        set<string> tableIDs;
        for (const auto &data : ruledatamap) {
            // if the tablename matches the current one, add the rule ID to the tableIDs set 
            if (data.second.table_name == table) {
                tableIDs.insert(data.first);
            }
        }
        
        
        // construct a SQL "create table" string from the rule IDs set
        // example statement:
        //CREATE TABLE CRS_10_IGNORE_STATIC                   (UNIQUE_ID TEXT PRIMARY KEY,    '900040' INTEGER DEFAULT 0 NOT NULL,    '900041' INTEGER DEFAULT 0 NOT NULL,    '900042' INTEGER DEFAULT 0 NOT NULL,    '900043' INTEGER DEFAULT 0 NOT NULL,    '999005' INTEGER DEFAULT 0 NOT NULL,    '999006' INTEGER DEFAULT 0 NOT NULL	);
        
        string sql_create_table = "CREATE TABLE " + table + " (UNIQUE_ID TEXT PRIMARY KEY";
        for (const auto &id : tableIDs) {
            sql_create_table.append(", '" + id + "' INTEGER DEFAULT 0 NOT NULL");
        }
        sql_create_table.append(");");
        if (debug) {cout << "Finished SQL create table statement is: " << sql_create_table << endl;}
        
        // execute the statement to create the table
        rc = sqlite3_exec(db, sql_create_table.c_str(), 0, 0, &zErrMsg);
        if( rc != SQLITE_OK ){
            if (!boost::regex_match(zErrMsg, match, table_exists_regex)) { // check if the error string is about table already existing
                cerr << "SQL error creating table " << table << ", error message: " << zErrMsg << endl;
            }
        } else {
            if (debug) {cout << "Table " << table << " was created successfully." << endl;}
        }
        
        
        
        // construct a SQL "insert into" string from the rule IDs set
        // example statement:
        // "INSERT INTO CRS_49_INBOUND_BLOCKING (UNIQUE_ID, '981175', '981176') VALUES (:UNIQUE_ID, :981175, :981176);
        string sql_insert = "INSERT INTO " + table + " (UNIQUE_ID";
        for (const auto &id : tableIDs) {
            sql_insert.append(", '" + id + "'");
        }
        sql_insert.append(") VALUES (:UNIQUE_ID");
        for (const auto &id : tableIDs) {
            sql_insert.append(", :" + id);
        }
        sql_insert.append(");");
        if (debug) {cout << "Finished SQL insert statement is: " << sql_insert << endl;}
        
        // insert the table name into the map
        sqlite3_stmt *compiled_statement; // must be a pointer to the compiled statement because otherwise type definition is incomplete
        insert_statements_map.insert({table,compiled_statement});
        
        // compile the statement
        rc = sqlite3_prepare_v2(db, sql_insert.c_str(), sql_insert.length(), &insert_statements_map[table], &pzTail);
        if( rc != SQLITE_OK ){
            cerr << "SQL error compiling prepared insert statement for table " << table << ", the error was: " << sqlite3_errmsg(db) << endl;
        } else {
            if (debug) {cout << "Prepared statement for inserting values into table " << table << " was compiled successfully" << endl;}
        }
        
    }
  
  
    
  
  // variables for sql compilation
  //const char *pzTail; // pointer to uncompiled portion of statement
  
  int prepared_statement_errors = 0; // sql compilation error counter
  for (const auto &s : prepared_statements_map) {
    rc = sqlite3_prepare_v2(db, get<0>(s.second), strlen(get<0>(s.second)), get<1>(s.second), &pzTail);
    if( rc != SQLITE_OK ){
      cerr << "SQL error compiling " << s.first << " prepared statement" << endl;
      cerr << "The error was: "<< sqlite3_errmsg(db) << endl;
      ++prepared_statement_errors;
    } else {
      if (debug) {cout << "Prepared statement " << s.first << " was compiled successfully" << endl;}
    }
  }
  
  
  
  
  if (prepared_statement_errors != 0) {
    cerr << "Skipping logfile processing due to failed prepared statement creation" << endl;
  } else {
    
    // create stream for reading logfile
    ifstream in(logfile);
    int line = 0;
    string linedata;
  

    
    // initialise strings for each value to be bound to the sqlite statement
    string UNIQUE_ID, HEADER, A, B, C, D, E, F, G, H, I, J, K; // "high level" strings
    
    // strings for matches in A
    string TIMESTAMP, UNIXTIME, SOURCE_IP, SOURCE_PORT, DESTINATION_IP, DESTINATION_PORT;
    int SOURCE_IP_ID, SOURCE_PORT_ID, DESTINATION_IP_ID, DESTINATION_PORT_ID;
    
    // strings for matches in B
    string REQUEST_METHOD, REQUEST_URI, REQUEST_HTTP_VERSION; // first regex
    string REQUEST_HOST, REQUEST_CONNECTION, REQUEST_ACCEPT, REQUEST_USER_AGENT, REQUEST_DNT, REQUEST_REFERRER, REQUEST_ACCEPT_ENCODING, REQUEST_ACCEPT_LANGUAGE, REQUEST_COOKIE, REQUEST_X_REQUESTED_WITH, REQUEST_CONTENT_TYPE, REQUEST_CONTENT_LENGTH, REQUEST_PROXY_CONNECTION, REQUEST_ACCEPT_CHARSET, REQUEST_UA_CPU, REQUEST_X_FORWARDED_FOR, REQUEST_CACHE_CONTROL, REQUEST_VIA, REQUEST_IF_MODIFIED_SINCE, REQUEST_IF_NONE_MATCH, REQUEST_PRAGMA;
    int REQUEST_METHOD_ID, REQUEST_URI_ID, REQUEST_HTTP_VERSION_ID;
    int REQUEST_HOST_ID, REQUEST_CONNECTION_ID, REQUEST_ACCEPT_ID, REQUEST_USER_AGENT_ID, REQUEST_DNT_ID, REQUEST_REFERRER_ID, REQUEST_ACCEPT_ENCODING_ID, REQUEST_ACCEPT_LANGUAGE_ID, REQUEST_COOKIE_ID, REQUEST_X_REQUESTED_WITH_ID, REQUEST_CONTENT_TYPE_ID, REQUEST_CONTENT_LENGTH_ID, REQUEST_PROXY_CONNECTION_ID, REQUEST_ACCEPT_CHARSET_ID, REQUEST_UA_CPU_ID, REQUEST_X_FORWARDED_FOR_ID, REQUEST_CACHE_CONTROL_ID, REQUEST_VIA_ID, REQUEST_IF_MODIFIED_SINCE_ID, REQUEST_IF_NONE_MATCH_ID, REQUEST_PRAGMA_ID;
    
    
    // strings for matches in F
    string RESPONSE_HTTP_VERSION, RESPONSE_HTTP_STATUS_CODE, RESPONSE_HTTP_STATUS_TEXT, RESPONSE_X_POWERED_BY, RESPONSE_EXPIRES, RESPONSE_CACHE_CONTROL, RESPONSE_PRAGMA, RESPONSE_VARY, RESPONSE_CONTENT_ENCODING, RESPONSE_CONTENT_LENGTH, RESPONSE_CONNECTION, RESPONSE_CONTENT_TYPE, RESPONSE_STATUS, RESPONSE_KEEP_ALIVE;
    int RESPONSE_HTTP_VERSION_ID, RESPONSE_HTTP_STATUS_CODE_ID, RESPONSE_HTTP_STATUS_TEXT_ID, RESPONSE_X_POWERED_BY_ID, RESPONSE_EXPIRES_ID, RESPONSE_CACHE_CONTROL_ID, RESPONSE_PRAGMA_ID, RESPONSE_VARY_ID, RESPONSE_CONTENT_ENCODING_ID, RESPONSE_CONTENT_LENGTH_ID, RESPONSE_CONNECTION_ID, RESPONSE_CONTENT_TYPE_ID, RESPONSE_STATUS_ID, RESPONSE_KEEP_ALIVE_ID;
    
    
    // strings for matches in H
    string TRAILER_MESSAGES, TRAILER_APACHE_HANDLER, TRAILER_APACHE_ERROR, TRAILER_STOPWATCH, TRAILER_STOPWATCH2, TRAILER_PRODUCER, TRAILER_SERVER, TRAILER_ENGINE_MODE, TRAILER_ACTION, TRAILER_XML_PARSER_ERROR;
    int TRAILER_MESSAGES_ID, TRAILER_APACHE_HANDLER_ID, TRAILER_APACHE_ERROR_ID, TRAILER_STOPWATCH_ID, TRAILER_STOPWATCH2_ID, TRAILER_PRODUCER_ID, TRAILER_SERVER_ID, TRAILER_ENGINE_MODE_ID, TRAILER_ACTION_ID, TRAILER_XML_PARSER_ERROR_ID;
    
    // map for holding messages related to each table, used in section H
    map <string,string> messagesmap;
    
    
    // 3. start on vector row 1. determine the header letter type
    // stop at penultimate row or we won't be able to find the last line number    
    for ( int r = 0; r < rows -1; ++r) {
      // header letter is always the 12th character in the string (11th index 0)
      char letter = results[r].second[11];
      int startline = results[r].first;
      int endline = results[r+1].first;
      
      if (debug) {cout << "Row " << r << " - letter is: " << letter << " - start line is: " << startline << " - end line is: " << endline << endl;}
      
      // initialise a string to hold the whole of the header data, will be re-created for each pass of the for loop
      string headerdata;
      
      // each time this is called it seems to start from where it left off before
      while (getline(in, linedata)) {
	++line;
	// if the data is in between two headers, append it to the headerdata string
	if (line > startline && line < endline ) {
	  if (debug) {cout << "Appending line data on line: " << line << endl;}
	  headerdata.append(linedata);
	  headerdata.append(string("\n"));
	  
	} else if (line == endline) {
	  if (debug) {
	    cout << "Reached endline, current string is:" << endl;
	    cout << headerdata << endl;
	  }
	    
	  // store the headerdata in the appropriate position in the array
	  if (letter == 'A') {
	    if (debug) {cout << "Letter is A" << endl;}
	    HEADER=results[r].second;
	    A = headerdata;
	    // submatch the apache UNIQUE_ID from the A header
	    if (boost::regex_match(A.c_str(), match, A_regex)) {
              TIMESTAMP = match[1]; // something like 14/Jun/2015:09:32:25 +0100
              // need to convert this timestamp to a sqlite timestamp YYYY-MM-DD HH:MM:SS[+-]HH:MM
              // try this http://www.thejach.com/view/2012/7/apaches_common_log_format_datetime_converted_to_unix_timestamp_with_c
              // then use sqlite's internal mechanism to convert from unix timestamp to something more user friendly
              UNIXTIME=logtimeToUnix(TIMESTAMP);
              if (debug) {cout << "Apache timestamp is " << TIMESTAMP << " Unix timestamp is " << UNIXTIME << endl;}
              
              
              
              
	      UNIQUE_ID = match[2];
              
	      SOURCE_IP = match[3];
              SOURCE_PORT = match[4];
	      DESTINATION_IP = match[5];
	      DESTINATION_PORT = match[6];
	      if(debug) {cout << "Apache UNIQUE_ID for header " << line << " is: " << UNIQUE_ID << endl;}
	    } else {
	      cerr << "No Apache Unique ID found" << endl;
	    }
	    
	    // get integer IDs from the map
            SOURCE_IP_ID = ID_from_map(SOURCE_IP,source_ip_map,debug);
            SOURCE_PORT_ID = ID_from_map(SOURCE_PORT,source_port_map,debug);
            DESTINATION_IP_ID = ID_from_map(DESTINATION_IP,destination_ip_map,debug);
            DESTINATION_PORT_ID = ID_from_map(DESTINATION_PORT,destination_port_map,debug);

	    // UNIQUE_ID must be bound to all statements
	    if (debug) {cout << "Binding unique ID to insert statements for base table" << endl;};
	    for (const auto &s : prepared_statements_map) {
	      int rc_bind = sqlite3_bind_text(*(get<1>(s.second)), sqlite3_bind_parameter_index(*(get<1>(s.second)), ":UNIQUE_ID"), UNIQUE_ID.c_str(), UNIQUE_ID.length(), 0);
	      if (rc_bind != SQLITE_OK) {
		cerr << UNIQUE_ID << ": error binding unique ID to statement " << s.first << ". Code " << rc_bind << " description: " << sqlite3_errmsg(db) << endl;
	      } else {
		if (debug) {cout << UNIQUE_ID << ": unique ID bound to " << s.first << " successfully" << endl;}
	      }
	    }
	    
	    // UNIQUE_ID must be bound to all insert_statements_map statements (used to insert data into rule ID tables generated from user input) 
	    if (debug) {cout << "Binding unique ID to insert statements for user supplied rule data" << endl;};
	    for (const auto &s : insert_statements_map) {
	      int rc_bind = sqlite3_bind_text(s.second, sqlite3_bind_parameter_index(s.second, ":UNIQUE_ID"), UNIQUE_ID.c_str(), UNIQUE_ID.length(), 0);
	      if (rc_bind != SQLITE_OK) {
		cerr << UNIQUE_ID << ": error binding unique ID to statement for inserting values into table " << s.first << ". Code " << rc_bind << " description: " << sqlite3_errmsg(db) << endl;
	      } else {
		if (debug) {cout << UNIQUE_ID << ": unique ID bound to table " << s.first << " successfully" << endl;}
	      }
	    }
	    
	    
	    
	    // header and A data bound to insert_main sql statement
	    if (debug) {cout << "Binding data from A to table main prepared statement" << endl;};
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":HEADER"), HEADER.c_str(), HEADER.length(), 0);
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":A"), A.c_str(), A.length(), 0);
	    
	    // these values bound to insert_A sql statement
	    if (debug) {cout << "Binding data for table A" << endl;};
	    sqlite3_bind_text(stmt_insert_A, sqlite3_bind_parameter_index(stmt_insert_A, ":TIMESTAMP"), TIMESTAMP.c_str(), TIMESTAMP.length(), 0);
	    sqlite3_bind_text(stmt_insert_A, sqlite3_bind_parameter_index(stmt_insert_A, ":UNIXTIME"), UNIXTIME.c_str(), UNIXTIME.length(), 0);
            
            
            // bind ID integers
            bind_ID (stmt_insert_A, ":SOURCE_IP_ID", SOURCE_IP_ID, debug);
            bind_ID (stmt_insert_A, ":SOURCE_PORT_ID", SOURCE_PORT_ID, debug);
            bind_ID (stmt_insert_A, ":DESTINATION_IP_ID", DESTINATION_IP_ID, debug);
            bind_ID (stmt_insert_A, ":DESTINATION_PORT_ID", DESTINATION_PORT_ID, debug);



	    
	    
	    
	  } else if (letter == 'B') {
	    if (debug) {cout << "Letter is B" << endl;}
	    B = headerdata;
	    // submatch some relevant bits from B
	    if (boost::regex_match(B.c_str(), match, B_regex)) {
	      REQUEST_METHOD = match[1];
	      REQUEST_URI = match[2];
	      REQUEST_HTTP_VERSION = match[3];
              
	    } else {
	      cerr << "Regex matching at B failed" << endl;
	    }
	    // get integer IDs from the map
            REQUEST_METHOD_ID = ID_from_map(REQUEST_METHOD,request_method_map,debug);
            REQUEST_URI_ID = ID_from_map(REQUEST_URI,uri_map,debug);
            REQUEST_HTTP_VERSION_ID = ID_from_map(REQUEST_HTTP_VERSION,http_version_b_map,debug);
	    
	    if (boost::regex_search(B.c_str(), match, B_regex_host)) {
	      REQUEST_HOST = match[1];
	    }
	    REQUEST_HOST_ID = ID_from_map(REQUEST_HOST,hosts_map,debug);
	    
	    if (boost::regex_search(B.c_str(), match, B_regex_connection)) {
	      REQUEST_CONNECTION = match[1];
	    }
	    REQUEST_CONNECTION_ID = ID_from_map(REQUEST_CONNECTION,connection_b_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_accept)) {
	      REQUEST_ACCEPT = match[1];
	    }
	    REQUEST_ACCEPT_ID = ID_from_map(REQUEST_ACCEPT,accept_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_useragent)) {
	      REQUEST_USER_AGENT = match[1];
	    }
	    REQUEST_USER_AGENT_ID = ID_from_map(REQUEST_USER_AGENT,user_agent_map,debug);
	    
	    if (boost::regex_search(B.c_str(), match, B_regex_DNT)) {
	      REQUEST_DNT = match[1];
	    }
	    REQUEST_DNT_ID = ID_from_map(REQUEST_DNT,dnt_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_referrer)) {
	      REQUEST_REFERRER = match[1];
	    }
	    REQUEST_REFERRER_ID = ID_from_map(REQUEST_REFERRER,referrer_map,debug);
	    
	    if (boost::regex_search(B.c_str(), match, B_regex_accept_encoding)) {
	      REQUEST_ACCEPT_ENCODING = match[1];
	    }
	    REQUEST_ACCEPT_ENCODING_ID = ID_from_map(REQUEST_ACCEPT_ENCODING,accept_encoding_map,debug);
	    
	    if (boost::regex_search(B.c_str(), match, B_regex_accept_language)) {
	      REQUEST_ACCEPT_LANGUAGE = match[1];
	    }
	    REQUEST_ACCEPT_LANGUAGE_ID = ID_from_map(REQUEST_ACCEPT_LANGUAGE,accept_language_map,debug);
	    
	    if (boost::regex_search(B.c_str(), match, B_regex_cookie)) {
	      REQUEST_COOKIE = match[1];
	    }
	    REQUEST_COOKIE_ID = ID_from_map(REQUEST_COOKIE,cookie_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_x_requested_with)) {
	      REQUEST_X_REQUESTED_WITH = match[1];
	    }
	    REQUEST_X_REQUESTED_WITH_ID = ID_from_map(REQUEST_X_REQUESTED_WITH,x_requested_with_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_content_type)) {
	      REQUEST_CONTENT_TYPE = match[1];
	    }
	    REQUEST_CONTENT_TYPE_ID = ID_from_map(REQUEST_CONTENT_TYPE,content_type_b_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_content_length)) {
	      REQUEST_CONTENT_LENGTH = match[1];
	    }
	    REQUEST_CONTENT_LENGTH_ID = ID_from_map(REQUEST_CONTENT_LENGTH,content_length_b_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_proxy_connection)) {
	      REQUEST_PROXY_CONNECTION = match[1];
	    }
	    REQUEST_PROXY_CONNECTION_ID = ID_from_map(REQUEST_PROXY_CONNECTION,proxy_connection_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_accept_charset)) {
	      REQUEST_ACCEPT_CHARSET = match[1];
	    }
	    REQUEST_ACCEPT_CHARSET_ID = ID_from_map(REQUEST_ACCEPT_CHARSET,accept_charset_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_UA_CPU)) {
	      REQUEST_UA_CPU = match[1];
	    }
	    REQUEST_UA_CPU_ID = ID_from_map(REQUEST_UA_CPU,ua_cpu_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_x_forwarded_for)) {
	      REQUEST_X_FORWARDED_FOR = match[1];
	    }
	    REQUEST_X_FORWARDED_FOR_ID = ID_from_map(REQUEST_X_FORWARDED_FOR,x_forwarded_for_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_cache_control)) {
	      REQUEST_CACHE_CONTROL = match[1];
	    }
	    REQUEST_CACHE_CONTROL_ID = ID_from_map(REQUEST_CACHE_CONTROL,cache_control_b_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_via)) {
	      REQUEST_VIA = match[1];
	    }
	    REQUEST_VIA_ID = ID_from_map(REQUEST_VIA,via_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_if_modified_since)) {
	      REQUEST_IF_MODIFIED_SINCE = match[1];
	    }
	    REQUEST_IF_MODIFIED_SINCE_ID = ID_from_map(REQUEST_IF_MODIFIED_SINCE,if_modified_since_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_if_none_match)) {
	      REQUEST_IF_NONE_MATCH = match[1];
	    }
	    REQUEST_IF_NONE_MATCH_ID = ID_from_map(REQUEST_IF_NONE_MATCH,if_none_match_map,debug);
            
	    if (boost::regex_search(B.c_str(), match, B_regex_pragma)) {
	      REQUEST_PRAGMA = match[1];
	    }
	    REQUEST_PRAGMA_ID = ID_from_map(REQUEST_PRAGMA,pragma_b_map,debug);
	    
	    // bind whole B string
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":B"), B.c_str(), B.length(), 0);
	    
            // bind the ID integers
            bind_ID (stmt_insert_B, ":REQUEST_METHOD_ID", REQUEST_METHOD_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_URI_ID", REQUEST_URI_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_HTTP_VERSION_ID", REQUEST_HTTP_VERSION_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_HOST_ID", REQUEST_HOST_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_USER_AGENT_ID", REQUEST_USER_AGENT_ID, debug);
	    bind_ID (stmt_insert_B, ":REQUEST_CONNECTION_ID", REQUEST_CONNECTION_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_ACCEPT_ID", REQUEST_ACCEPT_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_DNT_ID", REQUEST_DNT_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_REFERRER_ID", REQUEST_REFERRER_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_ACCEPT_ENCODING_ID", REQUEST_ACCEPT_ENCODING_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_ACCEPT_LANGUAGE_ID", REQUEST_ACCEPT_LANGUAGE_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_COOKIE_ID", REQUEST_COOKIE_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_X_REQUESTED_WITH_ID", REQUEST_X_REQUESTED_WITH_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_CONTENT_TYPE_ID", REQUEST_CONTENT_TYPE_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_CONTENT_LENGTH_ID", REQUEST_CONTENT_LENGTH_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_PROXY_CONNECTION_ID", REQUEST_PROXY_CONNECTION_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_ACCEPT_CHARSET_ID", REQUEST_ACCEPT_CHARSET_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_UA_CPU_ID", REQUEST_UA_CPU_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_X_FORWARDED_FOR_ID", REQUEST_X_FORWARDED_FOR_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_CACHE_CONTROL_ID", REQUEST_CACHE_CONTROL_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_VIA_ID", REQUEST_VIA_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_IF_MODIFIED_SINCE_ID", REQUEST_IF_MODIFIED_SINCE_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_IF_NONE_MATCH_ID", REQUEST_IF_NONE_MATCH_ID, debug);
            bind_ID (stmt_insert_B, ":REQUEST_PRAGMA_ID", REQUEST_PRAGMA_ID, debug);
	    

	    
	  } else if (letter == 'C') {
	    if (debug) {cout << "Letter is C" << endl;}
	    C = headerdata;
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":C"), C.c_str(), C.length(), 0);	    

	    
	    
	  } else if (letter == 'D') {
	    if (debug) {cout << "Letter is D" << endl;}
	    D = headerdata;
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":D"), D.c_str(), D.length(), 0);	    

	    
	    
	  } else if (letter == 'E') {
	    if (debug) {cout << "Letter is E" << endl;}
	    E = headerdata;
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":E"), E.c_str(), E.length(), 0);



	    
	  } else if (letter == 'F') {
	    if (debug) {cout << "Letter is F" << endl;}
	    F = headerdata;
	
	    if (boost::regex_search(F.c_str(), match, F_regex)) {
	      RESPONSE_HTTP_VERSION = match[1];
	      RESPONSE_HTTP_STATUS_CODE = match[2];
	      RESPONSE_HTTP_STATUS_TEXT = match[3];
              
	    } else {
	      cerr << "Failed to match F" << endl;
	    }
	    // get integer IDs from the map
            RESPONSE_HTTP_VERSION_ID = ID_from_map(RESPONSE_HTTP_VERSION,http_version_f_map,debug);
            RESPONSE_HTTP_STATUS_CODE_ID = ID_from_map(RESPONSE_HTTP_STATUS_CODE,http_status_code_map,debug);
            RESPONSE_HTTP_STATUS_TEXT_ID = ID_from_map(RESPONSE_HTTP_STATUS_TEXT,http_status_text_map,debug);
	    
	    if (boost::regex_search(F.c_str(), match, F_regex_x_powered_by)) {
	      RESPONSE_X_POWERED_BY = match[1];
	    }
	    RESPONSE_X_POWERED_BY_ID = ID_from_map(RESPONSE_X_POWERED_BY,x_powered_by_map,debug);
            
	    if (boost::regex_search(F.c_str(), match, F_regex_expires)) {
	      RESPONSE_EXPIRES = match[1];
	    }
	    RESPONSE_EXPIRES_ID = ID_from_map(RESPONSE_EXPIRES,expires_map,debug);
            
	    if (boost::regex_search(F.c_str(), match, F_regex_cache_control)) {
	      RESPONSE_CACHE_CONTROL = match[1];
	    }
	    RESPONSE_CACHE_CONTROL_ID = ID_from_map(RESPONSE_CACHE_CONTROL,cache_control_f_map,debug);
            
	    if (boost::regex_search(F.c_str(), match, F_regex_pragma)) {
	      RESPONSE_PRAGMA = match[1];
	    }
	    RESPONSE_PRAGMA_ID = ID_from_map(RESPONSE_PRAGMA,pragma_f_map,debug);
            
	    if (boost::regex_search(F.c_str(), match, F_regex_vary)) {
	      RESPONSE_VARY = match[1];
	    }
	    RESPONSE_VARY_ID = ID_from_map(RESPONSE_VARY,vary_map,debug);
            
	    if (boost::regex_search(F.c_str(), match, F_regex_content_encoding)) {
	      RESPONSE_CONTENT_ENCODING = match[1];
	    }
	    RESPONSE_CONTENT_ENCODING_ID = ID_from_map(RESPONSE_CONTENT_ENCODING,content_encoding_map,debug);
            
	    if (boost::regex_search(F.c_str(), match, F_regex_content_length)) {
	      RESPONSE_CONTENT_LENGTH = match[1];
	    }
	    RESPONSE_CONTENT_LENGTH_ID = ID_from_map(RESPONSE_CONTENT_LENGTH,content_length_f_map,debug);
            
	    if (boost::regex_search(F.c_str(), match, F_regex_connection)) {
	      RESPONSE_CONNECTION = match[1];
	    }
	    RESPONSE_CONNECTION_ID = ID_from_map(RESPONSE_CONNECTION,connection_f_map,debug);
            
	    if (boost::regex_search(F.c_str(), match, F_regex_content_type)) {
	      RESPONSE_CONTENT_TYPE = match[1];
	    }
	    RESPONSE_CONTENT_TYPE_ID = ID_from_map(RESPONSE_CONTENT_TYPE,content_type_f_map,debug);
            
	    if (boost::regex_search(F.c_str(), match, F_regex_status)) {
	      RESPONSE_STATUS = match[1];
	    }
	    RESPONSE_STATUS_ID = ID_from_map(RESPONSE_STATUS,status_map,debug);
            
	    if (boost::regex_search(F.c_str(), match, F_regex_keep_alive)) {
	      RESPONSE_KEEP_ALIVE = match[1];
	    }
	    RESPONSE_KEEP_ALIVE_ID = ID_from_map(RESPONSE_KEEP_ALIVE,keep_alive_map,debug);
	    
	    
	    // bind whole F string
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":F"), F.c_str(), F.length(), 0);	    

	    // bind first statement
            bind_ID (stmt_insert_F, ":RESPONSE_HTTP_VERSION_ID", RESPONSE_HTTP_VERSION_ID, debug);
            bind_ID (stmt_insert_F, ":RESPONSE_HTTP_STATUS_TEXT_ID", RESPONSE_HTTP_STATUS_TEXT_ID, debug);
                        
	    // bind the rest
            bind_ID (stmt_insert_F, ":RESPONSE_X_POWERED_BY_ID", RESPONSE_X_POWERED_BY_ID, debug);
            bind_ID (stmt_insert_F, ":RESPONSE_EXPIRES_ID", RESPONSE_X_POWERED_BY_ID, debug);
            bind_ID (stmt_insert_F, ":RESPONSE_CACHE_CONTROL_ID", RESPONSE_CACHE_CONTROL_ID, debug);
            bind_ID (stmt_insert_F, ":RESPONSE_PRAGMA_ID", RESPONSE_PRAGMA_ID, debug);
            bind_ID (stmt_insert_F, ":RESPONSE_VARY_ID", RESPONSE_VARY_ID, debug);
            bind_ID (stmt_insert_F, ":RESPONSE_CONTENT_ENCODING_ID", RESPONSE_CONTENT_ENCODING_ID, debug);
            bind_ID (stmt_insert_F, ":RESPONSE_CONTENT_LENGTH_ID", RESPONSE_CONTENT_LENGTH_ID, debug);
            bind_ID (stmt_insert_F, ":RESPONSE_CONNECTION_ID", RESPONSE_CONNECTION_ID, debug);
            bind_ID (stmt_insert_F, ":RESPONSE_CONTENT_TYPE_ID", RESPONSE_CONTENT_TYPE_ID, debug);
            bind_ID (stmt_insert_F, ":RESPONSE_STATUS_ID", RESPONSE_STATUS_ID, debug);
            bind_ID (stmt_insert_F, ":RESPONSE_KEEP_ALIVE_ID", RESPONSE_KEEP_ALIVE_ID, debug);
            bind_ID (stmt_insert_F, ":RESPONSE_HTTP_STATUS_CODE_ID", RESPONSE_HTTP_STATUS_CODE_ID, debug);
            
            
            
            
            
	    
	    
	    
	    
	    
	    
	    
	    
	  } else if (letter == 'G') {
	    if (debug) {cout << "Letter is G" << endl;}
	    G = headerdata;
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":G"), G.c_str(), G.length(), 0);	    

	    
	  } else if (letter == 'H') {
	    if (debug) {cout << "Letter is H" << endl;}
	    H = headerdata;
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":H"), H.c_str(), H.length(), 0);	
	    
	    // make a stream object from the H string so that it can be processed line by line
	    std::istringstream streamH(H);
	    string Hline;
	    while (getline(streamH, Hline)) {
	      if (boost::regex_search(Hline.c_str(), match, H_regex_messages)) {
		TRAILER_MESSAGES.append(match[1]);
		TRAILER_MESSAGES.append(string("\n"));
	      }
	    }
	    
	    TRAILER_MESSAGES_ID = ID_from_map(TRAILER_MESSAGES,messages_map,debug);
	    
            
            
            
            
            
            // split up all messages for this record into messages related to each rule file
            // messagesmap holds a map of table names to messages related to that rule file
            // make a stream object from the H string so that it can be processed line by line
	    
            // clear values in the messagesmap before starting 
            messagesmap.erase(messagesmap.begin(), messagesmap.end());
            
            std::istringstream messagesStream(TRAILER_MESSAGES);
            string messageLine;
            string tableMessages;
            while (getline(messagesStream, messageLine)) {
                // match rule IDs in this line
                if (boost::regex_search(messageLine.c_str(), match, H_regex_any_rule)) {
                    string id = match[1];
                    // look up the ID in the rulesdata map, find the name of the rule file (table name) it is from, and add the line to that data in the messagesmap
                    auto pos = ruledatamap.find(id);
                    if (pos == ruledatamap.end()) { 
                        // check if an error for this id has already been printed, if not then print an error and add the ID to the set
                        auto pos3 = printedErrorIDs.find(id);
                        if ( pos3 == printedErrorIDs.end() ) {
                            cerr << UNIQUE_ID << ": no data found for rule " << id << ", is your config " << rulesdatafile << " out of date? (new file can be generated with crs_to_ruledata.pl script)" << endl;
                            cerr << "note - subsequent errors for this rule ID will be ignored" << endl;
                            // add the id to the set
                            printedErrorIDs.insert(id);
                        }
                    } else {
                        if (debug) {cout << "rule " << id << " was found in the map, looking up table name" << endl;}
                        string tablename = (pos->second).table_name; // value is ruledata structure
                        // get current data for table name from the messagesmap
                        auto pos2 = messagesmap.find(tablename);
                        if (pos2 == messagesmap.end()) {
                            // no data in the map yet
                            messagesmap[tablename] = messageLine;
                        } else {
                            // add to the current data
                            string currentdata = messagesmap[tablename];
                            currentdata.append(messageLine);
                            currentdata.append(string("\n"));
                            messagesmap[tablename] = currentdata;
                        }
                    }
                }
            }
            
            // bind data from the messagesmap to the columns in table H
            for ( const auto &id : messagesmap ) {
                // get ID for this messages from the map (inserts a new record if one doesn't exist already)
                int bind_data = ID_from_map(id.second,messages_map,debug);
                // bind the data
                string coloncolumn = ":";
                coloncolumn.append(id.first);
                bind_ID (stmt_insert_H, coloncolumn.c_str(), bind_data, debug);
            }
            
            
            
            
            
            
            
	    
	    if (boost::regex_search(H.c_str(), match, H_regex_apache_handler)) {
	      TRAILER_APACHE_HANDLER = match[1];
	    }
	    TRAILER_APACHE_HANDLER_ID = ID_from_map(TRAILER_APACHE_HANDLER,apache_handler_map,debug);
            
	    if (boost::regex_search(H.c_str(), match, H_regex_apache_error)) {
	      TRAILER_APACHE_ERROR = match[1];
	    }
	    TRAILER_APACHE_ERROR_ID = ID_from_map(TRAILER_APACHE_ERROR,apache_error_map,debug);
            
	    if (boost::regex_search(H.c_str(), match, H_regex_stopwatch)) {
	      TRAILER_STOPWATCH = match[1];
	    }
	    if (boost::regex_search(H.c_str(), match, H_regex_stopwatch2)) {
	      TRAILER_STOPWATCH2 = match[1];
	    }
	    //if (boost::regex_search(H.c_str(), match, H_regex_response_body_transformed)) {
	    //  TRAILER_RESPONSE_BODY_TRANSFORMED = match[1];
	    //}
	    if (boost::regex_search(H.c_str(), match, H_regex_producer)) {
	      TRAILER_PRODUCER = match[1];
	    }
	    TRAILER_PRODUCER_ID = ID_from_map(TRAILER_PRODUCER,producer_map,debug);
            
	    if (boost::regex_search(H.c_str(), match, H_regex_server)) {
	      TRAILER_SERVER = match[1];
	    }
	    TRAILER_SERVER_ID = ID_from_map(TRAILER_SERVER,server_map,debug);
            
	    if (boost::regex_search(H.c_str(), match, H_regex_engine_mode)) {
	      TRAILER_ENGINE_MODE = match[1];
	    }
	    TRAILER_ENGINE_MODE_ID = ID_from_map(TRAILER_ENGINE_MODE,engine_mode_map,debug);
            
	    if (boost::regex_search(H.c_str(), match, H_regex_action)) {
	      TRAILER_ACTION = match[1];
	    }
	    TRAILER_ACTION_ID = ID_from_map(TRAILER_ACTION,action_map,debug);
            
	    if (boost::regex_search(H.c_str(), match, H_regex_xml_parser_error)) {
	      TRAILER_XML_PARSER_ERROR = match[1];
	    }
	    TRAILER_XML_PARSER_ERROR_ID = ID_from_map(TRAILER_XML_PARSER_ERROR,xml_parser_error_map,debug);
	    
	    // bind values for table H
	    sqlite3_bind_text(stmt_insert_H, sqlite3_bind_parameter_index(stmt_insert_H, ":TRAILER_STOPWATCH"), TRAILER_STOPWATCH.c_str(), TRAILER_STOPWATCH.length(), 0);
	    sqlite3_bind_text(stmt_insert_H, sqlite3_bind_parameter_index(stmt_insert_H, ":TRAILER_STOPWATCH2"), TRAILER_STOPWATCH2.c_str(), TRAILER_STOPWATCH2.length(), 0);
	    
            
            // bind ID ints
            bind_ID (stmt_insert_H, ":TRAILER_MESSAGES_ID", TRAILER_MESSAGES_ID, debug);
            bind_ID (stmt_insert_H, ":TRAILER_APACHE_HANDLER_ID", TRAILER_APACHE_HANDLER_ID, debug);
            bind_ID (stmt_insert_H, ":TRAILER_PRODUCER_ID", TRAILER_PRODUCER_ID, debug);
            bind_ID (stmt_insert_H, ":TRAILER_SERVER_ID", TRAILER_SERVER_ID, debug);
            bind_ID (stmt_insert_H, ":TRAILER_ENGINE_MODE_ID", TRAILER_ENGINE_MODE_ID, debug);
            bind_ID (stmt_insert_H, ":TRAILER_ACTION_ID", TRAILER_ACTION_ID, debug);
            bind_ID (stmt_insert_H, ":TRAILER_XML_PARSER_ERROR_ID", TRAILER_XML_PARSER_ERROR_ID, debug);
            bind_ID (stmt_insert_H, ":TRAILER_APACHE_ERROR_ID", TRAILER_APACHE_ERROR_ID, debug);
            
            

	    
	    // if the next operation is performed on the string H, then the data for H in the database becomes corrupted. Is sregex_iterator moving the start of H?
	    string H2 = H;
	    
	    
	    // search for rule IDs and bind integers
	    boost::sregex_iterator m1(H2.begin(), H2.end(), H_regex_any_rule);
	    boost::sregex_iterator m2;
	    std::set<std::string> ruleIDsSet; // use a set to hold the IDs so no duplicates are created
	    std::vector < string > ruleIDsVector; // use a vector to hold the IDs and preserve duplicates

	    
	    
	    
	    
	    // for each match, add the submatch (six digit rule ID) to a set and a vector
	    for (; m1 !=m2; ++m1) {
	      ruleIDsSet.insert ( m1->str(1) ); // rule IDs set (no duplicates)
	      ruleIDsVector.push_back( m1->str(1) ); // rule IDs vector (duplicates)
	    }
	    
	    
	    // print the unique ID followed by a unique list of the rule IDs matched
	    if (debug) {
	      cout << UNIQUE_ID << ": rules matched: ";
	      for (const auto &id : ruleIDsSet) {
		cout << id << ", ";
	      }
	      cout << endl;
	    }


	    // now count the number of times each individual rule was matched
	    map<string, size_t> ruleIDCountMap; // empty map from id string to size_t
	    int ids = ruleIDsVector.size(); // get size of vector holding ruleIDs
	    
	    // use "word count" program like cpp primer p.421
	    for ( int id = 0; id < ids; ++id) {
	      // increment the counter for the id
	      ++ruleIDCountMap[ruleIDsVector[id]];
	    }
	    
	    // print results
	    if (debug) {
	      for (const auto &id : ruleIDCountMap) {
		cout << id.first << " counted " << id.second
		  << ((id.second >1 ) ? " times" : " time") << endl;
	      }
	    }
	    
	    
	    // bind scores to the scores table
	    for (const auto &id : ruleIDCountMap) {
                // multiply the count number by the weighting to get the score for that rule and add increase the integer for the relevant table
                // look up weighting in the rulesdata map
                int weighting;
                int rulescore;
                int currentscore;
                string rulefilename;
                string ruleno = id.first;
                
                auto pos = ruledatamap.find(ruleno);
                
                if (pos == ruledatamap.end()) { 
                    // check if an error for this id has already been printed, if not then print an error and add the ID to the set
                    auto pos3 = printedErrorIDs.find(ruleno);
                    if ( pos3 == printedErrorIDs.end() ) {
                        cerr << UNIQUE_ID << ": no data found for rule " << ruleno << ", is your config " << rulesdatafile << " out of date? (new file can be generated with crs_to_ruledata.pl script)" << endl;
                        cerr << "note - subsequent errors for this rule ID will be ignored" << endl;
                        // add the id to the set
                        printedErrorIDs.insert(ruleno);
                    }
                } else {
                    
                    if (debug) {cout << "rule " << ruleno << " was found in the map, looking up weighting" << endl;}
                    weighting = (pos->second).anomaly_score; // value is ruledata structure. Set weighting equal to anomaly score
                    if (debug) {cout << "weighting is " << weighting << endl;}
                    
                    // calculate the score
                    rulescore = id.second * weighting; // number of matches multiplied by weighting
                    
                    // fetch the relevant rulefile name (string) for this rule
                    rulefilename = (pos->second).table_name;
                    if (debug) {cout << "Rule filename is " << rulefilename << endl;}
                    
                    // look up the counter associated with this string
                    currentscore = rulefiletocountermap[rulefilename];
                    if (debug) {cout << "Counter for this rulefile is currently " << currentscore << endl;}
                    
                    // set new score
                    rulefiletocountermap[rulefilename] = currentscore + rulescore;
                    
                }

            }
            
            
            
            
            
            
            // bind values to the ruleID score table
            int totalscore;
            for (const auto &rf : rulefiletocountermap) {
                
                string rulefile = rf.first;
                string colonrulefile = ":" + rulefile; 
                int score = rf.second;
                totalscore = totalscore + score;
                
                int rc_bind = sqlite3_bind_int(stmt_insert_anomaly_scores, sqlite3_bind_parameter_index(stmt_insert_anomaly_scores, colonrulefile.c_str()), score);
                
                if (rc_bind != SQLITE_OK) {
		  cerr << UNIQUE_ID << ": error binding score for " << rulefile << " . Code " << rc_bind << " description: " << sqlite3_errmsg(db) << endl;
		} else {
		  if (debug) {cout << UNIQUE_ID << ": score for " << rulefile << " bound successfully" << endl;}
		}
		
            }
            
            int rc_totalbind = sqlite3_bind_int(stmt_insert_anomaly_scores, sqlite3_bind_parameter_index(stmt_insert_anomaly_scores, ":total_score"), totalscore);
                
            if (rc_totalbind != SQLITE_OK) {
                cerr << UNIQUE_ID << ": error binding total score. Code " << rc_totalbind << " description: " << sqlite3_errmsg(db) << endl;
            } else {
                if (debug) {cout << UNIQUE_ID << ": total score bound successfully" << endl;}
            }
            
            
            // reset all of the counters
            // NB: cbegin is for const iterator to beginning of a map, begin is just iterator to beginning (not const). cbegin can't be used to modify content of map pointed to
            auto map_it = rulefiletocountermap.begin();
            while (map_it != rulefiletocountermap.end()) {
                map_it->second=0;
                ++map_it;
            }
            totalscore = 0;
            
            
            // need to iterate through user supplied data of rule IDs, look up tablename for each rule ID,
            // then use the tablename to look up the prepared statement in the insert_statements_map
            // bind the number of matches for each rule to the relevant statement
            for (const auto &pos : ruledatamap) {
                
                // get ID string
                string IDstring = pos.second.rule_id;
                string tablename = pos.second.table_name;

                auto pos2 = insert_statements_map.find(tablename);
                if (pos2 == insert_statements_map.end()) {
                    cerr << "table name " << tablename << " was not found in the map" << endl;
                } else {
                    
                    string colonnumber = ":" + IDstring;
                    
                    int rc_bind;
                    int num_matches;
                    
                    auto pos3 = ruleIDCountMap.find(IDstring);
                    if (pos3 == ruleIDCountMap.end()) { // if id does not exist as a key in the counter map, then there were no matches
                        num_matches = 0;
                    } else {
                        num_matches = pos3->second;
                    }
                    
                    rc_bind = sqlite3_bind_int(pos2->second, sqlite3_bind_parameter_index(pos2->second, colonnumber.c_str()), num_matches);
                    
                    if (rc_bind != SQLITE_OK) {
                        cerr << UNIQUE_ID << ": error binding values for " << IDstring << " to table " << tablename << ". Code " << rc_bind << " description: " << sqlite3_errmsg(db) << endl;
                    } else {
                        if (debug) {cout << UNIQUE_ID << ": values for " << IDstring << " bound successfully" << endl;}
                    }
                }
		
            }
	    
	    
	    
	    
	    
	    
	  } else if (letter == 'I') {
	    if (debug) {cout << "Letter is I" << endl;}
	    I = headerdata;
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":I"), I.c_str(), I.length(), 0);

	    
	  } else if (letter == 'J') {
	    if (debug) {cout << "Letter is J" << endl;}
	    J = headerdata;
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":J"), J.c_str(), J.length(), 0);

	    
	  } else if (letter == 'K') {
	    if (debug) {cout << "Letter is K" << endl;}
	    K = headerdata;
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":K"), K.c_str(), K.length(), 0);

	    
	  } else if (letter == 'Z') {
	    if (debug) {cout << "Letter is Z, committing to database" << endl;}
	    	    

	    // commit data to the database
	    for (const auto &s : prepared_statements_map) {
	      int step_rc = sqlite3_step(*get<1>(s.second));
	      if (step_rc != SQLITE_OK && step_rc != SQLITE_DONE) {
		cerr << UNIQUE_ID << ": SQLite error stepping " << s.first << " . Code " << step_rc << ": " << sqlite3_errmsg(db) << endl;
	      } else {
		if (debug) {cout << UNIQUE_ID << ": " << s.first << " was stepped successfully" << endl;}
	      }
	    }
	    for (const auto &s : insert_statements_map) {
	      int step_rc = sqlite3_step(s.second);
	      if (step_rc != SQLITE_OK && step_rc != SQLITE_DONE) {
		cerr << UNIQUE_ID << ": SQLite error stepping " << s.first << " . Code " << step_rc << ": " << sqlite3_errmsg(db) << endl;
	      } else {
		if (debug) {cout << UNIQUE_ID << ": " << s.first << " was stepped successfully" << endl;}
	      }
	    }
            
            
            
	    // reset all of the prepared statements ready to be re-executed
	    for (const auto &s : prepared_statements_map) {
	      int reset_rc = sqlite3_reset(*get<1>(s.second));
              
              // sqlite3_reset returns SQLITE_OK if the last call to sqlite3_step was SQLITE_ROW or SQLITE_DONE, or
              // the error message for the last step if not, there's no point in printing errors now (since they would be a duplicate
              // of what was printed it at the step stage)
              
	    }
	    
	    for (const auto &s : insert_statements_map) {
	      int reset_rc = sqlite3_reset(s.second);
              
              // sqlite3_reset returns SQLITE_OK if the last call to sqlite3_step was SQLITE_ROW or SQLITE_DONE, or
              // the error message for the last step if not, there's no point in printing errors now (since they would be a duplicate
              // of what was printed it at the step stage)
              
	    }
	    
	    
	    // clear bindings for each prepared statement
	    for (const auto &s : prepared_statements_map) {
	      int clear_bindings_rc = sqlite3_clear_bindings(*get<1>(s.second));
              if( clear_bindings_rc != SQLITE_OK ){
		cerr << UNIQUE_ID << ": SQL error clearing the bindings for " << s.first << "prepared statement: " << sqlite3_errmsg(db) << endl;
		//cerr << "The error was: "<< sqlite3_errmsg(db) << endl;
	      } else {
		if (debug) {cout << "Bindings for " << s.first << " were cleared successfully" << endl;}
	      }
	    }
	    for (const auto &s : insert_statements_map) {
	      int clear_bindings_rc = sqlite3_clear_bindings(s.second);
              if( clear_bindings_rc != SQLITE_OK ){
		cerr << UNIQUE_ID << ": SQL error clearing the bindings for " << s.first << "prepared statement: " << sqlite3_errmsg(db) << endl;
		//cerr << "The error was: "<< sqlite3_errmsg(db) << endl;
	      } else {
		if (debug) {cout << "Bindings for " << s.first << " were cleared successfully" << endl;}
	      }
	    }
	    
	    

	    // increment record counter
	    ++recordCounter;
	    
	    if (debug) {cout << "Resetting strings to empty" << endl;}
	    // clear main strings
	    UNIQUE_ID=HEADER=A=B=C=D=E=F=G=H="";
	    
	    // clear A strings
	    TIMESTAMP=UNIXTIME=SOURCE_IP=SOURCE_PORT=DESTINATION_IP=DESTINATION_PORT="";
	    REQUEST_METHOD=REQUEST_URI=REQUEST_HTTP_VERSION="";
	    
	    // clear B strings
	    REQUEST_HOST=REQUEST_CONNECTION=REQUEST_ACCEPT=REQUEST_USER_AGENT=REQUEST_DNT=REQUEST_REFERRER=REQUEST_ACCEPT_ENCODING=REQUEST_ACCEPT_LANGUAGE=REQUEST_COOKIE=REQUEST_X_REQUESTED_WITH=REQUEST_CONTENT_TYPE=REQUEST_CONTENT_LENGTH=REQUEST_PROXY_CONNECTION=REQUEST_ACCEPT_CHARSET=REQUEST_UA_CPU=REQUEST_X_FORWARDED_FOR=REQUEST_CACHE_CONTROL=REQUEST_VIA=REQUEST_IF_MODIFIED_SINCE=REQUEST_IF_NONE_MATCH=REQUEST_PRAGMA="";
	    RESPONSE_HTTP_VERSION=RESPONSE_HTTP_STATUS_CODE=RESPONSE_HTTP_STATUS_TEXT=RESPONSE_X_POWERED_BY=RESPONSE_EXPIRES=RESPONSE_CACHE_CONTROL=RESPONSE_PRAGMA=RESPONSE_VARY=RESPONSE_CONTENT_ENCODING=RESPONSE_CONTENT_LENGTH=RESPONSE_CONNECTION= RESPONSE_CONTENT_TYPE=RESPONSE_STATUS=RESPONSE_KEEP_ALIVE="";
	    
	    // clear H strings
	    TRAILER_MESSAGES=TRAILER_APACHE_HANDLER=TRAILER_APACHE_ERROR=TRAILER_STOPWATCH=TRAILER_STOPWATCH2=TRAILER_PRODUCER=TRAILER_SERVER=TRAILER_ENGINE_MODE=TRAILER_ACTION=TRAILER_XML_PARSER_ERROR="";
            
	    
	  }
	  break; // stop reading file
	} // end of "if line == endline"
      } // end of "while (getline(in, linedata))
    } // end of for loop looping through results vector
    
    
    // create sql statements for committing to database
    // A
    const char * sql_source_ip_ID = "INSERT OR IGNORE INTO source_ip (source_ip_id, source_ip) VALUES (:id, :value);";
    const char * sql_source_port_ID = "INSERT OR IGNORE INTO source_port (source_port_id, source_port) VALUES (:id, :value);";
    const char * sql_destination_ip_ID = "INSERT OR IGNORE INTO destination_ip (destination_ip_id, destination_ip) VALUES (:id, :value);";
    const char * sql_destination_port_ID = "INSERT OR IGNORE INTO destination_port (destination_port_id, destination_port) VALUES (:id, :value);";

    // B
    const char * sql_request_method_ID = "INSERT OR IGNORE INTO request_method (request_method_id, request_method) VALUES (:id, :value);";
    const char * sql_uri_ID = "INSERT OR IGNORE INTO uri (uri_id, uri) VALUES (:id, :value);";
    const char * sql_http_version_b_ID = "INSERT OR IGNORE INTO http_version_b (http_version_b_id, http_version_b) VALUES (:id, :value);";
    const char * sql_hosts_ID = "INSERT OR IGNORE INTO hosts (host_id, host) VALUES (:id, :value);";
    const char * sql_connection_b_ID = "INSERT OR IGNORE INTO connection_b (connection_b_id, connection_b) VALUES (:id, :value);";
    const char * sql_accept_ID = "INSERT OR IGNORE INTO accept (accept_id, accept) VALUES (:id, :value);";
    const char * sql_user_agent_ID = "INSERT OR IGNORE INTO user_agent (user_agent_id, user_agent) VALUES (:id, :value);";
    const char * sql_dnt_ID = "INSERT OR IGNORE INTO dnt (dnt_id, dnt) VALUES (:id, :value);";
    const char * sql_referrer_ID = "INSERT OR IGNORE INTO referrer (referrer_id, referrer) VALUES (:id, :value);";
    const char * sql_accept_encoding_ID = "INSERT OR IGNORE INTO accept_encoding (accept_encoding_id, accept_encoding) VALUES (:id, :value);";
    const char * sql_accept_language_ID = "INSERT OR IGNORE INTO accept_language (accept_language_id, accept_language) VALUES (:id, :value);";
    const char * sql_cookie_ID = "INSERT OR IGNORE INTO cookie (cookie_id, cookie) VALUES (:id, :value);";
    const char * sql_x_requested_with_ID = "INSERT OR IGNORE INTO x_requested_with (x_requested_with_id, x_requested_with) VALUES (:id, :value);";
    const char * sql_content_type_b_ID = "INSERT OR IGNORE INTO content_type_b (content_type_b_id, content_type_b) VALUES (:id, :value);";
    const char * sql_content_length_b_ID = "INSERT OR IGNORE INTO content_length_b (content_length_b_id, content_length_b) VALUES (:id, :value);";
    const char * sql_proxy_connection_ID = "INSERT OR IGNORE INTO proxy_connection (proxy_connection_id, proxy_connection) VALUES (:id, :value);";
    const char * sql_accept_charset_ID = "INSERT OR IGNORE INTO accept_charset (accept_charset_id, accept_charset) VALUES (:id, :value);";
    const char * sql_ua_cpu_ID = "INSERT OR IGNORE INTO ua_cpu (ua_cpu_id, ua_cpu) VALUES (:id, :value);";
    const char * sql_x_forwarded_for_ID = "INSERT OR IGNORE INTO x_forwarded_for (x_forwarded_for_id, x_forwarded_for) VALUES (:id, :value);";
    const char * sql_cache_control_b_ID = "INSERT OR IGNORE INTO cache_control_b (cache_control_b_id, cache_control_b) VALUES (:id, :value);";
    const char * sql_via_ID = "INSERT OR IGNORE INTO via (via_id, via) VALUES (:id, :value);";
    const char * sql_if_modified_since_ID = "INSERT OR IGNORE INTO if_modified_since (if_modified_since_id, if_modified_since) VALUES (:id, :value);";
    const char * sql_if_none_match_ID = "INSERT OR IGNORE INTO if_none_match (if_none_match_id, if_none_match) VALUES (:id, :value);";
    const char * sql_pragma_b_ID = "INSERT OR IGNORE INTO pragma_b (pragma_b_id, pragma_b) VALUES (:id, :value);";
    
    // F
    const char * sql_http_version_f_ID = "INSERT OR IGNORE INTO http_version_f (http_version_f_id, http_version_f) VALUES (:id, :value);";
    const char * sql_http_status_code_ID = "INSERT OR IGNORE INTO http_status_code (http_status_code_id, http_status_code) VALUES (:id, :value);";
    const char * sql_http_status_text_ID = "INSERT OR IGNORE INTO http_status_text (http_status_text_id, http_status_text) VALUES (:id, :value);";
    const char * sql_x_powered_by_ID = "INSERT OR IGNORE INTO x_powered_by (x_powered_by_id, x_powered_by) VALUES (:id, :value);";
    const char * sql_expires_ID = "INSERT OR IGNORE INTO expires (expires_id, expires) VALUES (:id, :value);";
    const char * sql_cache_control_f_ID = "INSERT OR IGNORE INTO cache_control_f (cache_control_f_id, cache_control_f) VALUES (:id, :value);";
    const char * sql_pragma_f_ID = "INSERT OR IGNORE INTO pragma_f (pragma_f_id, pragma_f) VALUES (:id, :value);";
    const char * sql_vary_ID = "INSERT OR IGNORE INTO vary (vary_id, vary) VALUES (:id, :value);";
    const char * sql_content_encoding_ID = "INSERT OR IGNORE INTO content_encoding (content_encoding_id, content_encoding) VALUES (:id, :value);";
    const char * sql_content_length_f_ID = "INSERT OR IGNORE INTO content_length_f (content_length_f_id, content_length_f) VALUES (:id, :value);";
    const char * sql_connection_f_ID = "INSERT OR IGNORE INTO connection_f (connection_f_id, connection_f) VALUES (:id, :value);";
    const char * sql_content_type_f_ID = "INSERT OR IGNORE INTO content_type_f (content_type_f_id, content_type_f) VALUES (:id, :value);";
    const char * sql_status_ID = "INSERT OR IGNORE INTO status (status_id, status) VALUES (:id, :value);";
    const char * sql_keep_alive_ID = "INSERT OR IGNORE INTO keep_alive (keep_alive_id, keep_alive) VALUES (:id, :value);";

    // H
    const char * sql_messages_ID = "INSERT OR IGNORE INTO messages (messages_id, messages) VALUES (:id, :value);";
    const char * sql_apache_handler_ID = "INSERT OR IGNORE INTO apache_handler (apache_handler_id, apache_handler) VALUES (:id, :value);";
    const char * sql_producer_ID = "INSERT OR IGNORE INTO producer (producer_id, producer) VALUES (:id, :value);";
    const char * sql_server_ID = "INSERT OR IGNORE INTO server (server_id, server) VALUES (:id, :value);";
    const char * sql_engine_mode_ID = "INSERT OR IGNORE INTO engine_mode (engine_mode_id, engine_mode) VALUES (:id, :value);";
    const char * sql_action_ID = "INSERT OR IGNORE INTO action (action_id, action) VALUES (:id, :value);";
    const char * sql_apache_error_ID = "INSERT OR IGNORE INTO apache_error (apache_error_id, apache_error) VALUES (:id, :value);";
    const char * sql_xml_parser_error_ID = "INSERT OR IGNORE INTO xml_parser_error (xml_parser_error_id, xml_parser_error) VALUES (:id, :value);";
    
    
    
    

    
    
    
    // commit ID maps to database
    // A
    commit_maps(db, sql_source_ip_ID, source_ip_map, debug);
    commit_maps(db, sql_source_port_ID, source_port_map, debug);
    commit_maps(db, sql_destination_ip_ID, destination_ip_map, debug);
    commit_maps(db, sql_destination_port_ID, destination_port_map, debug);

    // B
    commit_maps(db, sql_request_method_ID, request_method_map, debug);
    commit_maps(db, sql_uri_ID, uri_map, debug);
    commit_maps(db, sql_http_version_b_ID, http_version_b_map, debug);
    commit_maps(db, sql_hosts_ID, hosts_map, debug);
    commit_maps(db, sql_connection_b_ID, connection_b_map, debug);
    commit_maps(db, sql_accept_ID, accept_map, debug);
    commit_maps(db, sql_user_agent_ID, user_agent_map, debug);    
    commit_maps(db, sql_dnt_ID, dnt_map, debug);
    commit_maps(db, sql_referrer_ID, referrer_map, debug);
    commit_maps(db, sql_accept_encoding_ID, accept_encoding_map, debug);
    commit_maps(db, sql_accept_language_ID, accept_language_map, debug);
    commit_maps(db, sql_cookie_ID, cookie_map, debug);
    commit_maps(db, sql_x_requested_with_ID, x_requested_with_map, debug);
    commit_maps(db, sql_content_type_b_ID, content_type_b_map, debug);
    commit_maps(db, sql_content_length_b_ID, content_length_b_map, debug);
    commit_maps(db, sql_proxy_connection_ID, proxy_connection_map, debug);
    commit_maps(db, sql_accept_charset_ID, accept_charset_map, debug);
    commit_maps(db, sql_ua_cpu_ID, ua_cpu_map, debug);
    commit_maps(db, sql_x_forwarded_for_ID, x_forwarded_for_map, debug);
    commit_maps(db, sql_cache_control_b_ID, cache_control_b_map, debug);
    commit_maps(db, sql_via_ID, via_map, debug);
    commit_maps(db, sql_if_modified_since_ID, if_modified_since_map, debug);
    commit_maps(db, sql_if_none_match_ID, if_none_match_map, debug);
    commit_maps(db, sql_pragma_b_ID, pragma_b_map, debug);
    
    // F
    commit_maps(db, sql_http_version_f_ID, http_version_f_map, debug);
    commit_maps(db, sql_http_status_code_ID, http_status_code_map, debug);
    commit_maps(db, sql_http_status_text_ID, http_status_text_map, debug);
    commit_maps(db, sql_x_powered_by_ID, x_powered_by_map, debug);
    commit_maps(db, sql_expires_ID, expires_map, debug);
    commit_maps(db, sql_cache_control_f_ID, cache_control_f_map, debug);
    commit_maps(db, sql_pragma_f_ID, pragma_f_map, debug);
    commit_maps(db, sql_vary_ID, vary_map, debug);
    commit_maps(db, sql_content_encoding_ID, content_encoding_map, debug);
    commit_maps(db, sql_content_length_f_ID, content_length_f_map, debug);
    commit_maps(db, sql_connection_f_ID, connection_f_map, debug);
    commit_maps(db, sql_content_type_f_ID, content_type_f_map, debug);
    commit_maps(db, sql_status_ID, status_map, debug);
    commit_maps(db, sql_keep_alive_ID, keep_alive_map, debug);

    // H
    commit_maps(db, sql_messages_ID, messages_map, debug);
    commit_maps(db, sql_apache_handler_ID, apache_handler_map, debug);
    commit_maps(db, sql_producer_ID, producer_map, debug);
    commit_maps(db, sql_server_ID, server_map, debug);
    commit_maps(db, sql_engine_mode_ID, engine_mode_map, debug);
    commit_maps(db, sql_action_ID, action_map, debug);
    commit_maps(db, sql_apache_error_ID, apache_error_map, debug);
    commit_maps(db, sql_xml_parser_error_ID, xml_parser_error_map, debug);
    



    
    
    sqlite3_exec(db,"END TRANSACTION",0,0,0);
    
    
    // now that we are done with these statements they can be destroyed to free resources
    for (const auto &s : prepared_statements_map) {
      rc = sqlite3_finalize(*get<1>(s.second));
      if( rc != SQLITE_OK ){
	cerr << "SQL error finalizing " << s.first << " statement. The error was:" << endl;
	cerr << sqlite3_errmsg(db) << endl;
      } else {
	if (debug) {cout << "Finalized " << s.first << " statement successfully" << endl;}
      }
    }
    
    if (debug) {cout << "Now finalising insert statements for tables created from user supplied rule data" << endl;}
    for (const auto &s : insert_statements_map) {
      rc = sqlite3_finalize(s.second);
      if( rc != SQLITE_OK ){
	cerr << "SQL error finalizing " << s.first << " statement. The error was: " << sqlite3_errmsg(db) << endl;
      } else {
	if (debug) {cout << "Finalized " << s.first << " statement successfully" << endl;}
      }
    }    
    
    

  } 
  end = std::chrono::system_clock::now();
  std::chrono::duration<double> elapsed_seconds = end-start;
  double rate = recordCounter / elapsed_seconds.count();
  cout << "Processed " << recordCounter << " records in " << elapsed_seconds.count() << " seconds (" << rate << "/s)." << endl;
  return 0;
}