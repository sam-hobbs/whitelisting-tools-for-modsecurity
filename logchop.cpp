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

using namespace std;
using std::vector;


// 1. get size of the vector holding the header strings and line numbers
// 2. make new tables in DB to hold the logfile after it has been split by headers (is this necessary or will a commit create the table?)
// 3. start on vector row 1. determine the header letter type
// 4. get row line number for current header and row number for next header
// 5. read file, when the line number is >= the current header number and < the next header number, append the line to the data string
// 6. commit string to the correct column in the database
// 7. move on to next row in results vector


static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
  for (int i=0; i<argc; i++) {
    cout << azColName[i] << " = ";
    if (argv[i]) {cout << argv[i] << endl;} else {cout << "NULL" << endl;};
  }
  cout << endl;
  return 0;
}


int logchop(string database, string logfile, vector<pair<int,string>> results, bool debug, bool force) {
  // set a timer
  std::chrono::time_point<std::chrono::system_clock> start, end;
  start = std::chrono::system_clock::now();
  
  // record counter
  int recordCounter = 0;
  
  
  // 1. get size of the vector holding the header strings and line numbers
  // always two columns because each element in the vector is a pair
  int rows = results.size(); 
  
  // 2. make new tables in DB to hold the logfile after it has been split by headers

  // open database
  sqlite3 *db;
  int rc = sqlite3_open(database.c_str(), &db);
  if(rc) {
    cerr << "Can't open database" << endl;
  } else {
    if (debug) {cout << "Opened database successfully" << endl;}
  } 

  char *zErrMsg = 0;
  
  // create sql statements and add them to a map
  
  map <string, const char *> create_table_map;
  
  const char *sql_create_main = "CREATE TABLE main(" \
	"UNIQUE_ID			TEXT	PRIMARY KEY,"\
	"HEADER				TEXT	," \
	"A				TEXT	," \
	"B				TEXT	," \
	"C				TEXT	," \
	"D				TEXT	," \
	"E				TEXT	," \
	"F				TEXT	," \
	"G				TEXT	," \
	"H				TEXT	," \
	"I				TEXT	," \
	"J				TEXT	," \
	"K				TEXT	);";
  
  create_table_map.insert({"sql_create_main",sql_create_main});
	
  const char *sql_create_A = "CREATE TABLE A(" \
	"UNIQUE_ID			TEXT	PRIMARY KEY,"\
	"TIMESTAMP			TEXT	," \
	"SOURCE_IP			TEXT	," \
	"SOURCE_PORT			TEXT	," \
	"DESTINATION_IP			TEXT	," \
	"DESTINATION_PORT		TEXT	);";

  create_table_map.insert({"sql_create_A",sql_create_A});
	
  const char *sql_create_B = "CREATE TABLE B(" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"REQUEST_METHOD			TEXT	," \
	"URI				TEXT	," \
	"HTTP_VERSION			TEXT	," \
	"HOST				TEXT	," \
	"CONNECTION			TEXT	," \
	"ACCEPT				TEXT	," \
	"USER_AGENT			TEXT	," \
	"DNT				TEXT	," \
	"REFERRER			TEXT	," \
	"ACCEPT_ENCODING		TEXT	," \
	"ACCEPT_LANGUAGE		TEXT	," \
	"COOKIE				TEXT	," \
	"X_REQUESTED_WITH		TEXT	," \
	"CONTENT_TYPE			TEXT	," \
	"CONTENT_LENGTH			TEXT	," \
	"PROXY_CONNECTION		TEXT	," \
	"ACCEPT_CHARSET			TEXT	," \
	"UA_CPU				TEXT	," \
	"X_FORWARDED_FOR		TEXT	," \
	"CACHE_CONTROL			TEXT	," \
	"VIA				TEXT	," \
	"IF_MODIFIED_SINCE		TEXT	," \
	"IF_NONE_MATCH			TEXT	," \
	"PRAGMA				TEXT	);";

  create_table_map.insert({"sql_create_B",sql_create_B});
	
  const char *sql_create_F = "CREATE TABLE F(" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"HTTP_VERSION			TEXT	," \
	"HTTP_STATUS_CODE		TEXT	," \
	"HTTP_STATUS_TEXT		TEXT	," \
	"X_POWERED_BY			TEXT	," \
	"EXPIRES			TEXT	," \
	"CACHE_CONTROL			TEXT	," \
	"PRAGMA				TEXT	," \
	"VARY				TEXT	," \
	"CONTENT_ENCODING		TEXT	," \
	"CONTENT_LENGTH			TEXT	," \
	"CONNECTION			TEXT	," \
	"CONTENT_TYPE			TEXT	," \
	"STATUS				TEXT	," \
	"KEEP_ALIVE			TEXT	);";

  create_table_map.insert({"sql_create_F",sql_create_F});
	
  const char *sql_create_H = "CREATE TABLE H(" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"APACHE_HANDLER			TEXT	," \
	"APACHE_ERROR			TEXT	," \
	"STOPWATCH			TEXT	," \
	"STOPWATCH2			TEXT	," \
	"RESPONSE_BODY_TRANSFORMED	TEXT	," \
	"PRODUCER			TEXT	," \
	"SERVER				TEXT	," \
	"ACTION				TEXT	," \
	"XML_PARSER_ERROR		TEXT	," \
	"CRS_SEPARATE_RULES_MATCHED	INTEGER	," \
	"CRS_PROTOCOL_VIOLATION		INTEGER	," \
	"CRS_PROTOCOL_ANOMALY		INTEGER	," \
	"CRS_REQUEST_LIMIT		INTEGER	," \
	"CRS_HTTP_POLICY		INTEGER	," \
	"CRS_BAD_ROBOT			INTEGER	," \
	"CRS_GENERIC_ATTACK		INTEGER	," \
	"CRS_SQL_INJECTION		INTEGER	," \
	"CRS_XSS_ATTACK			INTEGER	," \
	"CRS_TIGHT_SECURITY		INTEGER	," \
	"CRS_TROJANS			INTEGER	," \
	"CRS_COMMON_EXCEPTIONS		INTEGER	," \
	"CRS_LOCAL_EXCEPTIONS		INTEGER	," \
	"CRS_INBOUND_BLOCKING		INTEGER	," \
	"CRS_OUTBOUND			INTEGER ," \
	"CRS_OUTBOUND_BLOCKING		INTEGER	," \
	"CRS_CORRELATION		INTEGER	," \
	"CRS_BRUTE_FORCE		INTEGER	," \
	"CRS_DOS			INTEGER	," \
	"CRS_PROXY_ABUSE		INTEGER	," \
	"CRS_SLOW_DOS			INTEGER	," \
	"CRS_CC_TRACK_PAN		INTEGER	," \
	"CRS_APPSENSOR			INTEGER	," \
	"CRS_HTTP_PARAMETER_POLLUTION	INTEGER	," \
	"CRS_CSP_ENFORCEMENT		INTEGER	," \
	"CRS_SCANNER_INTEGRATION	INTEGER	," \
	"CRS_BAYES_ANALYSIS		INTEGER	," \
	"CRS_RESPONSE_PROFILING		INTEGER	," \
	"CRS_PVI_CHECKS			INTEGER	," \
	"CRS_IP_FORENSICS		INTEGER	," \
	"CRS_IGNORE_STATIC		INTEGER	," \
	"CRS_AVS_TRAFFIC		INTEGER	," \
	"CRS_XML_ENABLER		INTEGER	," \
	"CRS_AUTHENTICATION_TRACKING	INTEGER	," \
	"CRS_SESSION_HIJACKING		INTEGER	," \
	"CRS_USERNAME_TRACKING		INTEGER	," \
	"CRS_CC_KNOWN			INTEGER	," \
	"CRS_COMMENT_SPAM		INTEGER	," \
	"CRS_CSRF_PROTECTION		INTEGER	," \
	"CRS_AV_SCANNING		INTEGER	," \
	"CRS_SKIP_OUTBOUND_CHECKS	INTEGER	," \
	"CRS_HEADER_TAGGING		INTEGER	," \
	"CRS_APPLICATION_DEFECTS	INTEGER	," \
	"CRS_MARKETING			INTEGER	);";
	
  create_table_map.insert({"sql_create_H",sql_create_H});
  

  const char *sql_create_H_protocol_violation = "CREATE TABLE CRS_PROTOCOL_VIOLATION (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
 	"'960911'			INTEGER	," \
	"'981227'			INTEGER	," \
	"'960000'			INTEGER	," \
	"'960912'			INTEGER	," \
	"'960914'			INTEGER	," \
	"'960915'			INTEGER	," \
	"'960016'			INTEGER	," \
	"'960011'			INTEGER	," \
	"'960012'			INTEGER	," \
	"'960902'			INTEGER	," \
	"'960022'			INTEGER	," \
	"'960020'			INTEGER	," \
	"'958291'			INTEGER	," \
	"'958230'			INTEGER	," \
	"'958231'			INTEGER	," \
	"'958295'			INTEGER	," \
	"'950107'			INTEGER	," \
	"'950109'			INTEGER	," \
	"'950108'			INTEGER	," \
	"'950801'			INTEGER	," \
	"'950116'			INTEGER	," \
	"'960014'			INTEGER	," \
	"'960901'			INTEGER	," \
	"'960018'			INTEGER	);";

  create_table_map.insert({"sql_create_H_protocol_violation",sql_create_H_protocol_violation});

  const char *sql_create_H_protocol_anomaly = "CREATE TABLE CRS_PROTOCOL_ANOMALY (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'960008'			INTEGER	," \
	"'960007'			INTEGER	," \
	"'960015'			INTEGER	," \
	"'960021'			INTEGER	," \
	"'960009'			INTEGER	," \
	"'960006'			INTEGER	," \
	"'960904'			INTEGER	," \
	"'960017'			INTEGER	);";

  create_table_map.insert({"sql_create_H_protocol_anomaly",sql_create_H_protocol_anomaly});
	
  const char *sql_create_H_request_limit = "CREATE TABLE CRS_REQUEST_LIMIT (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'960209'			INTEGER	," \
	"'960208'			INTEGER	," \
	"'960335'			INTEGER	," \
	"'960341'			INTEGER	," \
	"'960342'			INTEGER	," \
	"'960343'			INTEGER	);";

  create_table_map.insert({"sql_create_H_request_limit",sql_create_H_request_limit});
	
  const char *sql_create_H_http_policy = "CREATE TABLE CRS_HTTP_POLICY (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'960032'			INTEGER	," \
	"'960010'			INTEGER	," \
	"'960034'			INTEGER	," \
	"'960035'			INTEGER	," \
	"'960038'			INTEGER	);";

  create_table_map.insert({"sql_create_H_http_policy",sql_create_H_http_policy});
	
  const char *sql_create_H_bad_robot = "CREATE TABLE CRS_BAD_ROBOT (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'990002'			INTEGER	," \
	"'990901'			INTEGER	," \
	"'990902'			INTEGER	," \
	"'990012'			INTEGER	);";
	
  create_table_map.insert({"sql_create_H_bad_robot",sql_create_H_bad_robot});
	
  const char *sql_create_H_generic_attack = "CREATE TABLE CRS_GENERIC_ATTACK (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'950907'			INTEGER	," \
	"'960024'			INTEGER	," \
	"'950008'			INTEGER	," \
	"'950010'			INTEGER	," \
	"'950011'			INTEGER	," \
	"'950018'			INTEGER	," \
	"'950019'			INTEGER	," \
	"'950012'			INTEGER	," \
	"'950910'			INTEGER	," \
	"'950911'			INTEGER	," \
	"'950117'			INTEGER	," \
	"'950118'			INTEGER	," \
	"'950119'			INTEGER	," \
	"'950120'			INTEGER	," \
	"'981133'			INTEGER	," \
	"'950009'			INTEGER	," \
	"'950003'			INTEGER	," \
	"'950000'			INTEGER	," \
	"'950005'			INTEGER	," \
	"'950002'			INTEGER	," \
	"'950006'			INTEGER	," \
	"'959151'			INTEGER	," \
	"'958976'			INTEGER	," \
	"'958977'			INTEGER	);";

  create_table_map.insert({"sql_create_H_generic_attack",sql_create_H_generic_attack});

  const char *sql_create_H_sql_injection = "CREATE TABLE CRS_SQL_INJECTION (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981231'			INTEGER	," \
	"'981260'			INTEGER	," \
	"'981318'			INTEGER	," \
	"'981319'			INTEGER	," \
	"'950901'			INTEGER	," \
	"'981320'			INTEGER	," \
	"'981300'			INTEGER	," \
	"'981301'			INTEGER	," \
	"'981302'			INTEGER	," \
	"'981303'			INTEGER	," \
	"'981304'			INTEGER	," \
	"'981305'			INTEGER	," \
	"'981306'			INTEGER	," \
	"'981307'			INTEGER	," \
	"'981308'			INTEGER	," \
	"'981309'			INTEGER	," \
	"'981310'			INTEGER	," \
	"'981311'			INTEGER	," \
	"'981312'			INTEGER	," \
	"'981313'			INTEGER	," \
	"'981314'			INTEGER	," \
	"'981315'			INTEGER	," \
	"'981316'			INTEGER	," \
	"'981317'			INTEGER	," \
	"'950007'			INTEGER	," \
	"'950001'			INTEGER	," \
	"'959070'			INTEGER	," \
	"'959071'			INTEGER	," \
	"'959072'			INTEGER	," \
	"'950908'			INTEGER	," \
	"'959073'			INTEGER	," \
	"'981172'			INTEGER	," \
	"'981173'			INTEGER	," \
	"'981272'			INTEGER	," \
	"'981244'			INTEGER	," \
	"'981255'			INTEGER	," \
	"'981257'			INTEGER	," \
	"'981248'			INTEGER	," \
	"'981277'			INTEGER	," \
	"'981250'			INTEGER	," \
	"'981241'			INTEGER	," \
	"'981252'			INTEGER	," \
	"'981256'			INTEGER	," \
	"'981245'			INTEGER	," \
	"'981276'			INTEGER	," \
	"'981254'			INTEGER	," \
	"'981270'			INTEGER	," \
	"'981240'			INTEGER	," \
	"'981249'			INTEGER	," \
	"'981253'			INTEGER	," \
	"'981242'			INTEGER	," \
	"'981246'			INTEGER	," \
	"'981251'			INTEGER	," \
	"'981247'			INTEGER	," \
	"'981243'			INTEGER	);";

  create_table_map.insert({"sql_create_H_sql_injection",sql_create_H_sql_injection});
	
  const char *sql_create_H_xss_attack = "CREATE TABLE CRS_XSS_ATTACK (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'973336'			INTEGER	," \
	"'973337'			INTEGER	," \
	"'973338'			INTEGER	," \
	"'981136'			INTEGER	," \
	"'981018'			INTEGER	," \
	"'958016'			INTEGER	," \
	"'958414'			INTEGER	," \
	"'958032'			INTEGER	," \
	"'958026'			INTEGER	," \
	"'958027'			INTEGER	," \
	"'958054'			INTEGER	," \
	"'958418'			INTEGER	," \
	"'958034'			INTEGER	," \
	"'958019'			INTEGER	," \
	"'958013'			INTEGER	," \
	"'958408'			INTEGER	," \
	"'958012'			INTEGER	," \
	"'958423'			INTEGER	," \
	"'958002'			INTEGER	," \
	"'958017'			INTEGER	," \
	"'958007'			INTEGER	," \
	"'958047'			INTEGER	," \
	"'958410'			INTEGER	," \
	"'958415'			INTEGER	," \
	"'958022'			INTEGER	," \
	"'958405'			INTEGER	," \
	"'958419'			INTEGER	," \
	"'958028'			INTEGER	," \
	"'958057'			INTEGER	," \
	"'958031'			INTEGER	," \
	"'958006'			INTEGER	," \
	"'958033'			INTEGER	," \
	"'958038'			INTEGER	," \
	"'958409'			INTEGER	," \
	"'958001'			INTEGER	," \
	"'958005'			INTEGER	," \
	"'958404'			INTEGER	," \
	"'958023'			INTEGER	," \
	"'958010'			INTEGER	," \
	"'958411'			INTEGER	," \
	"'958422'			INTEGER	," \
	"'958036'			INTEGER	," \
	"'958000'			INTEGER	," \
	"'958018'			INTEGER	," \
	"'958406'			INTEGER	," \
	"'958040'			INTEGER	," \
	"'958052'			INTEGER	," \
	"'958037'			INTEGER	," \
	"'958049'			INTEGER	," \
	"'958030'			INTEGER	," \
	"'958041'			INTEGER	," \
	"'958416'			INTEGER	," \
	"'958024'			INTEGER	," \
	"'958059'			INTEGER	," \
	"'958417'			INTEGER	," \
	"'958020'			INTEGER	," \
	"'958045'			INTEGER	," \
	"'958004'			INTEGER	," \
	"'958421'			INTEGER	," \
	"'958009'			INTEGER	," \
	"'958025'			INTEGER	," \
	"'958413'			INTEGER	," \
	"'958051'			INTEGER	," \
	"'958420'			INTEGER	," \
	"'958407'			INTEGER	," \
	"'958056'			INTEGER	," \
	"'958011'			INTEGER	," \
	"'958412'			INTEGER	," \
	"'958008'			INTEGER	," \
	"'958046'			INTEGER	," \
	"'958039'			INTEGER	," \
	"'958003'			INTEGER	," \
	"'973300'			INTEGER	," \
	"'973301'			INTEGER	," \
	"'973302'			INTEGER	," \
	"'973303'			INTEGER	," \
	"'973304'			INTEGER	," \
	"'973305'			INTEGER	," \
	"'973306'			INTEGER	," \
	"'973307'			INTEGER	," \
	"'973308'			INTEGER	," \
	"'973309'			INTEGER	," \
	"'973310'			INTEGER	," \
	"'973311'			INTEGER	," \
	"'973312'			INTEGER	," \
	"'973313'			INTEGER	," \
	"'973314'			INTEGER	," \
	"'973331'			INTEGER	," \
	"'973315'			INTEGER	," \
	"'973330'			INTEGER	," \
	"'973327'			INTEGER	," \
	"'973326'			INTEGER	," \
	"'973346'			INTEGER	," \
	"'973345'			INTEGER	," \
	"'973324'			INTEGER	," \
	"'973323'			INTEGER	," \
	"'973322'			INTEGER	," \
	"'973348'			INTEGER	," \
	"'973321'			INTEGER	," \
	"'973320'			INTEGER	," \
	"'973318'			INTEGER	," \
	"'973317'			INTEGER	," \
	"'973347'			INTEGER	," \
	"'973335'			INTEGER	," \
	"'973334'			INTEGER	," \
	"'973333'			INTEGER	," \
	"'973344'			INTEGER	," \
	"'973332'			INTEGER	," \
	"'973329'			INTEGER	," \
	"'973328'			INTEGER	," \
	"'973316'			INTEGER	," \
	"'973325'			INTEGER	," \
	"'973319'			INTEGER	);";

  create_table_map.insert({"sql_create_H_xss_attack",sql_create_H_xss_attack});
	
  const char *sql_create_H_tight_security = "CREATE TABLE CRS_TIGHT_SECURITY (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'950103'			INTEGER	);";

  create_table_map.insert({"sql_create_H_tight_security",sql_create_H_tight_security});
	
  const char *sql_create_H_trojans = "CREATE TABLE CRS_TROJANS (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'950110'			INTEGER	," \
	"'950921'			INTEGER	," \
	"'950922'			INTEGER	);";

  create_table_map.insert({"sql_create_H_trojans",sql_create_H_trojans});
	
  const char *sql_create_H_common_exceptions = "CREATE TABLE CRS_COMMON_EXCEPTIONS (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981020'			INTEGER	," \
	"'981021'			INTEGER	," \
	"'981022'			INTEGER	);";

  create_table_map.insert({"sql_create_H_common_exceptions",sql_create_H_common_exceptions});
  
  const char *sql_create_H_local_exceptions = "CREATE TABLE CRS_LOCAL_EXCEPTIONS (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY );";

  create_table_map.insert({"sql_create_H_local_exceptions",sql_create_H_local_exceptions});
	
  const char *sql_create_H_inbound_blocking = "CREATE TABLE CRS_INBOUND_BLOCKING (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981175'			INTEGER	," \
	"'981176'			INTEGER	);";

  create_table_map.insert({"sql_create_H_inbound_blocking",sql_create_H_inbound_blocking});
	
  const char *sql_create_H_outbound = "CREATE TABLE CRS_OUTBOUND (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'970007'			INTEGER	," \
	"'970008'			INTEGER	," \
	"'970009'			INTEGER	," \
	"'970010'			INTEGER	," \
	"'970012'			INTEGER	," \
	"'970903'			INTEGER	," \
	"'970016'			INTEGER	," \
	"'970018'			INTEGER	," \
	"'970901'			INTEGER	," \
	"'970021'			INTEGER	," \
	"'970011'			INTEGER	," \
	"'981177'			INTEGER	," \
	"'981000'			INTEGER	," \
	"'981001'			INTEGER	," \
	"'981003'			INTEGER	," \
	"'981004'			INTEGER	," \
	"'981005'			INTEGER	," \
	"'981006'			INTEGER	," \
	"'981007'			INTEGER	," \
	"'981178'			INTEGER	," \
	"'970014'			INTEGER	," \
	"'970015'			INTEGER	," \
	"'970902'			INTEGER	," \
	"'970002'			INTEGER	," \
	"'970003'			INTEGER	," \
	"'970004'			INTEGER	," \
	"'970904'			INTEGER	," \
	"'970013'			INTEGER	);";

  create_table_map.insert({"sql_create_H_outbound",sql_create_H_outbound});
	
  const char *sql_create_H_outbound_blocking = "CREATE TABLE CRS_OUTBOUND_BLOCKING (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981200'			INTEGER	);";

  create_table_map.insert({"sql_create_H_outbound_blocking",sql_create_H_outbound_blocking});
	
  const char *sql_create_H_correlation = "CREATE TABLE CRS_CORRELATION (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981201'			INTEGER	," \
	"'981202'			INTEGER	," \
	"'981203'			INTEGER	," \
	"'981204'			INTEGER	," \
	"'981205'			INTEGER	);";
	
  create_table_map.insert({"sql_create_H_correlation",sql_create_H_correlation});
	
  const char *sql_create_H_brute_force = "CREATE TABLE CRS_BRUTE_FORCE (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981036'			INTEGER	," \
	"'981037'			INTEGER	," \
	"'981038'			INTEGER	," \
	"'981039'			INTEGER	," \
	"'981040'			INTEGER	," \
	"'981041'			INTEGER	," \
	"'981042'			INTEGER	," \
	"'981043'			INTEGER	);";

  create_table_map.insert({"sql_create_H_brute_force",sql_create_H_brute_force});
	
  const char *sql_create_H_dos = "CREATE TABLE CRS_DOS (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981044'			INTEGER	," \
	"'981045'			INTEGER	," \
	"'981046'			INTEGER	," \
	"'981047'			INTEGER	," \
	"'981048'			INTEGER	," \
	"'981049'			INTEGER	);";

  create_table_map.insert({"sql_create_H_dos",sql_create_H_dos});
	
  const char *sql_create_H_proxy_abuse = "CREATE TABLE CRS_PROXY_ABUSE (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981050'			INTEGER	);";

  create_table_map.insert({"sql_create_H_proxy_abuse",sql_create_H_proxy_abuse});
	
  const char *sql_create_H_slow_dos = "CREATE TABLE CRS_SLOW_DOS (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981051'			INTEGER	," \
	"'981052'			INTEGER	);";

  create_table_map.insert({"sql_create_H_slow_dos",sql_create_H_slow_dos});
	
//   const char *sql_create_H_scanner = "CREATE TABLE CRS_SCANNER (" \
// 	"UNIQUE_ID			TEXT	PRIMARY KEY," \
// 	"'900030'			INTEGER	," \
// 	"'900031'			INTEGER	);";
// 
//   create_table_vector.push_back(sql_create_H_scanner);
   
  const char *sql_create_H_cc_track_pan = "CREATE TABLE CRS_CC_TRACK_PAN (" \
 	"UNIQUE_ID			TEXT	PRIMARY KEY," \
 	"'920021'			INTEGER	," \
 	"'920022'			INTEGER	," \
 	"'920023'			INTEGER	);";

  create_table_map.insert({"sql_create_H_cc_track_pan",sql_create_H_cc_track_pan});
	
  const char *sql_create_H_appsensor = "CREATE TABLE CRS_APPSENSOR (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981082'			INTEGER	," \
	"'981083'			INTEGER	," \
	"'981084'			INTEGER	," \
	"'981085'			INTEGER	," \
	"'981086'			INTEGER	," \
	"'981087'			INTEGER	," \
	"'981088'			INTEGER	," \
	"'981089'			INTEGER	," \
	"'981090'			INTEGER	," \
	"'981091'			INTEGER	," \
	"'981092'			INTEGER	," \
	"'981093'			INTEGER	," \
	"'981094'			INTEGER	," \
	"'981095'			INTEGER	," \
	"'981096'			INTEGER	," \
	"'981097'			INTEGER	," \
	"'981103'			INTEGER	," \
	"'981104'			INTEGER	," \
	"'981110'			INTEGER	," \
	"'981105'			INTEGER	," \
	"'981098'			INTEGER	," \
	"'981099'			INTEGER	," \
	"'981100'			INTEGER	," \
	"'981101'			INTEGER	," \
	"'981102'			INTEGER	," \
	"'981131'			INTEGER	," \
	"'981132'			INTEGER	);";

  create_table_map.insert({"sql_create_H_appsensor",sql_create_H_appsensor});
	
  const char *sql_create_H_http_parameter_pollution = "CREATE TABLE CRS_HTTP_PARAMETER_POLLUTION (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'900032'			INTEGER	);";

  create_table_map.insert({"sql_create_H_http_parameter_pollution",sql_create_H_http_parameter_pollution});
	
  const char *sql_create_H_csp_enforcement = "CREATE TABLE CRS_CSP_ENFORCEMENT (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981142'			INTEGER	," \
	"'960001'			INTEGER	," \
	"'960002'			INTEGER	," \
	"'960003'			INTEGER	);";

  create_table_map.insert({"sql_create_H_csp_enforcement",sql_create_H_csp_enforcement});
	
  const char *sql_create_H_scanner_integration = "CREATE TABLE CRS_SCANNER_INTEGRATION (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'999003'			INTEGER	," \
	"'999004'			INTEGER	," \
	"'900030'			INTEGER	," \
	"'900031'			INTEGER	);";	
	
  create_table_map.insert({"sql_create_H_scanner_integration",sql_create_H_scanner_integration});
	
  const char *sql_create_H_bayes_analysis = "CREATE TABLE CRS_BAYES_ANALYSIS (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'900033'			INTEGER	," \
	"'900034'			INTEGER	," \
	"'900035'			INTEGER	);";


  create_table_map.insert({"sql_create_H_bayes_analysis",sql_create_H_bayes_analysis});
	
  const char *sql_create_H_response_profiling = "CREATE TABLE CRS_RESPONSE_PROFILING (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981187'			INTEGER	," \
	"'981189'			INTEGER	," \
	"'981190'			INTEGER	," \
	"'981191'			INTEGER	," \
	"'981192'			INTEGER	," \
	"'981193'			INTEGER	," \
	"'981194'			INTEGER	," \
	"'981195'			INTEGER	," \
	"'981196'			INTEGER	," \
	"'981197'			INTEGER	);";

  create_table_map.insert({"sql_create_H_response_profiling",sql_create_H_response_profiling});
	
  const char *sql_create_H_pvi_checks = "CREATE TABLE CRS_PVI_CHECKS (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981198'			INTEGER	," \
	"'981199'			INTEGER );";

  create_table_map.insert({"sql_create_H_pvi_checks",sql_create_H_pvi_checks});
	
  const char *sql_create_H_ip_forensics = "CREATE TABLE CRS_IP_FORENSICS (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'900036'			INTEGER	," \
	"'900037'			INTEGER	," \
	"'900039'			INTEGER	);";

  create_table_map.insert({"sql_create_H_ip_forensics",sql_create_H_ip_forensics});
	
  const char *sql_create_H_ignore_static = "CREATE TABLE CRS_IGNORE_STATIC (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'900040'			INTEGER	," \
	"'900041'			INTEGER	," \
	"'900042'			INTEGER	," \
	"'900043'			INTEGER	," \
	"'999005'			INTEGER	," \
	"'999006'			INTEGER	);";

  create_table_map.insert({"sql_create_H_ignore_static",sql_create_H_ignore_static});

  const char *sql_create_H_av_scanning = "CREATE TABLE CRS_AV_SCANNING (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981033'			INTEGER	," \
	"'981034'			INTEGER	," \
	"'981035'			INTEGER	," \
	"'950115'			INTEGER	);";

  create_table_map.insert({"sql_create_H_av_scanning",sql_create_H_av_scanning});  
  
  const char *sql_create_H_avs_traffic = "CREATE TABLE CRS_AVS_TRAFFIC (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981033'			INTEGER	," \
	"'981034'			INTEGER	," \
	"'981035'			INTEGER	);";

  create_table_map.insert({"sql_create_H_avs_traffic",sql_create_H_avs_traffic});
	
  const char *sql_create_H_xml_enabler = "CREATE TABLE CRS_XML_ENABLER (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981053'			INTEGER	);";

  create_table_map.insert({"sql_create_H_xml_enabler",sql_create_H_xml_enabler});
	
  const char *sql_create_H_authentication_tracking = "CREATE TABLE CRS_AUTHENTICATION_TRACKING (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY );";
	
  create_table_map.insert({"sql_create_H_authentication_tracking",sql_create_H_authentication_tracking});
	
  const char *sql_create_H_session_hijacking = "CREATE TABLE CRS_SESSION_HIJACKING (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981054'			INTEGER	," \
	"'981055'			INTEGER	," \
	"'981056'			INTEGER	," \
	"'981057'			INTEGER	," \
	"'981058'			INTEGER	," \
	"'981059'			INTEGER	," \
	"'981060'			INTEGER	," \
	"'981061'			INTEGER	," \
	"'981062'			INTEGER	," \
	"'981063'			INTEGER	," \
	"'981064'			INTEGER	);";

  create_table_map.insert({"sql_create_H_session_hijacking",sql_create_H_session_hijacking});
	
  const char *sql_create_H_username_tracking = "CREATE TABLE CRS_USERNAME_TRACKING (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981075'			INTEGER	," \
	"'981076'			INTEGER	," \
	"'981077'			INTEGER	);";

  create_table_map.insert({"sql_create_H_username_tracking",sql_create_H_username_tracking});
	
  const char *sql_create_H_cc_known = "CREATE TABLE CRS_CC_KNOWN (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981078'			INTEGER	," \
	"'981079'			INTEGER	," \
	"'920005'			INTEGER	," \
	"'920007'			INTEGER	," \
	"'920009'			INTEGER	," \
	"'920011'			INTEGER	," \
	"'920013'			INTEGER	," \
	"'920015'			INTEGER	," \
	"'920017'			INTEGER	," \
	"'981080'			INTEGER	," \
	"'920020'			INTEGER	," \
	"'920006'			INTEGER	," \
	"'920008'			INTEGER	," \
	"'920010'			INTEGER	," \
	"'920012'			INTEGER	," \
	"'920014'			INTEGER	," \
	"'920016'			INTEGER	," \
	"'920018'			INTEGER	);";

  create_table_map.insert({"sql_create_H_cc_known",sql_create_H_cc_known});
	
  const char *sql_create_H_comment_spam = "CREATE TABLE CRS_COMMENT_SPAM (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981137'			INTEGER	," \
	"'981138'			INTEGER	," \
	"'981139'			INTEGER	," \
	"'981140'			INTEGER	," \
	"'958297'			INTEGER	," \
	"'999010'			INTEGER	," \
	"'999011'			INTEGER	," \
	"'950923'			INTEGER	," \
	"'950020'			INTEGER	);";

  create_table_map.insert({"sql_create_H_comment_spam",sql_create_H_comment_spam});
	
  const char *sql_create_H_csrf_protection = "CREATE TABLE CRS_CSRF_PROTECTION (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981143'			INTEGER	," \
	"'981144'			INTEGER	," \
	"'981145'			INTEGER	);";

  create_table_map.insert({"sql_create_H_csrf_protection",sql_create_H_csrf_protection});
	
	
  const char *sql_create_H_skip_outbound_checks = "CREATE TABLE CRS_SKIP_OUTBOUND_CHECKS (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'999008'			INTEGER	);";

  create_table_map.insert({"sql_create_H_skip_outbound_checks",sql_create_H_skip_outbound_checks});
	
  const char *sql_create_H_header_tagging = "CREATE TABLE CRS_HEADER_TAGGING (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'900044'			INTEGER	," \
	"'900045'			INTEGER	);";
	
  create_table_map.insert({"sql_create_H_header_tagging",sql_create_H_header_tagging});
  
  const char *sql_create_H_application_defects = "CREATE TABLE CRS_APPLICATION_DEFECTS (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'981219'			INTEGER	," \
	"'981220'			INTEGER	," \
	"'981221'			INTEGER	," \
	"'981222'			INTEGER	," \
	"'981223'			INTEGER	," \
	"'981224'			INTEGER	," \
	"'981238'			INTEGER	," \
	"'981235'			INTEGER	," \
	"'981184'			INTEGER	," \
	"'981236'			INTEGER	," \
	"'981185'			INTEGER	," \
	"'981239'			INTEGER	," \
	"'900046'			INTEGER	," \
	"'981400'			INTEGER	," \
	"'981401'			INTEGER	," \
	"'981402'			INTEGER	," \
	"'981403'			INTEGER	," \
	"'981404'			INTEGER	," \
	"'981405'			INTEGER ," \
	"'981406'			INTEGER	," \
	"'981407'			INTEGER	," \
	"'900048'			INTEGER	," \
	"'981180'			INTEGER	," \
	"'981181'			INTEGER	," \
	"'981182'			INTEGER	);";

  create_table_map.insert({"sql_create_H_application_defects",sql_create_H_application_defects});
	
  const char *sql_create_H_marketing = "CREATE TABLE CRS_MARKETING (" \
	"UNIQUE_ID			TEXT	PRIMARY KEY," \
	"'910008'			INTEGER	," \
	"'910007'			INTEGER	," \
	"'910006'			INTEGER	);";

  create_table_map.insert({"sql_create_H_marketing",sql_create_H_marketing});
	





  // execute the SQL statements to create all of the tables in the database
  int create_table_errors = 0; // error counter (will be used later) 
  for (const auto &t : create_table_map) {
    rc = sqlite3_exec(db, t.second, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
      cerr << "SQL error executing the " << t.first << " statement. The error was: " << zErrMsg << endl;
      ++create_table_errors;
    } else {
      if (debug) { cout << "Statement " << t.first << " was executed successfully" << endl;}
    }
  }
  
  
  
  // stuff for boost regex matching
  boost::cmatch match; // cmatch type to hold matches
  
  // matches for section A, example data:
  // [25/Feb/2014:14:00:43 +0000] UwyiC38AAQEAAEx4slsAAAAG 125.210.204.242 40996 192.168.1.103 80
  boost::regex A_regex("^\\[(.*)\\]\\s(.{24})\\s(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s(\\d+)\\s(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s(\\d+).*"); // 1st match is TIMESTAMP, 2nd match is APACHE_UID, 3rd match is SOURCE_IP, 4th match is SOURCE_PORT, 5th match is DESTINATION_IP, 6th match is DESTINATION_PORT
  
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
  boost::regex H_regex_apache_handler("^Apache-Handler:(.*?)$");
  boost::regex H_regex_apache_error("^Apache-Error:(.*?)$");
  boost::regex H_regex_stopwatch("^Stopwatch:(.*?)$");
  boost::regex H_regex_stopwatch2("^Stopwatch2:(.*?)$");
  boost::regex H_regex_response_body_transformed("^Apache-Handler:(.*?)$");
  boost::regex H_regex_producer("^Producer:(.*?)$");
  boost::regex H_regex_server("^Server:(.*?)$");
  boost::regex H_regex_action("^Action:(.*?)$");
  boost::regex H_regex_xml_parser_error("^Message: XML parser error:(.*?)$");
  
  // matches for any rule ID
  boost::regex H_regex_any_rule("\\[id\\s\"(\\d{6})\"\\]");
  
  
  // matches for section I (a replacement for part C)
  // (none)
  
  // matches for section J (contains information about files uploaded using multipart/form-data encoding)
  // (none)
  
  // matches for section K (list of every rule that matched, one per line, in the order they were matched)
  // (none)
  
  // create the SQL statements that can be used to commit the values to the database
  map <string, tuple<const char *, sqlite3_stmt **>> prepared_statements_map;
  
  
  // NB: unbound values in prepared statements are NULL
  const char *sql_insert_main = "INSERT INTO main (UNIQUE_ID, HEADER, A, B, C, D, E, F, G, H, I, J, K) VALUES (:UNIQUE_ID, :HEADER, :A, :B, :C, :D, :E, :F, :G, :H, :I, :J, :K);";
  sqlite3_stmt *stmt_insert_main; // compiled statement handle (pointer of type sqlite3_stmt)
  prepared_statements_map.insert({"sql_insert_main",	make_tuple(sql_insert_main, &stmt_insert_main)});
  
  const char *sql_insert_A = "INSERT INTO A (UNIQUE_ID, TIMESTAMP, SOURCE_IP, SOURCE_PORT, DESTINATION_IP, DESTINATION_PORT) VALUES (:UNIQUE_ID, :TIMESTAMP, :SOURCE_IP, :SOURCE_PORT, :DESTINATION_IP, :DESTINATION_PORT);";
  sqlite3_stmt *stmt_insert_A;
  prepared_statements_map.insert({"sql_insert_A", make_tuple(sql_insert_A, &stmt_insert_A)});
  
  const char *sql_insert_B = "INSERT INTO B (UNIQUE_ID, REQUEST_METHOD, URI, HTTP_VERSION, HOST, CONNECTION, ACCEPT, USER_AGENT, DNT, REFERRER, ACCEPT_ENCODING, ACCEPT_LANGUAGE, COOKIE, X_REQUESTED_WITH, CONTENT_TYPE, CONTENT_LENGTH, PROXY_CONNECTION, ACCEPT_CHARSET, UA_CPU, X_FORWARDED_FOR, CACHE_CONTROL, VIA, IF_MODIFIED_SINCE, IF_NONE_MATCH, PRAGMA) VALUES (:UNIQUE_ID, :REQUEST_METHOD, :REQUEST_URI, :REQUEST_HTTP_VERSION, :REQUEST_HOST, :REQUEST_CONNECTION, :REQUEST_ACCEPT, :REQUEST_USER_AGENT, :REQUEST_DNT, :REQUEST_REFERRER, :REQUEST_ACCEPT_ENCODING, :REQUEST_ACCEPT_LANGUAGE, :REQUEST_COOKIE, :REQUEST_X_REQUESTED_WITH, :REQUEST_CONTENT_TYPE, :REQUEST_CONTENT_LENGTH, :REQUEST_PROXY_CONNECTION, :REQUEST_ACCEPT_CHARSET, :REQUEST_UA_CPU, :REQUEST_X_FORWARDED_FOR, :REQUEST_CACHE_CONTROL, :REQUEST_VIA, :REQUEST_IF_MODIFIED_SINCE, :REQUEST_IF_NONE_MATCH, :REQUEST_PRAGMA);";
  sqlite3_stmt *stmt_insert_B;
  prepared_statements_map.insert({"sql_insert_B", make_tuple(sql_insert_B, &stmt_insert_B)});
  
  const char *sql_insert_F = "INSERT INTO F (UNIQUE_ID, HTTP_VERSION, HTTP_STATUS_CODE, HTTP_STATUS_TEXT, X_POWERED_BY, EXPIRES, CACHE_CONTROL, PRAGMA, VARY, CONTENT_ENCODING, CONTENT_LENGTH, CONNECTION, CONTENT_TYPE, STATUS, KEEP_ALIVE) VALUES (:UNIQUE_ID, :RESPONSE_HTTP_VERSION, :RESPONSE_HTTP_STATUS_CODE, :RESPONSE_HTTP_STATUS_TEXT, :RESPONSE_X_POWERED_BY, :RESPONSE_EXPIRES, :RESPONSE_CACHE_CONTROL, :RESPONSE_PRAGMA, :RESPONSE_VARY, :RESPONSE_CONTENT_ENCODING, :RESPONSE_CONTENT_LENGTH, :RESPONSE_CONNECTION, :RESPONSE_CONTENT_TYPE, :RESPONSE_STATUS, :RESPONSE_KEEP_ALIVE);";
  sqlite3_stmt *stmt_insert_F;
  prepared_statements_map.insert({"sql_insert_F",make_tuple(sql_insert_F, &stmt_insert_F)});
  
  const char *sql_insert_H = "INSERT INTO H (UNIQUE_ID, APACHE_HANDLER, APACHE_ERROR, STOPWATCH, STOPWATCH2, RESPONSE_BODY_TRANSFORMED, PRODUCER, SERVER, ACTION, XML_PARSER_ERROR, CRS_SEPARATE_RULES_MATCHED, CRS_PROTOCOL_VIOLATION, CRS_PROTOCOL_ANOMALY, CRS_REQUEST_LIMIT, CRS_HTTP_POLICY, CRS_BAD_ROBOT, CRS_GENERIC_ATTACK, CRS_SQL_INJECTION, CRS_XSS_ATTACK, CRS_TIGHT_SECURITY, CRS_TROJANS, CRS_COMMON_EXCEPTIONS, CRS_LOCAL_EXCEPTIONS, CRS_INBOUND_BLOCKING, CRS_OUTBOUND, CRS_OUTBOUND_BLOCKING, CRS_CORRELATION, CRS_BRUTE_FORCE, CRS_DOS, CRS_PROXY_ABUSE, CRS_SLOW_DOS, CRS_CC_TRACK_PAN, CRS_APPSENSOR, CRS_HTTP_PARAMETER_POLLUTION, CRS_CSP_ENFORCEMENT, CRS_SCANNER_INTEGRATION, CRS_BAYES_ANALYSIS, CRS_RESPONSE_PROFILING, CRS_PVI_CHECKS, CRS_IP_FORENSICS, CRS_IGNORE_STATIC, CRS_AVS_TRAFFIC, CRS_XML_ENABLER, CRS_AUTHENTICATION_TRACKING, CRS_SESSION_HIJACKING, CRS_USERNAME_TRACKING, CRS_CC_KNOWN, CRS_COMMENT_SPAM, CRS_CSRF_PROTECTION, CRS_AV_SCANNING, CRS_SKIP_OUTBOUND_CHECKS, CRS_HEADER_TAGGING, CRS_APPLICATION_DEFECTS, CRS_MARKETING) VALUES (:UNIQUE_ID, :TRAILER_APACHE_HANDLER, :TRAILER_APACHE_ERROR, :TRAILER_STOPWATCH, :TRAILER_STOPWATCH2, :TRAILER_RESPONSE_BODY_TRANSFORMED, :TRAILER_PRODUCER, :TRAILER_SERVER, :TRAILER_ACTION, :TRAILER_XML_PARSER_ERROR, :CRS_SEPARATE_RULES_MATCHED, :CRS_PROTOCOL_VIOLATION, :CRS_PROTOCOL_ANOMALY, :CRS_REQUEST_LIMIT, :CRS_HTTP_POLICY, :CRS_BAD_ROBOT, :CRS_GENERIC_ATTACK, :CRS_SQL_INJECTION, :CRS_XSS_ATTACK, :CRS_TIGHT_SECURITY, :CRS_TROJANS, :CRS_COMMON_EXCEPTIONS, :CRS_LOCAL_EXCEPTIONS, :CRS_INBOUND_BLOCKING, :CRS_OUTBOUND, :CRS_OUTBOUND_BLOCKING, :CRS_CORRELATION, :CRS_BRUTE_FORCE, :CRS_DOS, :CRS_PROXY_ABUSE, :CRS_SLOW_DOS, :CRS_CC_TRACK_PAN, :CRS_APPSENSOR, :CRS_HTTP_PARAMETER_POLLUTION, :CRS_CSP_ENFORCEMENT, :CRS_SCANNER_INTEGRATION, :CRS_BAYES_ANALYSIS, :CRS_RESPONSE_PROFILING, :CRS_PVI_CHECKS, :CRS_IP_FORENSICS, :CRS_IGNORE_STATIC, :CRS_AVS_TRAFFIC, :CRS_XML_ENABLER, :CRS_AUTHENTICATION_TRACKING, :CRS_SESSION_HIJACKING, :CRS_USERNAME_TRACKING, :CRS_CC_KNOWN, :CRS_COMMENT_SPAM, :CRS_CSRF_PROTECTION, :CRS_AV_SCANNING, :CRS_SKIP_OUTBOUND_CHECKS, :CRS_HEADER_TAGGING, :CRS_APPLICATION_DEFECTS, :CRS_MARKETING);";
  sqlite3_stmt *stmt_insert_H;
  prepared_statements_map.insert({"sql_insert_H",make_tuple(sql_insert_H, &stmt_insert_H)});

  
  
  
  
  // ************************* PROTOCOL VIOLATION **************************  
  const char *sql_insert_crs_protocol_violation = "INSERT INTO CRS_PROTOCOL_VIOLATION (UNIQUE_ID, '960911', '981227', '960000', '960912', '960914', '960915','960016','960011','960012','960902','960022','960020','958291','958230','958231','958295','950107','950109','950108','950801','950116','960014','960901','960018') VALUES (:UNIQUE_ID, :960911, :981227, :960000, :960912, :960914, :960915,:960016,:960011,:960012,:960902,:960022,:960020,:958291,:958230,:958231,:958295,:950107,:950109,:950108,:950801,:950116,:960014,:960901,:960018);";
  sqlite3_stmt *stmt_insert_crs_protocol_violation;
  prepared_statements_map.insert({"sql_insert_crs_protocol_violation",make_tuple(sql_insert_crs_protocol_violation, &stmt_insert_crs_protocol_violation)});
  
  // ************************* PROTOCOL ANOMALY **************************
  const char *sql_insert_crs_protocol_anomaly = "INSERT INTO CRS_PROTOCOL_ANOMALY (UNIQUE_ID, '960008', '960007', '960015', '960021', '960009', '960006', '960904', '960017') VALUES (:UNIQUE_ID, :960008, :960007, :960015, :960021, :960009, :960006, :960904, :960017);";
  sqlite3_stmt *stmt_insert_crs_protocol_anomaly;
  prepared_statements_map.insert({"sql_insert_protocol_anomaly",make_tuple(sql_insert_crs_protocol_anomaly, &stmt_insert_crs_protocol_anomaly)});
  
  // ************************* REQUEST LIMIT **************************
  const char *sql_insert_crs_request_limit = "INSERT INTO CRS_REQUEST_LIMIT (UNIQUE_ID, '960209', '960208', '960335', '960341', '960342', '960343') VALUES (:UNIQUE_ID, :960209, :960208, :960335, :960341, :960342, :960343);";
  sqlite3_stmt *stmt_insert_crs_request_limit;
  prepared_statements_map.insert({"sql_insert_crs_request_limit",make_tuple(sql_insert_crs_request_limit, &stmt_insert_crs_request_limit)});
  
  // ************************* HTTP POLICY **************************
  const char *sql_insert_crs_http_policy = "INSERT INTO CRS_HTTP_POLICY (UNIQUE_ID, '960032', '960010', '960034', '960035', '960038') VALUES (:UNIQUE_ID, :960032, :960010, :960034, :960035, :960038);";
  sqlite3_stmt *stmt_insert_crs_http_policy;
  prepared_statements_map.insert({"sql_insert_crs_http_policy",make_tuple(sql_insert_crs_http_policy, &stmt_insert_crs_http_policy)});
  
  // ************************* BAD ROBOT **************************
  const char *sql_insert_crs_bad_robot = "INSERT INTO CRS_BAD_ROBOT (UNIQUE_ID, '990002', '990901', '990902', '990012') VALUES (:UNIQUE_ID, :990002, :990901, :990902, :990012);";
  sqlite3_stmt *stmt_insert_crs_bad_robot;
  prepared_statements_map.insert({"sql_insert_crs_bad_robot",make_tuple(sql_insert_crs_bad_robot, &stmt_insert_crs_bad_robot)});
  
  // ************************* GENERIC ATTACK **************************
  const char *sql_insert_crs_generic_attack = "INSERT INTO CRS_GENERIC_ATTACK (UNIQUE_ID, '950907', '960024', '950008', '950010', '950011', '950018', '950019', '950012', '950910', '950911', '950117', '950118', '950119', '950120', '981133', '950009', '950003', '950000', '950005', '950002', '950006', '959151', '958976', '958977') VALUES (:UNIQUE_ID, :950907, :960024, :950008, :950010, :950011, :950018, :950019, :950012, :950910, :950911, :950117, :950118, :950119, :950120, :981133, :950009, :950003, :950000, :950005, :950002, :950006, :959151, :958976, :958977);";
  sqlite3_stmt *stmt_insert_crs_generic_attack;
  prepared_statements_map.insert({"sql_insert_crs_generic_attack",make_tuple(sql_insert_crs_generic_attack, &stmt_insert_crs_generic_attack)});

  // ************************* SQL INJECTION ATTACK **************************
  const char *sql_insert_crs_sql_injection = "INSERT INTO CRS_SQL_INJECTION (UNIQUE_ID, '981231', '981260', '981318', '981319', '950901', '981320', '981300', '981301', '981302', '981303', '981304', '981305', '981306', '981307', '981308', '981309', '981310', '981311', '981312', '981313', '981314', '981315', '981316', '981317', '950007', '950001', '959070', '959071', '959072', '950908', '959073', '981172', '981173', '981272', '981244', '981255', '981257', '981248', '981277', '981250', '981241', '981252', '981256', '981245', '981276', '981254', '981270', '981240', '981249', '981253', '981242', '981246', '981251', '981247', '981243') VALUES (:UNIQUE_ID, :981231, :981260, :981318, :981319, :950901, :981320, :981300, :981301, :981302, :981303, :981304, :981305, :981306, :981307, :981308, :981309, :981310, :981311, :981312, :981313, :981314, :981315, :981316, :981317, :950007, :950001, :959070, :959071, :959072, :950908, :959073, :981172, :981173, :981272, :981244, :981255, :981257, :981248, :981277, :981250, :981241, :981252, :981256, :981245, :981276, :981254, :981270, :981240, :981249, :981253, :981242, :981246, :981251, :981247, :981243);";
  sqlite3_stmt *stmt_insert_crs_sql_injection;
  prepared_statements_map.insert({"sql_insert_crs_sql_injection",make_tuple(sql_insert_crs_sql_injection, &stmt_insert_crs_sql_injection)});
  
  // ************************* XSS ATTACK **************************
  const char *sql_insert_crs_xss_attack = "INSERT INTO CRS_XSS_ATTACK (UNIQUE_ID, '973336', '973337', '973338', '981136', '981018', '958016', '958414', '958032', '958026', '958027', '958054', '958418', '958034', '958019', '958013', '958408', '958012', '958423', '958002', '958017', '958007', '958047', '958410', '958415', '958022', '958405', '958419', '958028', '958057', '958031', '958006', '958033', '958038', '958409', '958001', '958005', '958404', '958023', '958010', '958411', '958422', '958036', '958000', '958018', '958406', '958040', '958052', '958037', '958049', '958030', '958041', '958416', '958024', '958059', '958417', '958020', '958045', '958004', '958421', '958009', '958025', '958413', '958051', '958420', '958407', '958056', '958011', '958412', '958008', '958046', '958039', '958003', '973300', '973301', '973302', '973303', '973304', '973305', '973306', '973307', '973308', '973309', '973310', '973311', '973312', '973313', '973314', '973331', '973315', '973330', '973327', '973326', '973346', '973345', '973324', '973323', '973322', '973348', '973321', '973320', '973318', '973317', '973347', '973335', '973334', '973333', '973344', '973332', '973329', '973328', '973316', '973325', '973319') VALUES (:UNIQUE_ID, :973336, :973337, :973338, :981136, :981018, :958016, :958414, :958032, :958026, :958027, :958054, :958418, :958034, :958019, :958013, :958408, :958012, :958423, :958002, :958017, :958007, :958047, :958410, :958415, :958022, :958405, :958419, :958028, :958057, :958031, :958006, :958033, :958038, :958409, :958001, :958005, :958404, :958023, :958010, :958411, :958422, :958036, :958000, :958018, :958406, :958040, :958052, :958037, :958049, :958030, :958041, :958416, :958024, :958059, :958417, :958020, :958045, :958004, :958421, :958009, :958025, :958413, :958051, :958420, :958407, :958056, :958011, :958412, :958008, :958046, :958039, :958003, :973300, :973301, :973302, :973303, :973304, :973305, :973306, :973307, :973308, :973309, :973310, :973311, :973312, :973313, :973314, :973331, :973315, :973330, :973327, :973326, :973346, :973345, :973324, :973323, :973322, :973348, :973321, :973320, :973318, :973317, :973347, :973335, :973334, :973333, :973344, :973332, :973329, :973328, :973316, :973325, :973319);";
  sqlite3_stmt *stmt_insert_crs_xss_attack;
  prepared_statements_map.insert({"sql_insert_crs_xss_attack",make_tuple(sql_insert_crs_xss_attack, &stmt_insert_crs_xss_attack)});

  // ************************* TIGHT SECURITY **************************
  const char *sql_insert_crs_tight_security = "INSERT INTO CRS_TIGHT_SECURITY (UNIQUE_ID, '950103') VALUES (:UNIQUE_ID, :950103);";
  sqlite3_stmt *stmt_insert_crs_tight_security;
  prepared_statements_map.insert({"sql_insert_crs_tight_security",make_tuple(sql_insert_crs_tight_security, &stmt_insert_crs_tight_security)});

  // ************************* TROJANS **************************
  const char *sql_insert_crs_trojans = "INSERT INTO CRS_TROJANS (UNIQUE_ID, '950110', '950921', '950922') VALUES (:UNIQUE_ID, :950110, :950921, :950922);";
  sqlite3_stmt *stmt_insert_crs_trojans;
  prepared_statements_map.insert({"sql_insert_crs_trojans",make_tuple(sql_insert_crs_trojans, &stmt_insert_crs_trojans)});

  // ************************* COMMON EXCEPTIONS **************************
  const char *sql_insert_crs_common_exceptions = "INSERT INTO CRS_COMMON_EXCEPTIONS (UNIQUE_ID, '981020', '981021', '981022') VALUES (:UNIQUE_ID, :981020, :981021, :981022);";
  sqlite3_stmt *stmt_insert_crs_common_exceptions;
  prepared_statements_map.insert({"sql_insert_crs_common_exceptions",make_tuple(sql_insert_crs_common_exceptions, &stmt_insert_crs_common_exceptions)});

  // ************************* LOCAL EXCEPTIONS **************************
  const char *sql_insert_crs_local_exceptions = "INSERT INTO CRS_LOCAL_EXCEPTIONS (UNIQUE_ID) VALUES (:UNIQUE_ID);";
  sqlite3_stmt *stmt_insert_crs_local_exceptions;
  prepared_statements_map.insert({"sql_insert_crs_local_exceptions",make_tuple(sql_insert_crs_local_exceptions, &stmt_insert_crs_local_exceptions)});

  // ************************* INBOUND BLOCKING **************************
  const char *sql_insert_crs_inbound_blocking = "INSERT INTO CRS_INBOUND_BLOCKING (UNIQUE_ID, '981175', '981176') VALUES (:UNIQUE_ID, :981175, :981176);";
  sqlite3_stmt *stmt_insert_crs_inbound_blocking;
  prepared_statements_map.insert({"sql_insert_crs_inbound_blocking",make_tuple(sql_insert_crs_inbound_blocking, &stmt_insert_crs_inbound_blocking)});

  // ************************* OUTBOUND **************************
  const char *sql_insert_crs_outbound = "INSERT INTO CRS_OUTBOUND (UNIQUE_ID, '970007', '970008', '970009', '970010', '970012', '970903', '970016', '970018', '970901', '970021', '970011', '981177', '981000', '981001', '981003', '981004', '981005', '981006', '981007', '981178', '970014', '970015', '970902', '970002', '970003', '970004', '970904', '970013') VALUES (:UNIQUE_ID, :970007, :970008, :970009, :970010, :970012, :970903, :970016, :970018, :970901, :970021, :970011, :981177, :981000, :981001, :981003, :981004, :981005, :981006, :981007, :981178, :970014, :970015, :970902, :970002, :970003, :970004, :970904, :970013);";
  sqlite3_stmt *stmt_insert_crs_outbound;
  prepared_statements_map.insert({"sql_insert_crs_outbound",make_tuple(sql_insert_crs_outbound, &stmt_insert_crs_outbound)});

  // ************************* OUTBOUND BLOCKING **************************
  const char *sql_insert_crs_outbound_blocking = "INSERT INTO CRS_OUTBOUND_BLOCKING (UNIQUE_ID, '981200') VALUES (:UNIQUE_ID, :981200);";
  sqlite3_stmt *stmt_insert_crs_outbound_blocking;
  prepared_statements_map.insert({"sql_insert_crs_outbound_blocking",make_tuple(sql_insert_crs_outbound_blocking, &stmt_insert_crs_outbound_blocking)});

  // ************************* CORRELATION **************************
  const char *sql_insert_crs_correlation = "INSERT INTO CRS_CORRELATION (UNIQUE_ID, '981201', '981202', '981203', '981204', '981205') VALUES (:UNIQUE_ID, :981201, :981202, :981203, :981204, :981205);";
  sqlite3_stmt *stmt_insert_crs_correlation;
  prepared_statements_map.insert({"sql_insert_crs_correlation",make_tuple(sql_insert_crs_correlation, &stmt_insert_crs_correlation)});

  
    
  // ************************* BRUTE FORCE **************************
  const char *sql_insert_crs_brute_force = "INSERT INTO CRS_BRUTE_FORCE (UNIQUE_ID, '981036', '981037', '981038', '981039', '981040', '981041', '981042', '981043') VALUES (:UNIQUE_ID, :981036, :981037, :981038, :981039, :981040, :981041, :981042, :981043);";
  sqlite3_stmt *stmt_insert_crs_brute_force;
  prepared_statements_map.insert({"sql_insert_crs_brute_force",make_tuple(sql_insert_crs_brute_force, &stmt_insert_crs_brute_force)});

  // ************************* DOS PROTECTION **************************
  const char *sql_insert_crs_dos = "INSERT INTO CRS_DOS (UNIQUE_ID, '981044', '981045', '981046', '981047', '981048', '981049') VALUES (:UNIQUE_ID, :981044, :981045, :981046, :981047, :981048, :981049);";
  sqlite3_stmt *stmt_insert_crs_dos;
  prepared_statements_map.insert({"sql_insert_crs_dos",make_tuple(sql_insert_crs_dos, &stmt_insert_crs_dos)});

  // ************************* PROXY ABUSE **************************
  const char *sql_insert_crs_proxy_abuse = "INSERT INTO CRS_PROXY_ABUSE (UNIQUE_ID, '981050') VALUES (:UNIQUE_ID, :981050);";
  sqlite3_stmt *stmt_insert_crs_proxy_abuse;
  prepared_statements_map.insert({"sql_insert_crs_proxy_abuse",make_tuple(sql_insert_crs_proxy_abuse, &stmt_insert_crs_proxy_abuse)});

  // ************************* SLOW DOS PROTECTION **************************
  const char *sql_insert_crs_slow_dos = "INSERT INTO CRS_SLOW_DOS (UNIQUE_ID, '981051', '981052') VALUES (:UNIQUE_ID, :981051, :981052);";
  sqlite3_stmt *stmt_insert_crs_slow_dos;
  prepared_statements_map.insert({"sql_insert_crs_slow_dos",make_tuple(sql_insert_crs_slow_dos, &stmt_insert_crs_slow_dos)});

  // ************************* CC TRACK PAN **************************
  const char *sql_insert_crs_cc_track_pan = "INSERT INTO CRS_CC_TRACK_PAN (UNIQUE_ID, '920021', '920022', '920023') VALUES (:UNIQUE_ID, :920021, :920022, :920023);";
  sqlite3_stmt *stmt_insert_crs_cc_track_pan;
  prepared_statements_map.insert({"sql_insert_crs_cc_track_pan",make_tuple(sql_insert_crs_cc_track_pan, &stmt_insert_crs_cc_track_pan)});

  // ************************* APPSENSOR DETECTION POINT **************************
  const char *sql_insert_crs_appsensor = "INSERT INTO CRS_APPSENSOR (UNIQUE_ID, '981082', '981083', '981084', '981085', '981086', '981087', '981088', '981089', '981090', '981091', '981092', '981093', '981094', '981095', '981096', '981097', '981103', '981104', '981110', '981105', '981098', '981099', '981100', '981101', '981102', '981131', '981132') VALUES (:UNIQUE_ID, :981082, :981083, :981084, :981085, :981086, :981087, :981088, :981089, :981090, :981091, :981092, :981093, :981094, :981095, :981096, :981097, :981103, :981104, :981110, :981105, :981098, :981099, :981100, :981101, :981102, :981131, :981132);";
  sqlite3_stmt *stmt_insert_crs_appsensor;
  prepared_statements_map.insert({"sql_insert_crs_appsensor",make_tuple(sql_insert_crs_appsensor, &stmt_insert_crs_appsensor)});

  // ************************* HTTP PARAMETER POLLUTION **************************
  const char *sql_insert_crs_http_parameter_pollution = "INSERT INTO CRS_HTTP_PARAMETER_POLLUTION (UNIQUE_ID, '900032') VALUES (:UNIQUE_ID, :900032);";
  sqlite3_stmt *stmt_insert_crs_http_parameter_pollution;
  prepared_statements_map.insert({"sql_insert_crs_http_parameter_pollution",make_tuple(sql_insert_crs_http_parameter_pollution, &stmt_insert_crs_http_parameter_pollution)});

  // ************************* CSP ENFORCEMENT **************************
  const char *sql_insert_crs_csp_enforcement = "INSERT INTO CRS_CSP_ENFORCEMENT (UNIQUE_ID, '981142', '960001', '960002', '960003') VALUES (:UNIQUE_ID, :981142, :960001, :960002, :960003);";
  sqlite3_stmt *stmt_insert_crs_csp_enforcement;
  prepared_statements_map.insert({"sql_insert_crs_csp_enforcement",make_tuple(sql_insert_crs_csp_enforcement, &stmt_insert_crs_csp_enforcement)});

  // ************************* SCANNER INTEGRATION **************************
  const char *sql_insert_crs_scanner_integration = "INSERT INTO CRS_SCANNER_INTEGRATION (UNIQUE_ID, '900030', '900031', '999003', '999004') VALUES (:UNIQUE_ID, :900030, :900031, :999003, :999004);";
  sqlite3_stmt *stmt_insert_crs_scanner_integration;
  prepared_statements_map.insert({"sql_insert_crs_scanner_integration",make_tuple(sql_insert_crs_scanner_integration, &stmt_insert_crs_scanner_integration)});

  // ************************* BAYES ANALYSIS **************************
  const char *sql_insert_crs_bayes_analysis = "INSERT INTO CRS_BAYES_ANALYSIS (UNIQUE_ID, '900033', '900034', '900035') VALUES (:UNIQUE_ID, :900033, :900034, :900035);";
  sqlite3_stmt *stmt_insert_crs_bayes_analysis;
  prepared_statements_map.insert({"sql_insert_crs_bayes_analysis",make_tuple(sql_insert_crs_bayes_analysis, &stmt_insert_crs_bayes_analysis)});

  // ************************* RESPONSE PROFILING **************************
  const char *sql_insert_crs_response_profiling = "INSERT INTO CRS_RESPONSE_PROFILING (UNIQUE_ID, '981187', '981189', '981190', '981191', '981192', '981193', '981194', '981195', '981196', '981197') VALUES (:UNIQUE_ID, :981187, :981188, :981190, :981191, :981192, :981193, :981194, :981195, :981196, :981197);";
  sqlite3_stmt *stmt_insert_crs_response_profiling;
  prepared_statements_map.insert({"sql_insert_crs_response_profiling",make_tuple(sql_insert_crs_response_profiling, &stmt_insert_crs_response_profiling)});

  // ************************* PVI CHECKS **************************
  const char *sql_insert_crs_pvi_checks = "INSERT INTO CRS_PVI_CHECKS (UNIQUE_ID, '981198', '981199') VALUES (:UNIQUE_ID, :981198, :981199);";
  sqlite3_stmt *stmt_insert_crs_pvi_checks;
  prepared_statements_map.insert({"sql_insert_crs_pvi_checks",make_tuple(sql_insert_crs_pvi_checks, &stmt_insert_crs_pvi_checks)});

  // ************************* IP FORENSICS **************************
  const char *sql_insert_crs_ip_forensics = "INSERT INTO CRS_IP_FORENSICS (UNIQUE_ID, '900036', '900037', '900039') VALUES (:UNIQUE_ID, :900036, :900037, :900039);";
  sqlite3_stmt *stmt_insert_crs_ip_forensics;
  prepared_statements_map.insert({"sql_insert_crs_ip_forensics",make_tuple(sql_insert_crs_ip_forensics, &stmt_insert_crs_ip_forensics)});



  // ************************* IGNORE STATIC **************************
  const char *sql_insert_crs_ignore_static = "INSERT INTO CRS_IGNORE_STATIC (UNIQUE_ID, '900040', '900041', '900042', '900043', '999005', '999006') VALUES (:UNIQUE_ID, :900040, :900041, :900042, :900043, :999005, :999006);";
  sqlite3_stmt *stmt_insert_crs_ignore_static;
  prepared_statements_map.insert({"sql_insert_crs_ignore_static",make_tuple(sql_insert_crs_ignore_static, &stmt_insert_crs_ignore_static)});

  // ************************* AV SCANNING **************************
  const char *sql_insert_crs_av_scanning = "INSERT INTO CRS_AV_SCANNING (UNIQUE_ID, '981033', '981034', '981035', '950115') VALUES (:UNIQUE_ID, :981033, :981034, :981035, :950115);";
  sqlite3_stmt *stmt_insert_crs_av_scanning;
  prepared_statements_map.insert({"sql_insert_crs_av_scanning",make_tuple(sql_insert_crs_av_scanning, &stmt_insert_crs_av_scanning)});

  // ************************* XML ENABLER **************************
  const char *sql_insert_crs_xml_enabler = "INSERT INTO CRS_XML_ENABLER (UNIQUE_ID, '981053') VALUES (:UNIQUE_ID, :981053);";
  sqlite3_stmt *stmt_insert_crs_xml_enabler;
  prepared_statements_map.insert({"sql_insert_crs_xml_enabler",make_tuple(sql_insert_crs_xml_enabler, &stmt_insert_crs_xml_enabler)});

  // ************************* SESSION HIJACKING **************************
  const char *sql_insert_crs_session_hijacking = "INSERT INTO CRS_SESSION_HIJACKING (UNIQUE_ID, '981054', '981055', '981056', '981057', '981058', '981059', '981060', '981061', '981062', '981063', '981064') VALUES (:UNIQUE_ID, :981054, :981055, :981056, :981057, :981058, :981059, :981060, :981061, :981062, :981063, :981064);";
  sqlite3_stmt *stmt_insert_crs_session_hijacking;
  prepared_statements_map.insert({"sql_insert_crs_session_hijacking",make_tuple(sql_insert_crs_session_hijacking, &stmt_insert_crs_session_hijacking)});

  // ************************* USERNAME TRACKING **************************
  const char *sql_insert_crs_username_tracking = "INSERT INTO CRS_USERNAME_TRACKING (UNIQUE_ID, '981075', '981076', '981077') VALUES (:UNIQUE_ID, :981075, :981076, :981077);";
  sqlite3_stmt *stmt_insert_crs_username_tracking;
  prepared_statements_map.insert({"sql_insert_crs_username_tracking",make_tuple(sql_insert_crs_username_tracking, &stmt_insert_crs_username_tracking)});

  // ************************* CC KNOWN **************************
  const char *sql_insert_crs_cc_known = "INSERT INTO CRS_CC_KNOWN (UNIQUE_ID, '981078', '981079', '920005', '920007', '920009', '920011', '920013', '920015', '920017', '981080', '920020', '920006', '920008', '920010', '920012', '920014', '920016', '920018') VALUES (:UNIQUE_ID, :981078, :981079, :920005, :920007, :920009, :920011, :920013, :920015, :920017, :981080, :920020, :920006, :920008, :920010, :920012, :920014, :920016, :920018);";
  sqlite3_stmt *stmt_insert_crs_cc_known;
  prepared_statements_map.insert({"sql_insert_crs_cc_known",make_tuple(sql_insert_crs_cc_known, &stmt_insert_crs_cc_known)});

  // ************************* COMMENT SPAM **************************
  const char *sql_insert_crs_comment_spam = "INSERT INTO CRS_COMMENT_SPAM (UNIQUE_ID, '981137', '981138', '981139', '981140', '958297', '999010', '999011', '950923', '950020') VALUES (:UNIQUE_ID, :981137, :981138, :981139, :981140, :958297, :999010, :999011, :950923, :950020);";
  sqlite3_stmt *stmt_insert_crs_comment_spam;
  prepared_statements_map.insert({"sql_insert_crs_comment_spam",make_tuple(sql_insert_crs_comment_spam, &stmt_insert_crs_comment_spam)});

  // ************************* CSRF PROTECTION **************************
  const char *sql_insert_crs_csrf_protection = "INSERT INTO CRS_CSRF_PROTECTION (UNIQUE_ID, '981143', '981144', '981145') VALUES (:UNIQUE_ID, :981143, :981144, :981145);";
  sqlite3_stmt *stmt_insert_crs_csrf_protection;
  prepared_statements_map.insert({"sql_insert_crs_csrf_protection",make_tuple(sql_insert_crs_csrf_protection, &stmt_insert_crs_csrf_protection)});

  // ************************* SKIP OUTBOUND CHECKS **************************
  const char *sql_insert_crs_skip_outbound_checks = "INSERT INTO CRS_SKIP_OUTBOUND_CHECKS (UNIQUE_ID, '999008') VALUES (:UNIQUE_ID, :999008);";
  sqlite3_stmt *stmt_insert_crs_skip_outbound_checks;
  prepared_statements_map.insert({"sql_insert_crs_skip_outbound_checks",make_tuple(sql_insert_crs_skip_outbound_checks, &stmt_insert_crs_skip_outbound_checks)});

  // ************************* HEADER TAGGING **************************
  const char *sql_insert_crs_header_tagging = "INSERT INTO CRS_HEADER_TAGGING (UNIQUE_ID, '900044', '900045') VALUES (:UNIQUE_ID, :900044, :900045);";
  sqlite3_stmt *stmt_insert_crs_header_tagging;
  prepared_statements_map.insert({"sql_insert_crs_header_tagging",make_tuple(sql_insert_crs_header_tagging, &stmt_insert_crs_header_tagging)});

  // ************************* APPLICATION DEFECTS **************************
  const char *sql_insert_crs_application_defects = "INSERT INTO CRS_APPLICATION_DEFECTS (UNIQUE_ID, '981219', '981220', '981221', '981222', '981223', '981224', '981238', '981235', '981184', '981236', '981185', '981239', '900046', '981400', '981401', '981402', '981403', '981404', '981405', '981406', '981407', '900048', '981180', '981181', '981182') VALUES (:UNIQUE_ID, :981219, :981220, :981221, :981222, :981223, :981224, :981238, :981235, :981184, :981236, :981185, :981239, :900046, :981400, :981401, :981402, :981403, :981404, :981405, :981406, :981407, :900048, :981180, :981181, :981182);";
  sqlite3_stmt *stmt_insert_crs_application_defects;
  prepared_statements_map.insert({"sql_insert_crs_application_defects",make_tuple(sql_insert_crs_application_defects, &stmt_insert_crs_application_defects)});
  
  // ************************* MARKETING **************************
  const char *sql_insert_crs_marketing = "INSERT INTO CRS_MARKETING (UNIQUE_ID, '910008', '910007', '910006') VALUES (:UNIQUE_ID, :910008, :910007, :910006);";
  sqlite3_stmt *stmt_insert_crs_marketing;
  prepared_statements_map.insert({"sql_insert_crs_marketing",make_tuple(sql_insert_crs_marketing, &stmt_insert_crs_marketing)});

  
  
  
  //************************************************************************************************
  
  // start a transaction - all of the statements from here until END TRANSACTION will be queued and executed at once,
  // reducing the overhead associated with committing to the database multiple times (massive speed improvement)
  sqlite3_exec(db, "BEGIN TRANSACTION", 0, 0, 0);

  
  
  
  
    
  
  // variables for sql compilation
  const char *pzTail; // pointer to uncompiled portion of statement
  
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
  

  
  
  // integers for rule ID counting
  int CRS_SEPARATE_RULES_MATCHED, CRS_PROTOCOL_VIOLATION, CRS_PROTOCOL_ANOMALY, CRS_REQUEST_LIMIT, CRS_HTTP_POLICY, CRS_BAD_ROBOT, CRS_GENERIC_ATTACK, CRS_SQL_INJECTION, CRS_XSS_ATTACK, CRS_TIGHT_SECURITY, CRS_TROJANS, CRS_COMMON_EXCEPTIONS, CRS_LOCAL_EXCEPTIONS, CRS_INBOUND_BLOCKING, CRS_OUTBOUND, CRS_OUTBOUND_BLOCKING, CRS_CORRELATION, CRS_BRUTE_FORCE, CRS_DOS, CRS_PROXY_ABUSE, CRS_SLOW_DOS, CRS_CC_TRACK_PAN, CRS_APPSENSOR, CRS_HTTP_PARAMETER_POLLUTION, CRS_CSP_ENFORCEMENT, CRS_SCANNER_INTEGRATION, CRS_BAYES_ANALYSIS, CRS_RESPONSE_PROFILING, CRS_PVI_CHECKS, CRS_IP_FORENSICS, CRS_IGNORE_STATIC, CRS_AVS_TRAFFIC, CRS_XML_ENABLER, CRS_AUTHENTICATION_TRACKING, CRS_SESSION_HIJACKING, CRS_USERNAME_TRACKING, CRS_CC_KNOWN, CRS_COMMENT_SPAM, CRS_CSRF_PROTECTION, CRS_AV_SCANNING, CRS_SKIP_OUTBOUND_CHECKS, CRS_HEADER_TAGGING, CRS_APPLICATION_DEFECTS, CRS_MARKETING;
  
  
  map <string, int*> countersMap = {	{"CRS_SEPARATE_RULES_MATCHED",		&CRS_SEPARATE_RULES_MATCHED},
					{"CRS_PROTOCOL_VIOLATION",		&CRS_PROTOCOL_VIOLATION	},
					{"CRS_PROTOCOL_ANOMALY",		&CRS_PROTOCOL_ANOMALY},
					{"CRS_REQUEST_LIMIT",			&CRS_REQUEST_LIMIT},
					{"CRS_HTTP_POLICY",			&CRS_HTTP_POLICY},
					{"CRS_BAD_ROBOT",			&CRS_BAD_ROBOT},
					{"CRS_GENERIC_ATTACK",			&CRS_GENERIC_ATTACK},
					{"CRS_SQL_INJECTION",			&CRS_SQL_INJECTION},
					{"CRS_XSS_ATTACK",			&CRS_XSS_ATTACK},
					{"CRS_TIGHT_SECURITY",			&CRS_TIGHT_SECURITY},
					{"CRS_TROJANS",				&CRS_TROJANS},
					{"CRS_COMMON_EXCEPTIONS",		&CRS_COMMON_EXCEPTIONS},
					{"CRS_LOCAL_EXCEPTIONS",		&CRS_LOCAL_EXCEPTIONS},
					{"CRS_INBOUND_BLOCKING",		&CRS_INBOUND_BLOCKING},
					{"CRS_OUTBOUND",			&CRS_OUTBOUND},
					{"CRS_OUTBOUND_BLOCKING",		&CRS_OUTBOUND_BLOCKING},
					{"CRS_CORRELATION",			&CRS_CORRELATION},
					{"CRS_BRUTE_FORCE",			&CRS_BRUTE_FORCE},
					{"CRS_DOS",				&CRS_DOS},
					{"CRS_PROXY_ABUSE",			&CRS_PROXY_ABUSE},
					{"CRS_SLOW_DOS",			&CRS_SLOW_DOS},
					{"CRS_CC_TRACK_PAN",			&CRS_CC_TRACK_PAN},
					{"CRS_APPSENSOR",			&CRS_APPSENSOR},
					{"CRS_HTTP_PARAMETER_POLLUTION",	&CRS_HTTP_PARAMETER_POLLUTION},
					{"CRS_CSP_ENFORCEMENT",			&CRS_CSP_ENFORCEMENT},
					{"CRS_SCANNER_INTEGRATION",		&CRS_SCANNER_INTEGRATION},
					{"CRS_BAYES_ANALYSIS",			&CRS_BAYES_ANALYSIS},
					{"CRS_RESPONSE_PROFILING",		&CRS_RESPONSE_PROFILING},
					{"CRS_PVI_CHECKS",			&CRS_PVI_CHECKS},
					{"CRS_IP_FORENSICS",			&CRS_IP_FORENSICS},
					{"CRS_IGNORE_STATIC",			&CRS_IGNORE_STATIC},
					{"CRS_AVS_TRAFFIC",			&CRS_AVS_TRAFFIC},
					{"CRS_XML_ENABLER",			&CRS_XML_ENABLER},
					{"CRS_AUTHENTICATION_TRACKING",		&CRS_AUTHENTICATION_TRACKING},
					{"CRS_SESSION_HIJACKING",		&CRS_SESSION_HIJACKING},
					{"CRS_USERNAME_TRACKING",		&CRS_USERNAME_TRACKING},
					{"CRS_CC_KNOWN",			&CRS_CC_KNOWN},
					{"CRS_COMMENT_SPAM",			&CRS_COMMENT_SPAM},
					{"CRS_CSRF_PROTECTION",			&CRS_CSRF_PROTECTION},
					{"CRS_AV_SCANNING",			&CRS_AV_SCANNING},
					{"CRS_SKIP_OUTBOUND_CHECKS",		&CRS_SKIP_OUTBOUND_CHECKS},
					{"CRS_HEADER_TAGGING",			&CRS_HEADER_TAGGING},
					{"CRS_APPLICATION_DEFECTS",		&CRS_APPLICATION_DEFECTS},
					{"CRS_MARKETING",			&CRS_MARKETING},};
  
  
  if(debug) {cout << "Setting counters to 0" << endl;}
  for (const auto &counter : countersMap) {
    *(counter.second) = 0;
  }
  if(debug) {cout << "...done." << endl;}
  
  
  
  

  map <string, tuple<sqlite3_stmt **,int *>> ruleIDmap = {	{"960911",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"981227",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"960000",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"960912",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"960914",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"960915",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"960016",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"960011",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"960012",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"960902",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"960022",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"960020",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"958291",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"958230",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"958231",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"958295",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"950107",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"950109",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"950108",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"950801",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"950116",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"960014",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"960901",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"960018",	make_tuple(&stmt_insert_crs_protocol_violation,		&CRS_PROTOCOL_VIOLATION		)	},
								{"960008",	make_tuple(&stmt_insert_crs_protocol_anomaly,		&CRS_PROTOCOL_ANOMALY		)	},
								{"960007",	make_tuple(&stmt_insert_crs_protocol_anomaly,		&CRS_PROTOCOL_ANOMALY		)	},
								{"960015",	make_tuple(&stmt_insert_crs_protocol_anomaly,		&CRS_PROTOCOL_ANOMALY		)	},
								{"960021",	make_tuple(&stmt_insert_crs_protocol_anomaly,		&CRS_PROTOCOL_ANOMALY		)	},
								{"960009",	make_tuple(&stmt_insert_crs_protocol_anomaly,		&CRS_PROTOCOL_ANOMALY		)	},
								{"960006",	make_tuple(&stmt_insert_crs_protocol_anomaly,		&CRS_PROTOCOL_ANOMALY		)	},
								{"960904",	make_tuple(&stmt_insert_crs_protocol_anomaly,		&CRS_PROTOCOL_ANOMALY		)	},
								{"960017",	make_tuple(&stmt_insert_crs_protocol_anomaly,		&CRS_PROTOCOL_ANOMALY		)	},
								{"960209",	make_tuple(&stmt_insert_crs_request_limit,		&CRS_REQUEST_LIMIT		)	},
								{"960208",	make_tuple(&stmt_insert_crs_request_limit,		&CRS_REQUEST_LIMIT		)	},
								{"960335",	make_tuple(&stmt_insert_crs_request_limit,		&CRS_REQUEST_LIMIT		)	},
								{"960341",	make_tuple(&stmt_insert_crs_request_limit,		&CRS_REQUEST_LIMIT		)	},
								{"960342",	make_tuple(&stmt_insert_crs_request_limit,		&CRS_REQUEST_LIMIT		)	},
								{"960343",	make_tuple(&stmt_insert_crs_request_limit,		&CRS_REQUEST_LIMIT		)	},
								{"960032",	make_tuple(&stmt_insert_crs_http_policy,		&CRS_HTTP_POLICY		)	},
								{"960010",	make_tuple(&stmt_insert_crs_http_policy,		&CRS_HTTP_POLICY		)	},
								{"960034",	make_tuple(&stmt_insert_crs_http_policy,		&CRS_HTTP_POLICY		)	},
								{"960035",	make_tuple(&stmt_insert_crs_http_policy,		&CRS_HTTP_POLICY		)	},
								{"960038",	make_tuple(&stmt_insert_crs_http_policy,		&CRS_HTTP_POLICY		)	},
								{"990002",	make_tuple(&stmt_insert_crs_bad_robot,			&CRS_BAD_ROBOT			)	},
								{"990901",	make_tuple(&stmt_insert_crs_bad_robot,			&CRS_BAD_ROBOT			)	},
								{"990902",	make_tuple(&stmt_insert_crs_bad_robot,			&CRS_BAD_ROBOT			)	},
								{"990012",	make_tuple(&stmt_insert_crs_bad_robot,			&CRS_BAD_ROBOT			)	},
								{"950907",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"960024",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950008",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950010",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950011",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950018",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950019",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950012",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950910",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950911",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950117",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950118",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950119",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950120",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"981133",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950009",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950003",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950000",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950005",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950002",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"950006",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"959151",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"958976",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"958977",	make_tuple(&stmt_insert_crs_generic_attack,		&CRS_GENERIC_ATTACK		)	},
								{"981231",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981260",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981318",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981319",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"950901",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981320",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981300",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981301",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981302",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981303",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981304",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981305",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981306",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981307",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981308",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981309",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981310",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981311",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981312",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981313",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981314",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981315",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981316",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981317",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"950007",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"950001",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"959070",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"959071",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"959072",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"950908",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"959073",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981172",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981173",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981272",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981244",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981255",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981257",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981248",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981277",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981250",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981241",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981252",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981256",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981245",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981276",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981254",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981270",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981240",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981249",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981253",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981242",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981246",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981251",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981247",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"981243",	make_tuple(&stmt_insert_crs_sql_injection,		&CRS_SQL_INJECTION		)	},
								{"973336",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973337",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973338",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"981136",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"981018",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958016",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958414",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958032",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958026",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958027",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958054",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958418",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958034",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958019",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958013",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958408",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958012",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958423",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958002",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958017",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958007",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958047",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958410",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958415",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958022",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958405",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958419",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958028",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958057",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958031",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958006",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958033",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958038",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958409",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958001",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958005",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958404",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958023",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958010",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958411",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958422",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958036",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958000",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958018",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958406",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958040",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958052",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958037",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958049",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958030",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958041",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958416",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958024",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958059",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958417",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958020",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958045",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958004",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958421",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958009",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958025",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958413",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958051",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958420",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958407",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958056",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958011",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958412",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958008",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958046",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958039",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"958003",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973300",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973301",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973302",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973303",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973304",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973305",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973306",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973307",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973308",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973309",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973310",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973311",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973312",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973313",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973314",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973331",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973315",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973330",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973327",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973326",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973346",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973345",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973324",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973323",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973322",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973348",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973321",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973320",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973318",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973317",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973347",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973335",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973334",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973333",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973344",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973332",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973329",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973328",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973316",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973325",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"973319",	make_tuple(&stmt_insert_crs_xss_attack,			&CRS_XSS_ATTACK			)	},
								{"950103",	make_tuple(&stmt_insert_crs_tight_security,		&CRS_TIGHT_SECURITY		)	},
								{"950110",	make_tuple(&stmt_insert_crs_trojans,			&CRS_TROJANS			)	},
								{"950921",	make_tuple(&stmt_insert_crs_trojans,			&CRS_TROJANS			)	},
								{"950922",	make_tuple(&stmt_insert_crs_trojans,			&CRS_TROJANS			)	},
								{"981020",	make_tuple(&stmt_insert_crs_common_exceptions,		&CRS_COMMON_EXCEPTIONS		)	},
								{"981021",	make_tuple(&stmt_insert_crs_common_exceptions,		&CRS_COMMON_EXCEPTIONS		)	},
								{"981022",	make_tuple(&stmt_insert_crs_common_exceptions,		&CRS_COMMON_EXCEPTIONS		)	},
								{"981175",	make_tuple(&stmt_insert_crs_inbound_blocking,		&CRS_INBOUND_BLOCKING		)	},
								{"981176",	make_tuple(&stmt_insert_crs_inbound_blocking,		&CRS_INBOUND_BLOCKING		)	},
								{"970007",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970008",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970009",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970010",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970012",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970903",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970016",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970018",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970901",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970021",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970011",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"981177",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"981000",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"981001",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"981003",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"981004",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"981005",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"981006",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"981007",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"981178",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970014",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970015",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970902",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970002",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970003",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970004",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970904",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"970013",	make_tuple(&stmt_insert_crs_outbound,			&CRS_OUTBOUND			)	},
								{"981200",	make_tuple(&stmt_insert_crs_outbound_blocking,		&CRS_OUTBOUND_BLOCKING		)	},
								{"981201",	make_tuple(&stmt_insert_crs_correlation,		&CRS_CORRELATION		)	},
								{"981202",	make_tuple(&stmt_insert_crs_correlation,		&CRS_CORRELATION		)	},
								{"981203",	make_tuple(&stmt_insert_crs_correlation,		&CRS_CORRELATION		)	},
								{"981204",	make_tuple(&stmt_insert_crs_correlation,		&CRS_CORRELATION		)	},
								{"981205",	make_tuple(&stmt_insert_crs_correlation,		&CRS_CORRELATION		)	},
								{"981036",	make_tuple(&stmt_insert_crs_brute_force,		&CRS_BRUTE_FORCE		)	},
								{"981037",	make_tuple(&stmt_insert_crs_brute_force,		&CRS_BRUTE_FORCE		)	},
								{"981038",	make_tuple(&stmt_insert_crs_brute_force,		&CRS_BRUTE_FORCE		)	},
								{"981039",	make_tuple(&stmt_insert_crs_brute_force,		&CRS_BRUTE_FORCE		)	},
								{"981040",	make_tuple(&stmt_insert_crs_brute_force,		&CRS_BRUTE_FORCE		)	},
								{"981041",	make_tuple(&stmt_insert_crs_brute_force,		&CRS_BRUTE_FORCE		)	},
								{"981042",	make_tuple(&stmt_insert_crs_brute_force,		&CRS_BRUTE_FORCE		)	},
								{"981043",	make_tuple(&stmt_insert_crs_brute_force,		&CRS_BRUTE_FORCE		)	},
								{"981044",	make_tuple(&stmt_insert_crs_dos,			&CRS_DOS			)	},
								{"981045",	make_tuple(&stmt_insert_crs_dos,			&CRS_DOS			)	},
								{"981046",	make_tuple(&stmt_insert_crs_dos,			&CRS_DOS			)	},
								{"981047",	make_tuple(&stmt_insert_crs_dos,			&CRS_DOS			)	},
								{"981048",	make_tuple(&stmt_insert_crs_dos,			&CRS_DOS			)	},
								{"981049",	make_tuple(&stmt_insert_crs_dos,			&CRS_DOS			)	},
								{"981050",	make_tuple(&stmt_insert_crs_proxy_abuse,		&CRS_PROXY_ABUSE		)	},
								{"981051",	make_tuple(&stmt_insert_crs_slow_dos,			&CRS_SLOW_DOS			)	},
								{"981052",	make_tuple(&stmt_insert_crs_slow_dos,			&CRS_SLOW_DOS			)	},
								{"900030",	make_tuple(&stmt_insert_crs_scanner_integration,	&CRS_SCANNER_INTEGRATION	)	},
								{"900031",	make_tuple(&stmt_insert_crs_scanner_integration,	&CRS_SCANNER_INTEGRATION	)	},
								{"920021",	make_tuple(&stmt_insert_crs_cc_track_pan,		&CRS_CC_TRACK_PAN		)	},
								{"920022",	make_tuple(&stmt_insert_crs_cc_track_pan,		&CRS_CC_TRACK_PAN		)	},
								{"920023",	make_tuple(&stmt_insert_crs_cc_track_pan,		&CRS_CC_TRACK_PAN		)	},
								{"981082",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981083",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981084",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981085",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981086",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981087",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981088",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981089",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981090",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981091",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981092",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981093",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981094",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981095",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981096",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981097",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981103",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981104",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981110",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981105",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981098",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981099",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981100",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981101",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981102",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981131",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"981132",	make_tuple(&stmt_insert_crs_appsensor,			&CRS_APPSENSOR			)	},
								{"900032",	make_tuple(&stmt_insert_crs_http_parameter_pollution,	&CRS_HTTP_PARAMETER_POLLUTION	)	},
								{"981142",	make_tuple(&stmt_insert_crs_csp_enforcement,		&CRS_CSP_ENFORCEMENT		)	},
								{"960001",	make_tuple(&stmt_insert_crs_csp_enforcement,		&CRS_CSP_ENFORCEMENT		)	},
								{"960002",	make_tuple(&stmt_insert_crs_csp_enforcement,		&CRS_CSP_ENFORCEMENT		)	},
								{"960003",	make_tuple(&stmt_insert_crs_csp_enforcement,		&CRS_CSP_ENFORCEMENT		)	},
								{"999003",	make_tuple(&stmt_insert_crs_scanner_integration,	&CRS_SCANNER_INTEGRATION	)	},
								{"999004",	make_tuple(&stmt_insert_crs_scanner_integration,	&CRS_SCANNER_INTEGRATION	)	},
								{"900033",	make_tuple(&stmt_insert_crs_bayes_analysis,		&CRS_BAYES_ANALYSIS		)	},
								{"900034",	make_tuple(&stmt_insert_crs_bayes_analysis,		&CRS_BAYES_ANALYSIS		)	},
								{"900035",	make_tuple(&stmt_insert_crs_bayes_analysis,		&CRS_BAYES_ANALYSIS		)	},
								{"981187",	make_tuple(&stmt_insert_crs_response_profiling,		&CRS_RESPONSE_PROFILING		)	},
								{"981189",	make_tuple(&stmt_insert_crs_response_profiling,		&CRS_RESPONSE_PROFILING		)	},
								{"981190",	make_tuple(&stmt_insert_crs_response_profiling,		&CRS_RESPONSE_PROFILING		)	},
								{"981191",	make_tuple(&stmt_insert_crs_response_profiling,		&CRS_RESPONSE_PROFILING		)	},
								{"981192",	make_tuple(&stmt_insert_crs_response_profiling,		&CRS_RESPONSE_PROFILING		)	},
								{"981193",	make_tuple(&stmt_insert_crs_response_profiling,		&CRS_RESPONSE_PROFILING		)	},
								{"981194",	make_tuple(&stmt_insert_crs_response_profiling,		&CRS_RESPONSE_PROFILING		)	},
								{"981195",	make_tuple(&stmt_insert_crs_response_profiling,		&CRS_RESPONSE_PROFILING		)	},
								{"981196",	make_tuple(&stmt_insert_crs_response_profiling,		&CRS_RESPONSE_PROFILING		)	},
								{"981197",	make_tuple(&stmt_insert_crs_response_profiling,		&CRS_RESPONSE_PROFILING		)	},
								{"981198",	make_tuple(&stmt_insert_crs_pvi_checks,			&CRS_PVI_CHECKS			)	},
								{"981199",	make_tuple(&stmt_insert_crs_pvi_checks,			&CRS_PVI_CHECKS			)	},
								{"900036",	make_tuple(&stmt_insert_crs_ip_forensics,		&CRS_IP_FORENSICS		)	},
								{"900037",	make_tuple(&stmt_insert_crs_ip_forensics,		&CRS_IP_FORENSICS		)	},
								{"900039",	make_tuple(&stmt_insert_crs_ip_forensics,		&CRS_IP_FORENSICS		)	},
								{"900040",	make_tuple(&stmt_insert_crs_ignore_static,		&CRS_IGNORE_STATIC		)	},
								{"900041",	make_tuple(&stmt_insert_crs_ignore_static,		&CRS_IGNORE_STATIC		)	},
								{"900042",	make_tuple(&stmt_insert_crs_ignore_static,		&CRS_IGNORE_STATIC		)	},
								{"900043",	make_tuple(&stmt_insert_crs_ignore_static,		&CRS_IGNORE_STATIC		)	},
								{"999005",	make_tuple(&stmt_insert_crs_ignore_static,		&CRS_IGNORE_STATIC		)	},
								{"999006",	make_tuple(&stmt_insert_crs_ignore_static,		&CRS_IGNORE_STATIC		)	},
								{"981033",	make_tuple(&stmt_insert_crs_av_scanning,		&CRS_AV_SCANNING		)	},
								{"981034",	make_tuple(&stmt_insert_crs_av_scanning,		&CRS_AV_SCANNING		)	},
								{"981035",	make_tuple(&stmt_insert_crs_av_scanning,		&CRS_AV_SCANNING		)	},
								{"981053",	make_tuple(&stmt_insert_crs_xml_enabler,		&CRS_XML_ENABLER		)	},
								{"981054",	make_tuple(&stmt_insert_crs_session_hijacking,		&CRS_SESSION_HIJACKING		)	},
								{"981055",	make_tuple(&stmt_insert_crs_session_hijacking,		&CRS_SESSION_HIJACKING		)	},
								{"981056",	make_tuple(&stmt_insert_crs_session_hijacking,		&CRS_SESSION_HIJACKING		)	},
								{"981057",	make_tuple(&stmt_insert_crs_session_hijacking,		&CRS_SESSION_HIJACKING		)	},
								{"981058",	make_tuple(&stmt_insert_crs_session_hijacking,		&CRS_SESSION_HIJACKING		)	},
								{"981059",	make_tuple(&stmt_insert_crs_session_hijacking,		&CRS_SESSION_HIJACKING		)	},
								{"981060",	make_tuple(&stmt_insert_crs_session_hijacking,		&CRS_SESSION_HIJACKING		)	},
								{"981061",	make_tuple(&stmt_insert_crs_session_hijacking,		&CRS_SESSION_HIJACKING		)	},
								{"981062",	make_tuple(&stmt_insert_crs_session_hijacking,		&CRS_SESSION_HIJACKING		)	},
								{"981063",	make_tuple(&stmt_insert_crs_session_hijacking,		&CRS_SESSION_HIJACKING		)	},
								{"981064",	make_tuple(&stmt_insert_crs_session_hijacking,		&CRS_SESSION_HIJACKING		)	},
								{"981075",	make_tuple(&stmt_insert_crs_username_tracking,		&CRS_USERNAME_TRACKING		)	},
								{"981076",	make_tuple(&stmt_insert_crs_username_tracking,		&CRS_USERNAME_TRACKING		)	},
								{"981077",	make_tuple(&stmt_insert_crs_username_tracking,		&CRS_USERNAME_TRACKING		)	},
								{"981078",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"981079",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920005",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920007",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920009",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920011",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920013",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920015",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920017",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"981080",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920020",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920006",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920008",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920010",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920012",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920014",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920016",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"920018",	make_tuple(&stmt_insert_crs_cc_known,			&CRS_CC_KNOWN			)	},
								{"981137",	make_tuple(&stmt_insert_crs_comment_spam,		&CRS_COMMENT_SPAM		)	},
								{"981138",	make_tuple(&stmt_insert_crs_comment_spam,		&CRS_COMMENT_SPAM		)	},
								{"981139",	make_tuple(&stmt_insert_crs_comment_spam,		&CRS_COMMENT_SPAM		)	},
								{"981140",	make_tuple(&stmt_insert_crs_comment_spam,		&CRS_COMMENT_SPAM		)	},
								{"958297",	make_tuple(&stmt_insert_crs_comment_spam,		&CRS_COMMENT_SPAM		)	},
								{"999010",	make_tuple(&stmt_insert_crs_comment_spam,		&CRS_COMMENT_SPAM		)	},
								{"999011",	make_tuple(&stmt_insert_crs_comment_spam,		&CRS_COMMENT_SPAM		)	},
								{"950923",	make_tuple(&stmt_insert_crs_comment_spam,		&CRS_COMMENT_SPAM		)	},
								{"950020",	make_tuple(&stmt_insert_crs_comment_spam,		&CRS_COMMENT_SPAM		)	},
								{"981143",	make_tuple(&stmt_insert_crs_csrf_protection,		&CRS_CSRF_PROTECTION		)	},
								{"981144",	make_tuple(&stmt_insert_crs_csrf_protection,		&CRS_CSRF_PROTECTION		)	},
								{"981145",	make_tuple(&stmt_insert_crs_csrf_protection,		&CRS_CSRF_PROTECTION		)	},
								{"950115",	make_tuple(&stmt_insert_crs_av_scanning,		&CRS_AV_SCANNING		)	},
								{"999008",	make_tuple(&stmt_insert_crs_skip_outbound_checks,	&CRS_SKIP_OUTBOUND_CHECKS	)	},
								{"900044",	make_tuple(&stmt_insert_crs_header_tagging,		&CRS_HEADER_TAGGING		)	},
								{"900045",	make_tuple(&stmt_insert_crs_header_tagging,		&CRS_HEADER_TAGGING		)	},
								{"981219",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981220",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981221",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981222",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981223",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981224",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981238",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981235",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981184",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981236",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981185",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981239",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"900046",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981400",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981401",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981402",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981403",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981404",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981405",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981406",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981407",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"900048",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981180",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981181",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"981182",	make_tuple(&stmt_insert_crs_application_defects,	&CRS_APPLICATION_DEFECTS	)	},
								{"910008",	make_tuple(&stmt_insert_crs_marketing,			&CRS_MARKETING			)	},
								{"910007",	make_tuple(&stmt_insert_crs_marketing,			&CRS_MARKETING			)	},
								{"910006",	make_tuple(&stmt_insert_crs_marketing,			&CRS_MARKETING			)	} };

     
  
  
  if (prepared_statement_errors != 0) {
    cerr << "Skipping logfile processing due to failed prepared statement creation" << endl;
  } else {
    // print a warning if there were errors creating a table and allow the user to choose to exit
    if (create_table_errors != 0) {
      if (force) {
	cout << "Creation of some tables failed, this may be because you are using an existing database" << endl;
	cout << "If the database was created with an old version of the software, you may get strange" << endl;
	cout << "SQLite errors where newer versions of tables have more columns or different column names" << endl;
	cout << "Force option was specified, continuing..." << endl;
      } else {
	cerr << "Creation of some tables failed, this may be because you are using an existing database" << endl;
	cerr << "If the database was created with an old version of the software, you may get strange" << endl;
	cerr << "SQLite errors where newer versions of tables have more columns or different column names" << endl;
	cout << "Do you wish to proceed? (y/n): \t \t";
	string ans;
	getline (cin, ans);
	while (ans != string("y") && ans != string("n")) {
	  cout << "Please type either 'y' or 'n'. Try again: \t ";
	  getline (cin, ans);
	}
	if (ans == string("n")) {
	  return 1;
	}
	cout << "OK. Continuing..." << endl;
      }
    }
    
    // create stream for reading logfile
    ifstream in(logfile);
    int line = 0;
    string linedata;
  

    
    // initialise strings for each value to be bound to the sqlite statement
    string UNIQUE_ID, HEADER, A, B, C, D, E, F, G, H, I, J, K; // "high level" strings
    // strings for matches in A
    string TIMESTAMP, SOURCE_IP, SOURCE_PORT, DESTINATION_IP, DESTINATION_PORT;
    // strings for matches in B
    string REQUEST_METHOD, REQUEST_URI, REQUEST_HTTP_VERSION; // first regex
    string REQUEST_HOST, REQUEST_CONNECTION, REQUEST_ACCEPT, REQUEST_USER_AGENT, REQUEST_DNT, REQUEST_REFERRER, REQUEST_ACCEPT_ENCODING, REQUEST_ACCEPT_LANGUAGE, REQUEST_COOKIE, REQUEST_X_REQUESTED_WITH, REQUEST_CONTENT_TYPE, REQUEST_CONTENT_LENGTH, REQUEST_PROXY_CONNECTION, REQUEST_ACCEPT_CHARSET, REQUEST_UA_CPU, REQUEST_X_FORWARDED_FOR, REQUEST_CACHE_CONTROL, REQUEST_VIA, REQUEST_IF_MODIFIED_SINCE, REQUEST_IF_NONE_MATCH, REQUEST_PRAGMA;
    // strings for matches in F
    string RESPONSE_HTTP_VERSION, RESPONSE_HTTP_STATUS_CODE, RESPONSE_HTTP_STATUS_TEXT, RESPONSE_X_POWERED_BY, RESPONSE_EXPIRES, RESPONSE_CACHE_CONTROL, RESPONSE_PRAGMA, RESPONSE_VARY, RESPONSE_CONTENT_ENCODING, RESPONSE_CONTENT_LENGTH, RESPONSE_CONNECTION, RESPONSE_CONTENT_TYPE, RESPONSE_STATUS, RESPONSE_KEEP_ALIVE;
    // strings for matches in H
    string TRAILER_APACHE_HANDLER, TRAILER_APACHE_ERROR, TRAILER_STOPWATCH, TRAILER_STOPWATCH2, TRAILER_RESPONSE_BODY_TRANSFORMED, TRAILER_PRODUCER, TRAILER_SERVER, TRAILER_ACTION, TRAILER_XML_PARSER_ERROR;
    
    
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
	      TIMESTAMP = match[1];
	      UNIQUE_ID = match[2];
	      SOURCE_IP = match[3];
	      SOURCE_PORT = match[4];
	      DESTINATION_IP = match[5];
	      DESTINATION_PORT = match[6];
	      if(debug) {cout << "Apache UNIQUE_ID for header " << line << " is: " << UNIQUE_ID << endl;}
	    } else {
	      cerr << "No Apache Unique ID found" << endl;
	    }

	    // UNIQUE_ID must be bound to all statements
	    if (debug) {cout << "Binding unique ID to statements" << endl;};
	    for (const auto &s : prepared_statements_map) {
	      int rc_bind = sqlite3_bind_text(*(get<1>(s.second)), sqlite3_bind_parameter_index(*(get<1>(s.second)), ":UNIQUE_ID"), UNIQUE_ID.c_str(), UNIQUE_ID.length(), 0);
	      if (rc_bind != SQLITE_OK) {
		cerr << UNIQUE_ID << ": error binding unique ID to statement " << s.first << ". Code " << rc_bind << " description: " << sqlite3_errmsg(db) << endl;
	      } else {
		if (debug) {cout << UNIQUE_ID << ": unique ID bound to " << s.first << " successfully" << endl;}
	      }
	    }
	    
	    
	    
	    // header and A data bound to insert_main sql statement
	    if (debug) {cout << "Binding data from A to table main prepared statement" << endl;};
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":HEADER"), HEADER.c_str(), HEADER.length(), 0);
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":A"), A.c_str(), A.length(), 0);
	    
	    // these values bound to insert_A sql statement
	    if (debug) {cout << "Binding data for table A" << endl;};
	    sqlite3_bind_text(stmt_insert_A, sqlite3_bind_parameter_index(stmt_insert_A, ":TIMESTAMP"), TIMESTAMP.c_str(), TIMESTAMP.length(), 0);
	    sqlite3_bind_text(stmt_insert_A, sqlite3_bind_parameter_index(stmt_insert_A, ":SOURCE_IP"), SOURCE_IP.c_str(), SOURCE_IP.length(), 0);
	    sqlite3_bind_text(stmt_insert_A, sqlite3_bind_parameter_index(stmt_insert_A, ":SOURCE_PORT"), SOURCE_PORT.c_str(), SOURCE_PORT.length(), 0);
	    sqlite3_bind_text(stmt_insert_A, sqlite3_bind_parameter_index(stmt_insert_A, ":DESTINATION_IP"), DESTINATION_IP.c_str(), DESTINATION_IP.length(), 0);
	    sqlite3_bind_text(stmt_insert_A, sqlite3_bind_parameter_index(stmt_insert_A, ":DESTINATION_PORT"), DESTINATION_PORT.c_str(), DESTINATION_PORT.length(), 0);
	    
	    



	    
	    
	    
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
	    
	    if (boost::regex_search(B.c_str(), match, B_regex_host)) {
	      REQUEST_HOST = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_connection)) {
	      REQUEST_CONNECTION = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_accept)) {
	      REQUEST_ACCEPT = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_useragent)) {
	      REQUEST_USER_AGENT = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_DNT)) {
	      REQUEST_DNT = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_referrer)) {
	      REQUEST_REFERRER = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_accept_encoding)) {
	      REQUEST_ACCEPT_ENCODING = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_accept_language)) {
	      REQUEST_ACCEPT_LANGUAGE = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_cookie)) {
	      REQUEST_COOKIE = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_x_requested_with)) {
	      REQUEST_X_REQUESTED_WITH = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_content_type)) {
	      REQUEST_CONTENT_TYPE = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_content_length)) {
	      REQUEST_CONTENT_LENGTH = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_proxy_connection)) {
	      REQUEST_PROXY_CONNECTION = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_accept_charset)) {
	      REQUEST_ACCEPT_CHARSET = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_UA_CPU)) {
	      REQUEST_UA_CPU = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_x_forwarded_for)) {
	      REQUEST_X_FORWARDED_FOR = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_cache_control)) {
	      REQUEST_CACHE_CONTROL = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_via)) {
	      REQUEST_VIA = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_if_modified_since)) {
	      REQUEST_IF_MODIFIED_SINCE = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_if_none_match)) {
	      REQUEST_IF_NONE_MATCH = match[1];
	    }
	    if (boost::regex_search(B.c_str(), match, B_regex_pragma)) {
	      REQUEST_PRAGMA = match[1];
	    }
	    
	    // bind whole B string
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":B"), B.c_str(), B.length(), 0);
	    
	    // bind first regex match
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_METHOD"), REQUEST_METHOD.c_str(), REQUEST_METHOD.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_URI"), REQUEST_URI.c_str(), REQUEST_URI.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_HTTP_VERSION"), REQUEST_HTTP_VERSION.c_str(), REQUEST_HTTP_VERSION.length(), 0);

	    // bind the rest
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_HOST"), REQUEST_HOST.c_str(), REQUEST_HOST.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_CONNECTION"), REQUEST_CONNECTION.c_str(), REQUEST_CONNECTION.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_ACCEPT"), REQUEST_ACCEPT.c_str(), REQUEST_ACCEPT.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_USER_AGENT"), REQUEST_USER_AGENT.c_str(), REQUEST_USER_AGENT.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_DNT"), REQUEST_DNT.c_str(), REQUEST_DNT.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_REFERRER"), REQUEST_REFERRER.c_str(), REQUEST_REFERRER.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_ACCEPT_ENCODING"), REQUEST_ACCEPT_ENCODING.c_str(), REQUEST_ACCEPT_ENCODING.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_ACCEPT_LANGUAGE"), REQUEST_ACCEPT_LANGUAGE.c_str(), REQUEST_ACCEPT_LANGUAGE.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_COOKIE"), REQUEST_COOKIE.c_str(), REQUEST_COOKIE.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_X_REQUESTED_WITH"), REQUEST_X_REQUESTED_WITH.c_str(), REQUEST_X_REQUESTED_WITH.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_CONTENT_TYPE"), REQUEST_CONTENT_TYPE.c_str(), REQUEST_CONTENT_TYPE.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_CONTENT_LENGTH"), REQUEST_CONTENT_LENGTH.c_str(), REQUEST_CONTENT_LENGTH.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_PROXY_CONNECTION"), REQUEST_PROXY_CONNECTION.c_str(), REQUEST_PROXY_CONNECTION.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_ACCEPT_CHARSET"), REQUEST_ACCEPT_CHARSET.c_str(), REQUEST_ACCEPT_CHARSET.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_UA_CPU"), REQUEST_UA_CPU.c_str(), REQUEST_UA_CPU.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_X_FORWARDED_FOR"), REQUEST_X_FORWARDED_FOR.c_str(), REQUEST_X_FORWARDED_FOR.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_CACHE_CONTROL"), REQUEST_CACHE_CONTROL.c_str(), REQUEST_CACHE_CONTROL.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_VIA"), REQUEST_VIA.c_str(), REQUEST_VIA.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_IF_MODIFIED_SINCE"), REQUEST_IF_MODIFIED_SINCE.c_str(), REQUEST_IF_MODIFIED_SINCE.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_IF_NONE_MATCH"), REQUEST_IF_NONE_MATCH.c_str(), REQUEST_IF_NONE_MATCH.length(), 0);
	    sqlite3_bind_text(stmt_insert_B, sqlite3_bind_parameter_index(stmt_insert_B, ":REQUEST_PRAGMA"), REQUEST_PRAGMA.c_str(), REQUEST_PRAGMA.length(), 0);


	    
	    
		    
	    
	    
	    
	    

	    
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
	    
	    if (boost::regex_search(F.c_str(), match, F_regex_x_powered_by)) {
	      RESPONSE_X_POWERED_BY = match[1];
	    }
	    if (boost::regex_search(F.c_str(), match, F_regex_expires)) {
	      RESPONSE_EXPIRES = match[1];
	    }
	    if (boost::regex_search(F.c_str(), match, F_regex_cache_control)) {
	      RESPONSE_CACHE_CONTROL = match[1];
	    }
	    if (boost::regex_search(F.c_str(), match, F_regex_pragma)) {
	      RESPONSE_PRAGMA = match[1];
	    }
	    if (boost::regex_search(F.c_str(), match, F_regex_vary)) {
	      RESPONSE_VARY = match[1];
	    }
	    if (boost::regex_search(F.c_str(), match, F_regex_content_encoding)) {
	      RESPONSE_CONTENT_ENCODING = match[1];
	    }
	    if (boost::regex_search(F.c_str(), match, F_regex_content_length)) {
	      RESPONSE_CONTENT_LENGTH = match[1];
	    }
	    if (boost::regex_search(F.c_str(), match, F_regex_connection)) {
	      RESPONSE_CONNECTION = match[1];
	    }
	    if (boost::regex_search(F.c_str(), match, F_regex_content_type)) {
	      RESPONSE_CONTENT_TYPE = match[1];
	    }
	    if (boost::regex_search(F.c_str(), match, F_regex_status)) {
	      RESPONSE_STATUS = match[1];
	    }
	    if (boost::regex_search(F.c_str(), match, F_regex_keep_alive)) {
	      RESPONSE_KEEP_ALIVE = match[1];
	    }
	    
	    
	    // bind whole F string
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":F"), F.c_str(), F.length(), 0);	    

	    // bind first statement
	    sqlite3_bind_text(stmt_insert_F, sqlite3_bind_parameter_index(stmt_insert_F, ":RESPONSE_HTTP_VERSION"), RESPONSE_HTTP_VERSION.c_str(), RESPONSE_HTTP_VERSION.length(), 0);
	    sqlite3_bind_text(stmt_insert_F, sqlite3_bind_parameter_index(stmt_insert_F, ":RESPONSE_HTTP_STATUS_CODE"), RESPONSE_HTTP_STATUS_CODE.c_str(), RESPONSE_HTTP_STATUS_CODE.length(), 0);
	    sqlite3_bind_text(stmt_insert_F, sqlite3_bind_parameter_index(stmt_insert_F, ":RESPONSE_HTTP_STATUS_TEXT"), RESPONSE_HTTP_STATUS_TEXT.c_str(), RESPONSE_HTTP_STATUS_TEXT.length(), 0);
	    
	    // bind the rest
	    sqlite3_bind_text(stmt_insert_F, sqlite3_bind_parameter_index(stmt_insert_F, ":RESPONSE_X_POWERED_BY"), RESPONSE_X_POWERED_BY.c_str(), RESPONSE_X_POWERED_BY.length(), 0);
	    sqlite3_bind_text(stmt_insert_F, sqlite3_bind_parameter_index(stmt_insert_F, ":RESPONSE_EXPIRES"), RESPONSE_EXPIRES.c_str(), RESPONSE_EXPIRES.length(), 0);
	    sqlite3_bind_text(stmt_insert_F, sqlite3_bind_parameter_index(stmt_insert_F, ":RESPONSE_CACHE_CONTROL"), RESPONSE_CACHE_CONTROL.c_str(), RESPONSE_CACHE_CONTROL.length(), 0);
	    sqlite3_bind_text(stmt_insert_F, sqlite3_bind_parameter_index(stmt_insert_F, ":RESPONSE_PRAGMA"), RESPONSE_PRAGMA.c_str(), RESPONSE_PRAGMA.length(), 0);
	    sqlite3_bind_text(stmt_insert_F, sqlite3_bind_parameter_index(stmt_insert_F, ":RESPONSE_VARY"), RESPONSE_VARY.c_str(), RESPONSE_VARY.length(), 0);
	    sqlite3_bind_text(stmt_insert_F, sqlite3_bind_parameter_index(stmt_insert_F, ":RESPONSE_CONTENT_ENCODING"), RESPONSE_CONTENT_ENCODING.c_str(), RESPONSE_CONTENT_ENCODING.length(), 0);
	    sqlite3_bind_text(stmt_insert_F, sqlite3_bind_parameter_index(stmt_insert_F, ":RESPONSE_CONTENT_LENGTH"), RESPONSE_CONTENT_LENGTH.c_str(), RESPONSE_CONTENT_LENGTH.length(), 0);
	    sqlite3_bind_text(stmt_insert_F, sqlite3_bind_parameter_index(stmt_insert_F, ":RESPONSE_CONNECTION"), RESPONSE_CONNECTION.c_str(), RESPONSE_CONNECTION.length(), 0);
	    sqlite3_bind_text(stmt_insert_F, sqlite3_bind_parameter_index(stmt_insert_F, ":RESPONSE_CONTENT_TYPE"), RESPONSE_CONTENT_TYPE.c_str(), RESPONSE_CONTENT_TYPE.length(), 0);
	    sqlite3_bind_text(stmt_insert_F, sqlite3_bind_parameter_index(stmt_insert_F, ":RESPONSE_STATUS"), RESPONSE_STATUS.c_str(), RESPONSE_STATUS.length(), 0);
	    sqlite3_bind_text(stmt_insert_F, sqlite3_bind_parameter_index(stmt_insert_F, ":RESPONSE_KEEP_ALIVE"), RESPONSE_KEEP_ALIVE.c_str(), RESPONSE_KEEP_ALIVE.length(), 0);
	    
	    
	    
	    
	    
	    
	    
	    
	    
	    
	  } else if (letter == 'G') {
	    if (debug) {cout << "Letter is G" << endl;}
	    G = headerdata;
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":G"), G.c_str(), G.length(), 0);	    

	    
	  } else if (letter == 'H') {
	    if (debug) {cout << "Letter is H" << endl;}
	    H = headerdata;
	    sqlite3_bind_text(stmt_insert_main, sqlite3_bind_parameter_index(stmt_insert_main, ":H"), H.c_str(), H.length(), 0);	

	    if (boost::regex_search(H.c_str(), match, H_regex_apache_handler)) {
	      TRAILER_APACHE_HANDLER = match[1];
	    }
	    if (boost::regex_search(H.c_str(), match, H_regex_apache_error)) {
	      TRAILER_APACHE_ERROR = match[1];
	    }
	    if (boost::regex_search(H.c_str(), match, H_regex_stopwatch)) {
	      TRAILER_STOPWATCH = match[1];
	    }
	    if (boost::regex_search(H.c_str(), match, H_regex_stopwatch2)) {
	      TRAILER_STOPWATCH2 = match[1];
	    }
	    if (boost::regex_search(H.c_str(), match, H_regex_response_body_transformed)) {
	      TRAILER_RESPONSE_BODY_TRANSFORMED = match[1];
	    }
	    if (boost::regex_search(H.c_str(), match, H_regex_producer)) {
	      TRAILER_PRODUCER = match[1];
	    }
	    if (boost::regex_search(H.c_str(), match, H_regex_server)) {
	      TRAILER_SERVER = match[1];
	    }
	    if (boost::regex_search(H.c_str(), match, H_regex_action)) {
	      TRAILER_ACTION = match[1];
	    }
	    if (boost::regex_search(H.c_str(), match, H_regex_xml_parser_error)) {
	      TRAILER_XML_PARSER_ERROR = match[1];
	    }
	    
	    // bind values for table H
	    sqlite3_bind_text(stmt_insert_H, sqlite3_bind_parameter_index(stmt_insert_H, ":TRAILER_APACHE_HANDLER"), TRAILER_APACHE_HANDLER.c_str(), TRAILER_APACHE_HANDLER.length(), 0);
	    sqlite3_bind_text(stmt_insert_H, sqlite3_bind_parameter_index(stmt_insert_H, ":TRAILER_APACHE_ERROR"), TRAILER_APACHE_ERROR.c_str(), TRAILER_APACHE_ERROR.length(), 0);
	    sqlite3_bind_text(stmt_insert_H, sqlite3_bind_parameter_index(stmt_insert_H, ":TRAILER_STOPWATCH"), TRAILER_STOPWATCH.c_str(), TRAILER_STOPWATCH.length(), 0);
	    sqlite3_bind_text(stmt_insert_H, sqlite3_bind_parameter_index(stmt_insert_H, ":TRAILER_STOPWATCH2"), TRAILER_STOPWATCH2.c_str(), TRAILER_STOPWATCH2.length(), 0);
	    sqlite3_bind_text(stmt_insert_H, sqlite3_bind_parameter_index(stmt_insert_H, ":TRAILER_RESPONSE_BODY_TRANSFORMED"), TRAILER_RESPONSE_BODY_TRANSFORMED.c_str(), TRAILER_RESPONSE_BODY_TRANSFORMED.length(), 0);
	    sqlite3_bind_text(stmt_insert_H, sqlite3_bind_parameter_index(stmt_insert_H, ":TRAILER_PRODUCER"), TRAILER_PRODUCER.c_str(), TRAILER_PRODUCER.length(), 0);
	    sqlite3_bind_text(stmt_insert_H, sqlite3_bind_parameter_index(stmt_insert_H, ":TRAILER_SERVER"), TRAILER_SERVER.c_str(), TRAILER_SERVER.length(), 0);
	    sqlite3_bind_text(stmt_insert_H, sqlite3_bind_parameter_index(stmt_insert_H, ":TRAILER_ACTION"), TRAILER_ACTION.c_str(), TRAILER_ACTION.length(), 0);
	    sqlite3_bind_text(stmt_insert_H, sqlite3_bind_parameter_index(stmt_insert_H, ":TRAILER_XML_PARSER_ERROR"), TRAILER_XML_PARSER_ERROR.c_str(), TRAILER_XML_PARSER_ERROR.length(), 0);

	    
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
	    
	    
	    
	    // for each ID matched and stored in the set:
	    // 1) Increment the relevant counter
	    // 2) Bind the value to the relevant value in the relevant statement
	    for (const auto &id : ruleIDsSet) {
	      sqlite3_stmt *statement; // pointer called statement that we can point at the relevant sqlite3_stmt when we have retrieved it from the map
	      
	      // 1) increment the relevant counter and retrieve statement to bind the values to from the map
	      auto pos = ruleIDmap.find(id); // postition of the relevant rule ID in the rule ID map
	      if (pos == ruleIDmap.end()) {
		cerr << UNIQUE_ID << ": Error - " << id << " could not be found in the rule ID map" << endl;
	      } else {
		// define a pointer equal to the address of the relevant counter
		int * ruleIDcounterpointer = get<1>(pos->second);
		++*ruleIDcounterpointer; // increment the counter using the dereferenced pointer
		if (debug) {cout << "Counter is: " << *ruleIDcounterpointer << endl;}
		
		// retrieve statement to bind the values to from the map
		statement = *get<0>(pos->second);
	      }
	      
  	      // 2) bind the value in the matching ruleIDCountMap to the relevant value in the relevant statement	      
	      // create a string containing a colon followed by the rule ID for use in the bind statement
	      string colonnumber = ":" + id;
	      if (debug) {cout << "colonnumber is: " << colonnumber << endl;}
	      
	      
	      auto pos2 = ruleIDCountMap.find(id); // position of the relevant rule Id in the rule Id map
	      if (pos2 == ruleIDCountMap.end()) { // if id exists as a key in the map
		cerr << UNIQUE_ID << ": Error - " << id << "could not be found in the rule ID counter" << endl;
	      } else {
		if(debug) {cout << UNIQUE_ID << ": " << id << " was found in the ID counter" << endl;}
		
		// bind the counter for the relevant rule ID to the correct statement
		int rc_bind = sqlite3_bind_int(statement, sqlite3_bind_parameter_index(statement, colonnumber.c_str()), pos2->second); // WALRUS - working! Just tidy up
		
		if (rc_bind != SQLITE_OK) {
		  cerr << UNIQUE_ID << ": error binding values for " << id << " . Code " << rc_bind << " description: " << sqlite3_errmsg(db) << endl;
		} else {
		  if (debug) {cout << UNIQUE_ID << ": values for " << id << " bound successfully" << endl;}
		}	      
	      }
	    }	    
	    

	    // calculate total rules matched
	    for (const auto &counter : countersMap) {
	      // for every item in the counters map except CRS_SEPARATE_RULES_MATCHED, add the value of the counter to the total 
	      if (counter.first != string("CRS_SEPARATE_RULES_MATCHED")) {
		CRS_SEPARATE_RULES_MATCHED = CRS_SEPARATE_RULES_MATCHED + *(counter.second);
	      }
	    }
	    
	    
	    // bind the value of each of the rule counters to statement H
	    for (const auto &counter : countersMap) {
	      string colonnumber = ":" + counter.first; // colonnumber is used for sqlite parameter index
	      // bind the value and check the response code
	      int rc_bind = sqlite3_bind_int(stmt_insert_H, sqlite3_bind_parameter_index(stmt_insert_H, colonnumber.c_str()), *counter.second);
	      if (rc_bind != SQLITE_OK) {
		cerr << UNIQUE_ID << ": error binding " << counter.first << ". Code " << rc_bind << " description: " << sqlite3_errmsg(db) << endl;
	      } else {
		if (debug) {cout << UNIQUE_ID << ": " << counter.first << " integer bound successfully" << endl;}
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
	    	    
	    // reset all of the prepared statements ready to be re-executed
	    for (const auto &s : prepared_statements_map) {
	      rc = sqlite3_reset(*get<1>(s.second));
	      if( rc != SQLITE_OK ){
		cerr << "SQL error resetting " << s.first << " prepared statement" << endl;
		cerr << "The error was: "<< sqlite3_errmsg(db) << endl;
	      } else {
		if (debug) {cout << "Prepared statement " << s.first << " was reset successfully" << endl;}
	      }
	    }
	    
	    // clear bindings for each prepared statement
	    for (const auto &s : prepared_statements_map) {
	      rc = sqlite3_clear_bindings(*get<1>(s.second));
	      if( rc != SQLITE_OK ){
		cerr << "SQL error clearing the bindings for " << s.first << "prepared statement" << endl;
		cerr << "The error was: "<< sqlite3_errmsg(db) << endl;
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
	    TIMESTAMP=SOURCE_IP=SOURCE_PORT=DESTINATION_IP=DESTINATION_PORT="";
	    REQUEST_METHOD=REQUEST_URI=REQUEST_HTTP_VERSION="";
	    
	    // clear B strings
	    REQUEST_HOST=REQUEST_CONNECTION=REQUEST_ACCEPT=REQUEST_USER_AGENT=REQUEST_DNT=REQUEST_REFERRER=REQUEST_ACCEPT_ENCODING=REQUEST_ACCEPT_LANGUAGE=REQUEST_COOKIE=REQUEST_X_REQUESTED_WITH=REQUEST_CONTENT_TYPE=REQUEST_CONTENT_LENGTH=REQUEST_PROXY_CONNECTION=REQUEST_ACCEPT_CHARSET=REQUEST_UA_CPU=REQUEST_X_FORWARDED_FOR=REQUEST_CACHE_CONTROL=REQUEST_VIA=REQUEST_IF_MODIFIED_SINCE=REQUEST_IF_NONE_MATCH=REQUEST_PRAGMA="";
	    RESPONSE_HTTP_VERSION=RESPONSE_HTTP_STATUS_CODE=RESPONSE_HTTP_STATUS_TEXT=RESPONSE_X_POWERED_BY=RESPONSE_EXPIRES=RESPONSE_CACHE_CONTROL=RESPONSE_PRAGMA=RESPONSE_VARY=RESPONSE_CONTENT_ENCODING=RESPONSE_CONTENT_LENGTH=RESPONSE_CONNECTION= RESPONSE_CONTENT_TYPE=RESPONSE_STATUS=RESPONSE_KEEP_ALIVE="";
	    
	    // clear H strings
	    TRAILER_APACHE_HANDLER=TRAILER_APACHE_ERROR=TRAILER_STOPWATCH=TRAILER_STOPWATCH2=TRAILER_RESPONSE_BODY_TRANSFORMED=TRAILER_PRODUCER=TRAILER_SERVER=TRAILER_ACTION=TRAILER_XML_PARSER_ERROR="";
	    
	    // reset counters for matches in H to 0    
	    if(debug) {cout << "Resetting counters to 0" << endl;}
	    for (const auto &counter : countersMap) {
	      *(counter.second) = 0;
	    }
	    if(debug) {cout << "...done." << endl;}
	    
	  }
	  break; // stop reading file
	} // end of "if line == endline"
      } // end of "while (getline(in, linedata))
    } // end of for loop looping through results vector
    
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
    

  } 
  end = std::chrono::system_clock::now();
  std::chrono::duration<double> elapsed_seconds = end-start;
  double rate = recordCounter / elapsed_seconds.count();
  cout << "Processed " << recordCounter << " records in " << elapsed_seconds.count() << " seconds (" << rate << "/s)." << endl;
  return 0;
}