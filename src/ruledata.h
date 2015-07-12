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
// if ruledata hasn't been defined already
#ifndef RULEDATA
#define RULEDATA

#include <string>

//RULE_ID TABLENAME ANOMALY_SCORE SQL_SCORE XSS_SCORE TROJAN_SCORE OUTBOUND_ANOMALY_SCORE AUTOMATION_SCORE PROFILER_SCORE 

struct rule_data {
    std::string rule_id;
    std::string table_name;
    signed int anomaly_score;
    signed int sql_score;
    signed int xss_score;
    signed int trojan_score;
    signed int outbound_anomaly_score;
    signed int automation_score;
    signed int profiler_score;
};

#endif