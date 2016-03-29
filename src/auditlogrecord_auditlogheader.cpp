/*
    This file is part of modsecurity-whitelister.

    modsecurity-whitelister is free software: you can redistribute it and/or
    modify it under the terms of the GNU General Public License as published
    by the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    modsecurity-whitelister is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with modsecurity-whitelister.  If not, see
    <http://www.gnu.org/licenses/>.
*/

#include "auditlogrecord_auditlogheader.h"
#include <QString>
#include <QDebug>
#include <QRegularExpression>
#include <QRegularExpressionMatch>

// for apache log time to unix time function - rewrite to use Qt members
#include <sstream>
using std::string;
using std::stringstream;


AuditLogHeader::AuditLogHeader (QString data) {
    completeString = data;

    QRegularExpression regex("^\\[(.*)\\]\\s(.{24})\\s(\\d+\\.\\d+\\.\\d+\\.\\d+|::1)\\s(\\d+)\\s(\\d+\\.\\d+\\.\\d+\\.\\d+|::1)\\s(\\d+).*");
    QRegularExpressionMatch matches = regex.match(data);
    if(matches.hasMatch()) {

        apacheTimestamp = matches.captured(1);
        uniqueID = matches.captured(2);
        sourceIP = matches.captured(3);
        sourcePort = matches.captured(4);
        destinationIP = matches.captured(5);
        destinationPort = matches.captured(6);
        unixtime = QString::fromStdString(apachetimeToUnixtime(apacheTimestamp.toStdString()) );

        //qDebug() << "timestamp is " << apacheTimestamp;
    }
};

void AuditLogHeader::clear () {
    completeString.clear();

    unixtime.clear();
    apacheTimestamp.clear();
    uniqueID.clear();
    sourceIP.clear();
    sourcePort.clear();
    destinationIP.clear();
    destinationPort.clear();
};


string AuditLogHeader::apachetimeToUnixtime(const string &timestamp) {

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

    struct tm tm;
    time_t t;
    if (strptime(timestamp.c_str(), "%d/%b/%Y:%H:%M:%S %Z", &tm) == NULL)
    return "-";

    tm.tm_isdst = 0; // Force dst off
    // Parse the timezone, the five digits start with the sign at idx 21.
    int hours = 10*(timestamp[22] - '0') + timestamp[23] - '0';
    int mins = 10*(timestamp[24] - '0') + timestamp[25] - '0';
    int off_secs = 60*60*hours + 60*mins;
    if (timestamp[21] == '-')
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
