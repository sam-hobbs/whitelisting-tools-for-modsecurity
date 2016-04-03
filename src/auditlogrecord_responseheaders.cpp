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

#include "auditlogrecord_responseheaders.h"
#include "databaseconfig.h"
#include <QDebug>
#include <QString>
#include <QRegularExpression>
#include <QRegularExpressionMatch>

// constructor
ResponseHeaders::ResponseHeaders(DatabaseConfig *config) : databaseConfig(config) {

    // note: the following regex is hard coded in the program, since it is always present
    // 1st match is HTTP version, 2nd match is HTTP code, 3rd match is HTTP code description
    F_regex = QRegularExpression("^(HTTP\\/\\d\\.\\d)\\s(\\d+)\\s(.*?)$",QRegularExpression::MultilineOption);

}

void ResponseHeaders::extract(QString data) {
    completeString = data;

    QRegularExpressionMatch matches = F_regex.match(data);
    if (matches.hasMatch()) {
        httpVersion = matches.captured(1);
        httpCode = matches.captured(2);
        httpCodeDescription = matches.captured(3);
    }

    // now loop through the user defined members and capture data
    for (int i = 0; i < databaseConfig->responseHeaders.size(); ++i) {

        qDebug().noquote() << "trying to match " << databaseConfig->responseHeaders.at(i).name << " using regex " << databaseConfig->responseHeaders.at(i).regex.pattern() << " against data: \n" << data;

        // TODO - this part isn't capturing data properly

        //qDebug() << "pattern options in user defined data are: " << databaseConfig->responseHeaders.at(i).regex.patternOptions();


        matches = databaseConfig->responseHeaders.at(i).regex.match(data);
        //matches = databaseConfig->responseHeaders[i].regex.match(data);

        if(!matches.isValid())
            qDebug() << "invalid regex";


        if(matches.hasMatch()) {
            databaseConfig->responseHeaders[i].matchedData = matches.captured(1);
            qDebug() << "matched data: " << matches.captured(1);
        }

        QRegularExpressionMatch match = databaseConfig->responseHeaders.at(i).regex.match(data);
        if(match.hasMatch()) {
            databaseConfig->responseHeaders[i].matchedData = match.captured(1);
            qDebug() << "matched data: " << match.captured(1);
        }
    }
    // delete me v
    QRegularExpression regex("^Content-Encoding:\\s*(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpressionMatch mymatch = regex.match(data);
    //qDebug() << "pattern options are: " << regex.patternOptions();
    if(mymatch.hasMatch())
        qDebug() << "matched: " << mymatch.captured(1);

    // delete me ^
}

void ResponseHeaders::clear() {
    completeString.clear();

    httpVersion.clear();
    httpCode.clear();
    httpCodeDescription.clear();

    // clear the matched strings in the user defined parts
    for (int i = 0; i < databaseConfig->responseHeaders.size(); ++i) {
        databaseConfig->responseHeaders[i].matchedData.clear();
    }
}
