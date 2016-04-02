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

#include "databaseconfig.h"
#include <QFile>
#include <QDebug>
#include <QRegularExpression>

DatabaseConfig::DatabaseConfig (QString filepath, bool debug) {

    QFile file(filepath);
    if(debug) { qDebug() << "Parsing configuration file: " << filepath;}


    try {

        if (!file.exists()) {
            throw QString("The specified database configuration file does not exist.");
        }

        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            throw QString("Can't open the specified database configuration file.");
        }

        QRegularExpression validConfig("(\\w+?)\\s+([BFH])\\s+(.+?)$");
        QRegularExpression comment("^[\\s*#|#].*"); // any amount of whitespace followed by a hash followed by anything, or a hash followed by anything

        QRegularExpressionMatch match;

        int line = 0;
        while (!file.atEnd()) {
            ++line;
            QString lineData = file.readLine();

            // skip comment lines and empty lines
            match = comment.match(lineData);

            if ( match.hasMatch() ) {
                if(debug) {qDebug() << "Comment or blank line on line " << line << " of database configuration file.";}
            } else {
                match = validConfig.match(lineData);
                if(match.hasMatch()) {
                    if(debug) { qDebug().noquote() << "Matched data on line: " << line << ", value name is: " << match.captured(1) << ", section is: " << match.captured(2) << ", regex is: " << match.captured(3);}

                    QRegularExpression regex(match.captured(3));
                    if(!regex.isValid())
                        throw QString("Error in regular expression on line ") + QString::number(line) + ": " + match.captured(3) + ", " + regex.errorString() + " at position " + QString::number(regex.patternErrorOffset()+1);

                    if(match.captured(2) == QString("B")) {
                        requestHeaders.append(AuditLogConfigEntry{match.captured(1),match.captured(3),regex});
                    } else if(match.captured(2) == QString("F")) {
                        responseHeaders.append(AuditLogConfigEntry{match.captured(1),match.captured(3),regex});
                    } else {
                         throw QString("Invalid section identifier on line ") + QString::number(line) + " of database configuration file (section not implemented): " + lineData.replace(QRegExp("\\s+"), " "); // collapse whitespace into a single space
                    }
                } else {
                    throw QString("Invalid syntax on line ") + QString::number(line) + " of database configuration file: " + lineData.replace(QRegExp("\\s+"), " "); // collapse whitespace into a single space
                }
            }
        }

    } catch (QString message) {
        qCritical().noquote() << message;
        file.close();
        throw message;
    } catch (...) {
        file.close();
        throw QString("unknown error parsing config file");
    }

}
