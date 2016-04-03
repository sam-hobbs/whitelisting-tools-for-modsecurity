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

        QRegularExpression validConfig("(\\w+?)\\s+([ABCDEFGHIJKZ])\\s+(\\S+?)$");
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
                try {
                    match = validConfig.match(lineData);
                    if(match.hasMatch()) {
                        QString value = match.captured(1);
                        QString section = match.captured(2);
                        QString regexString = match.captured(3);

                        if(debug) { qDebug().noquote() << "Matched data on line: " << line << ", value name is: " << value << ", section is: " << section << ", regex is: " << regexString;}

                        if(match.captured(2) == QString("B")) {
                            requestHeaders.append(UserDefinedHeaderPart(value,regexString));
                        } else if(match.captured(2) == QString("F")) {
                            responseHeaders.append(UserDefinedHeaderPart(value,regexString));
                        } else {
                             throw QString("configuration of section ") + section + " has not been implemented: " + lineData.replace(QRegExp("\\s+"), " "); // collapse whitespace into a single space
                        }
                    } else {
                        throw QString("invalid syntax: ") + lineData.replace(QRegExp("\\s+"), " "); // collapse whitespace into a single space
                    }
                } catch (QString message) {
                    // rethrow the message with a line number attached
                    throw QString("Error on line: ") + QString::number(line) + " of database config file: " + message;
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
