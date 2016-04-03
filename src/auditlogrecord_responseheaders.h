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

#ifndef RESPONSEHEADERS_H
#define RESPONSEHEADERS_H

#include <QString>
#include <QRegularExpression>
#include "databaseconfig.h"

// section F

class ResponseHeaders {
public:
    //ResponseHeaders(QString data, DatabaseConfig *databaseConfig);
    ResponseHeaders(DatabaseConfig *databaseConfig);
    void clear();
    void extract(QString data);

    QString completeString;

    QString httpVersion;
    QString httpCode;
    QString httpCodeDescription;

    DatabaseConfig *databaseConfig;

private:
    QRegularExpression F_regex;


};

#endif
