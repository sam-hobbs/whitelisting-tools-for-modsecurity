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

#ifndef DATABASECONFIG_H
#define DATABASECONFIG_H

#include <QString>
#include <QChar>
#include <QVector>
#include <QRegularExpression>

struct AuditLogConfigEntry {
    QString name;
    QString regexText;
    QRegularExpression regex;
};


class DatabaseConfig {
public:
    DatabaseConfig(QString filepath = QString(""), bool debug = 0);

    QVector<AuditLogConfigEntry> requestHeaders;
    QVector<AuditLogConfigEntry> responseHeaders;

};

#endif
