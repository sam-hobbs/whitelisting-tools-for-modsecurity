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

#ifndef AUDITLOGDATABASE_H
#define AUDITLOGDATABASE_H

#include <QtSql>

class AuditLogDatabase {
public:
    AuditLogDatabase(const QString database, bool debug, bool progress);

    void importLogFile(const QString logfile);   

private:
    bool createDatabase();

    void getConnection();
    void setFilePath();
    bool beginTransaction();
    bool endTransaction();

    QString filepath;
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", 0);
    bool isOpen = 0;
    bool debug;
    bool showProgress;
};

#endif
