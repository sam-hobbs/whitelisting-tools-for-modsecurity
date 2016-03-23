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


#include <QCommandLineParser>
#include <QDebug>

#include "auditlogdatabase.h"

int main (int argc , char **argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("ModSecurity-Whitelister");
    QCoreApplication::setApplicationVersion("0.2");



    QCommandLineParser parser;
    parser.setApplicationDescription("A utility to read a ModSecurity audit log into a sqlite database file.");
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addPositionalArgument("logfile", QCoreApplication::translate("main","Log file to read"));
    parser.addPositionalArgument("database", QCoreApplication::translate("main", "Database file to be created or written to"));

    QCommandLineOption showProgressOption(QStringList() << "p" << "progress",
                                          QCoreApplication::translate("main", "Show Progress during import."));

    QCommandLineOption forceOption(QStringList() << "f" << "force",
                                   QCoreApplication::translate("force", "Don't ask for confirmation on errors."));

    QCommandLineOption debugOption(QStringList() << "d" << "debug",
                                   QCoreApplication::translate("debug", "Print debugging messages."));


    parser.addOptions({
        {{"p", "progress"},
            QCoreApplication::translate("main", "Progress during import")},
        {{"f", "force"},
            QCoreApplication::translate("main", "Don't ask for confirmation on errors")},
        {{"d", "debug"},
            QCoreApplication::translate("main", "Print debugging messages")},
    });

    parser.process(app);

    QString database;
    QStringList logfileList;

    QStringList args = parser.positionalArguments();
    // logfile is args.at(0)
    // database is args.at(1)
    if (args.size() < 2) {
        qCritical() << "You must supply at least two positional arguments: the logfile you want to parse, and the database to write it to (see --help)";
        return 1;
    } else {
        // last argument is the database
        database = args.takeLast();

        // other arguments are logfiles
        logfileList = args;

    }

    bool showProgress = parser.isSet(showProgressOption);
    bool force = parser.isSet(forceOption);
    bool debug = parser.isSet(debugOption);

    try {
        AuditLogDatabase db(database, debug, showProgress);

        foreach (const QString &str, logfileList) {
            if( showProgress || debug ) {qDebug() << "Importing logfile " << str;}
            db.importLogFile(str);
        }
    } catch (...) {
        qCritical() << "Import failed";
    }

}
