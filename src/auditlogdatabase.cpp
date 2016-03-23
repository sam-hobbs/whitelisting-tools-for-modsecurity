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

#include <QDebug>
#include <iostream>

#include "auditlogdatabase.h"
#include "auditlogrecord.h"

AuditLogDatabase::AuditLogDatabase(const QString database, bool debugging, bool progress) {
    filepath = database;
    debug = debugging;
    showProgress = progress;
    db.setDatabaseName(filepath);

    if (!createDatabase()) {
        qCritical() << "couldn't create database";
        throw "Couldn't create database";
    }

}

void AuditLogDatabase::getConnection() {
    if ( !db.open() ) {
        qCritical() << "Can't open database";
        throw "Can't open database";
    } else {
        if(debug) {qDebug() << "Opened database";}
        isOpen = true;
    }
}

void AuditLogDatabase::importLogFile(const QString logfile) {
    // only throw errors when it is not possible to continue the import
    try {

        // check if the database is open, get a connection if necessary
        if (!isOpen) {
            getConnection();
        }

        // go through the log file and find the line numbers of all the headers
        QVector<QPair<int,QString>> headerlines; // holds the line number of headers in the log file
        QRegularExpression headerRegex("(^\\-\\-\\w{8}\\-[A-Z]\\-\\-)");

        QFile file(logfile);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            qCritical() << "can't open logfile";
            throw "can't open logfile";
        }

        if(debug) {qDebug() << "Finding the lines with headers in the log file";}

        int line = 0;
        while (!file.atEnd()) {
            ++line;
            QRegularExpressionMatch match = headerRegex.match(file.readLine());
            if(match.hasMatch()) {
                if(debug) {qDebug().nospace().noquote() << "matched header " << match.captured(1) << " on line " << line;}
                headerlines.append({line,match.captured(1)});
            }
        }

        if(debug) {qDebug() << "Number of records to process is: " << headerlines.size();}

        // variables used to display progress while processing records
        // http://stackoverflow.com/questions/14539867/how-to-display-a-progress-indicator-in-pure-c-c-cout-printf
        int recordNumber = 0;
        float progress = 0.0;
        int barWidth = 70;

        // regular expressions for capturing data
        QRegularExpression audit_log_header_regex("^\\[(.*)\\]\\s(.{24})\\s(\\d+\\.\\d+\\.\\d+\\.\\d+|::1)\\s(\\d+)\\s(\\d+\\.\\d+\\.\\d+\\.\\d+|::1)\\s(\\d+).*");


        // queries for inserting data into main table
        QSqlQuery insert_main(db);

        if ( !insert_main.prepare("INSERT INTO main ( unique_id,  a_auditlogheader,  b_requestheaders,  c_requestbody,  d_intendedresponseheaders,  e_intendedresponsebody,  f_responseheaders,  g_responsebody,  h_auditlogtrailer,  i_reducedmultipartrequestbody,  j_multipartfilesinformation,  k_matchedrules)"
                                 "VALUES           (:unique_id, :a_auditlogheader, :b_requestheaders, :c_requestbody, :d_intendedresponseheaders, :e_intendedresponsebody, :f_responseheaders, :g_responsebody, :h_auditlogtrailer, :i_reducedmultipartrequestbody, :j_multipartfilesinformation, :k_matchedrules)" ) )
            throw QString("Failed to prepare insert statement, error was ( ") + insert_main.lastError().databaseText() + ", " + insert_main.lastError().driverText() + " )";

        // queries for inserting data into section A - audit log header
        QSqlQuery insert_audit_log_header(db);
        if (!insert_audit_log_header.prepare("INSERT INTO a_auditlogheader ( unique_id,  timestamp,  unixtime, source_ip_id, source_port_id, destination_ip_id, destination_port_id)"
                                                                      "VALUES( :unique_id, :timestamp, :unixtime,"
                                        "(SELECT id FROM x_a_source_ip WHERE data = :source_ip),"
                                        "(SELECT id FROM x_a_source_port WHERE data = :source_port),"
                                        "(SELECT id FROM x_a_destination_ip WHERE data = :destination_ip),"
                                        "(SELECT id FROM x_a_destination_port WHERE data = :destination_port))" ))
            throw QString("failed to prepare insert_audit_log_header statement, error was ( ") + insert_audit_log_header.lastError().databaseText() + ", " + insert_audit_log_header.lastError().driverText() + " )";

        QSqlQuery insert_a_source_ip(db);
        QSqlQuery insert_a_source_port(db);
        QSqlQuery insert_a_destination_ip(db);
        QSqlQuery insert_a_destination_port(db);


        if(!insert_a_source_ip.prepare("INSERT OR IGNORE INTO x_a_source_ip (data) VALUES (:data)"))
            throw "failed to prepare insert_a_source_ip statement";
        if(!insert_a_source_port.prepare("INSERT OR IGNORE INTO x_a_source_port (data) VALUES (:data)"))
            throw "failed to prepare insert_a_source_port statement";
        if(!insert_a_destination_ip.prepare("INSERT OR IGNORE INTO x_a_destination_ip (data) VALUES (:data)"))
            throw "failed to prepare insert_a_destination_ip statement";
        if(!insert_a_destination_port.prepare("INSERT OR IGNORE INTO x_a_destination_port (data) VALUES (:data)"))
            throw "failed to prepare insert_a_destination_port statement";

        // part B - request headers
        QSqlQuery insert_request_headers(db);
        if(!insert_request_headers.prepare("INSERT INTO b_requestheaders (unique_id, request_method_id, uri_id, http_version_id, host_id, connection_id, accept_id,"
                                           "user_agent_id, dnt_id, referrer_id, accept_encoding_id, accept_language_id, cookie_id, x_requested_with_id, content_type_id,"
                                           "content_length_id, proxy_connection_id, accept_charset_id, ua_cpu_id, x_forwarded_for_id, cache_control_id, via_id,"
                                           "if_modified_since_id, if_none_match_id, pragma_id)"
                                           "VALUES ( :unique_id,"
                                           "(SELECT id FROM x_b_request_method WHERE data = :request_method),"
                                           "(SELECT id FROM x_b_uri WHERE data = :uri),"
                                           "(SELECT id FROM x_b_http_version WHERE data = :http_version),"
                                           "(SELECT id FROM x_b_host WHERE data = :host),"
                                           "(SELECT id FROM x_b_connection WHERE data = :connection),"
                                           "(SELECT id FROM x_b_accept WHERE data = :accept),"
                                           "(SELECT id FROM x_b_user_agent WHERE data = :user_agent),"
                                           "(SELECT id FROM x_b_dnt WHERE data = :dnt),"
                                           "(SELECT id FROM x_b_referrer WHERE data = :referrer),"
                                           "(SELECT id FROM x_b_accept_encoding WHERE data = :accept_encoding),"
                                           "(SELECT id FROM x_b_accept_language WHERE data = :accept_language),"
                                           "(SELECT id FROM x_b_cookie WHERE data = :cookie),"
                                           "(SELECT id FROM x_b_x_requested_with WHERE data = :x_requested_with),"
                                           "(SELECT id FROM x_b_content_type WHERE data = :content_type),"
                                           "(SELECT id FROM x_b_content_length WHERE data = :content_length),"
                                           "(SELECT id FROM x_b_proxy_connection WHERE data = :proxy_connection),"
                                           "(SELECT id FROM x_b_accept_charset WHERE data = :accept_charset),"
                                           "(SELECT id FROM x_b_ua_cpu WHERE data = :ua_cpu),"
                                           "(SELECT id FROM x_b_x_forwarded_for WHERE data = :x_forwarded_for),"
                                           "(SELECT id FROM x_b_cache_control WHERE data = :cache_control),"
                                           "(SELECT id FROM x_b_via WHERE data = :via),"
                                           "(SELECT id FROM x_b_if_modified_since WHERE data = :if_modified_since),"
                                           "(SELECT id FROM x_b_if_none_match WHERE data = :if_none_match),"
                                           "(SELECT id FROM x_b_pragma WHERE data = :pragma)"
                                           ")") )
            throw QString("failed to prepare insert_request_headers statement, error was ( ") + insert_request_headers.lastError().databaseText() + ", " + insert_request_headers.lastError().driverText() + " )";

        QSqlQuery insert_request_method(db);



        // data structure to hold the current record's data, will be cleared after data has been bound in Z
        AuditLogRecord record;

        while ( recordNumber < headerlines.size() ) {

            if(debug) {qDebug() << "processing record number " << recordNumber + 1 << " of " << headerlines.size();}

            // data for extracting this record
            char letter = headerlines.at(recordNumber).second.toUtf8().constData()[11];

            int currentLine = 0;
            int startline = headerlines.at(recordNumber).first;
            int endline;
            if ( recordNumber == headerlines.size() - 1 ) {
                endline = line; // end of file from header extraction routine
            } else {
                endline = headerlines.at(recordNumber+1).first;
            }
            QString headerData;

            if(debug) {qDebug() << "startline is " << startline << " and endline is " << endline;}

            // reset the file stream to the start of the file
            file.seek(0);

            // extract the data we need from the log file
            while (!file.atEnd()) {
                QString linedata = file.readLine(); // NB: readLine moves the pos
                //qDebug() << "line is " << line;
                if (currentLine >= startline && currentLine < endline - 1) {
                    //qDebug() << "line";
                    headerData.append(linedata);
                } else if (currentLine == endline) {
                    //qDebug() << "reached end line";
                    // headerData now holds all of the data from one header
                    switch ( letter ) {
                    case 'A':
                        record.importAuditLogHeader(headerData);
                        break;
                    case 'B':
                        record.importRequestHeaders(headerData);
                        break;
                    case 'C':
                        record.importRequestBody(headerData);
                        break;
                    case 'D':
                        record.importIntendedResponseHeaders(headerData);
                        break;
                    case 'E':
                        record.importIntendedResponseBody(headerData);
                        break;
                    case 'F':
                        record.importResponseHeaders(headerData);
                        break;
                    case 'G':
                        record.importResponseBody(headerData);
                        break;
                    case 'H':
                        record.importAuditLogTrailer(headerData);
                        break;
                    case 'I':
                        record.importReducedMultipartRequestBody(headerData);
                        break;
                    case 'J':
                        record.importMultipartFilesInformation(headerData);
                        break;
                    case 'K':
                        record.importMatchedRules(headerData);
                        break;
                    case 'Z':
                        // bind the data to the queries
                        insert_main.bindValue(":unique_id", record.auditLogHeader->uniqueID);
                        insert_main.bindValue(":a_auditlogheader", record.auditLogHeader->completeString);
                        insert_main.bindValue(":b_requestheaders", record.requestHeaders);
                        insert_main.bindValue(":c_requestbody", record.requestBody);
                        insert_main.bindValue(":d_intendedresponseheaders", record.intendedResponseHeaders);
                        insert_main.bindValue(":e_intendedresponsebody", record.intendedResponseBody);
                        insert_main.bindValue(":f_responseheaders", record.responseHeaders);
                        insert_main.bindValue(":g_responsebody", record.responseBody);
                        insert_main.bindValue(":h_auditlogtrailer", record.auditLogTrailer);
                        insert_main.bindValue(":i_reducedmultipartrequestbody", record.reducedMultipartRequestBody);
                        insert_main.bindValue(":j_reducedmultipartfilesinformation", record.multipartFilesInformation);
                        insert_main.bindValue(":k_matchedrules", record.matchedRules);

                        // value tables for A (auditlog header)
                        insert_a_source_ip.bindValue(":data",record.auditLogHeader->sourceIP);
                        insert_a_source_port.bindValue(":data",record.auditLogHeader->sourcePort);
                        insert_a_destination_ip.bindValue(":data",record.auditLogHeader->destinationIP);
                        insert_a_destination_port.bindValue(":data",record.auditLogHeader->destinationPort);

                        // A (auditlog header)
                        insert_audit_log_header.bindValue(":unique_id", record.auditLogHeader->uniqueID);
                        insert_audit_log_header.bindValue(":timestamp", record.auditLogHeader->apacheTimestamp);
                        insert_audit_log_header.bindValue(":unixtime", record.auditLogHeader->unixtime); // TODO - check me new
                        insert_audit_log_header.bindValue(":source_ip", record.auditLogHeader->sourceIP);
                        insert_audit_log_header.bindValue(":source_port", record.auditLogHeader->sourcePort);
                        insert_audit_log_header.bindValue(":destination_ip", record.auditLogHeader->destinationIP);
                        insert_audit_log_header.bindValue(":destination_port", record.auditLogHeader->destinationPort);
                        //qDebug() << "values are " + record.auditLogHeader->sourceIP + " " + record.auditLogHeader->sourcePort + " " + record.auditLogHeader->destinationIP + " " + record.auditLogHeader->destinationPort;

                        // execute the queries

                        if (!insert_main.exec()) {
                            if( insert_main.lastError().databaseText() == QString("UNIQUE constraint failed: main.unique_id") ) {
                                if(showProgress) qWarning().noquote() << ""; // don't write the error on top of the progress bar!
                                qWarning().noquote() << "Record " + record.auditLogHeader->uniqueID + " is already in the database";
                            } else {
                                if(showProgress) qWarning().noquote() << "";
                                qWarning() << "Warning: record could not be inserted, error is (" << insert_main.lastError().databaseText() +  ", " + insert_main.lastError().driverText() + ")";
                            }
                        }

                        // insert values into the data tables for the audit log header (required before executing insert_audit_log_header query
                        // no error checking on these because they are "insert or ignore" type statements
                        insert_a_source_ip.exec();
                        insert_a_source_port.exec();
                        insert_a_destination_ip.exec();
                        insert_a_destination_port.exec();

                        if (!insert_audit_log_header.exec()) {
                            if(showProgress) qWarning().noquote() << "";
                            qWarning() << "Warning: record could not be inserted, error is (" << insert_audit_log_header.lastError().databaseText() +  ", " + insert_audit_log_header.lastError().driverText() + ")";
                        }

                        // clear the record and start again
                        record.clear();
                        break;
                    default:
                        throw "Letter out of bounds";
                    }
                }
                currentLine++;
            }




            // update the progress indicator
            if (showProgress && !debug) {
                progress = float(recordNumber) / float(headerlines.size() - 1);

                std::cout << "[";
                int pos = barWidth * progress;
                for (int i = 0; i < barWidth; ++i) {
                    if (i < pos) std::cout << "=";
                    else if (i == pos) std::cout << ">";
                    else std::cout << " ";
                }
                std::cout << "] " << int(progress * 100.0) << " %\r";
                std::cout.flush();
            }

            recordNumber++;
        }
        if(showProgress) {std::cout << std::endl;}
    } catch (QString & msg) {
        qCritical().noquote() << "error importing log file: " + msg;
    } catch (const char * msg) {
        qCritical().noquote() << "error importing log file: " << msg;
    } catch (...) {
        qCritical().noquote() << "an unknown error occurred during import";
    }

}

// TODO - use http://doc.qt.io/qt-5/qsqldatabase.html#transaction instead
bool AuditLogDatabase::beginTransaction() {
    QSqlQuery query(QString("BEGIN_TRANSACTION"),db);
    if (!query.exec()) {
        qWarning() << "Couldn't begin transaction, error was " << query.lastError();
        return 1;
    }
    return 0;
}

// TODO - use http://doc.qt.io/qt-5/qsqldatabase.html#commit instead
bool AuditLogDatabase::endTransaction() {
    QSqlQuery query(QString("END_TRANSACTION"),db);
    if (!query.exec()) {
        qWarning() << "Couldn't commit transaction, error was " << query.lastError();
        return 1;
    }
    return 0;
}


bool AuditLogDatabase::createDatabase() {

    // check if the database is open, get a connection if necessary
    if (!isOpen) {
        getConnection();
    }




    // generate sql queries for creating each table
    QSqlQuery create_table_main(QString("CREATE TABLE IF NOT EXISTS main (unique_id TEXT PRIMARY KEY, a_auditlogheader TEXT, b_requestheaders TEXT, c_requestbody TEXT, d_intendedresponseheaders TEXT, e_intendedresponsebody TEXT, f_responseheaders TEXT, g_responsebody TEXT, h_auditlogtrailer TEXT, i_reducedmultipartrequestbody TEXT, j_multipartfilesinformation TEXT, k_matchedrules TEXT)"),db);
    QSqlQuery create_table_a_auditlogheader(QString("CREATE TABLE IF NOT EXISTS a_auditlogheader (unique_id TEXT PRIMARY KEY,    timestamp TEXT, unixtime TEXT, source_ip_id INTEGER NOT NULL, source_port_id INTEGER NOT NULL, destination_ip_id INTEGER NOT NULL, destination_port_id INTEGER NOT NULL)"),db);
    QSqlQuery create_table_b_requestheaders(QString("CREATE TABLE IF NOT EXISTS b_requestheaders (unique_id TEXT PRIMARY KEY,    request_method_id INTEGER NOT NULL, uri_id INTEGER NOT NULL,  http_version_id INTEGER DEFAULT NULL, host_id INTEGER DEFAULT NULL, connection_id INTEGER DEFAULT NULL, accept_id INTEGER DEFAULT NULL, user_agent_id INTEGER DEFAULT NULL, dnt_id INTEGER DEFAULT NULL, referrer_id INTEGER DEFAULT NULL, accept_encoding_id INTEGER DEFAULT NULL, accept_language_id INTEGER DEFAULT NULL, cookie_id INTEGER DEFAULT NULL,x_requested_with_id INTEGER DEFAULT NULL, content_type_id INTEGER DEFAULT NULL, content_length_id INTEGER DEFAULT NULL, proxy_connection_id INTEGER DEFAULT NULL, accept_charset_id INTEGER DEFAULT NULL, ua_cpu_id INTEGER DEFAULT NULL, x_forwarded_for_id INTEGER DEFAULT NULL, cache_control_id INTEGER DEFAULT NULL, via_id INTEGER DEFAULT NULL, if_modified_since_id INTEGER DEFAULT NULL, if_none_match_id INTEGER DEFAULT NULL, pragma_id INTEGER DEFAULT NULL)"),db);
    //c_requestbody
    //d_intendedresponseheaders
    //e_intendedresponsebody
    QSqlQuery create_table_f_responseheaders(QString("CREATE TABLE IF NOT EXISTS f_responseheaders (unique_id TEXT PRIMARY KEY,    http_version_id INTEGER DEFAULT NULL,  http_status_code_id INTEGER DEFAULT NULL, http_status_text_id INTEGER DEFAULT NULL, x_powered_by_id INTEGER DEFAULT NULL, expires_id INTEGER DEFAULT NULL, cache_control_id INTEGER DEFAULT NULL, pragma_id INTEGER DEFAULT NULL, vary_id INTEGER DEFAULT NULL, content_encoding_id INTEGER DEFAULT NULL, content_length_id INTEGER DEFAULT NULL, connection_id INTEGER DEFAULT NULL, content_type_id INTEGER DEFAULT NULL, status_id INTEGER DEFAULT NULL, keep_alive_id INTEGER DEFAULT NULL)"),db);
    //g_responsebody
    //h_auditlogtrailer
    //i_reducedmultipartrequestbody
    //j_reducedmultipartfilesinformation
    //k_matchedrules

    // A
    // TODO
    QSqlQuery create_table_a_source_ip("CREATE TABLE IF NOT EXISTS x_a_source_ip (id INTEGER NOT NULL PRIMARY KEY, data TEXT UNIQUE NOT NULL)",db);
    QSqlQuery create_table_a_source_port("CREATE TABLE IF NOT EXISTS x_a_source_port (id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, data TEXT UNIQUE NOT NULL)",db);
    QSqlQuery create_table_a_destination_ip("CREATE TABLE IF NOT EXISTS x_a_destination_ip (id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, data TEXT UNIQUE NOT NULL)",db);
    QSqlQuery create_table_a_destination_port("CREATE TABLE IF NOT EXISTS x_a_destination_port (id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, data TEXT UNIQUE NOT NULL)",db);

    try {
        if( !create_table_main.exec() )
            throw "Error creating table main";
        if ( !create_table_a_auditlogheader.exec() )
            throw "Error creating table a_auditlogheader";
        if ( !create_table_b_requestheaders.exec() )
            throw "Error creating table b_requestheaders";
        if ( !create_table_f_responseheaders.exec() )
            throw "Error creating table f_responseheaders";

        if ( !create_table_a_source_ip.exec() )
            throw QString("Error creating table x_a_source_ip, error is (" + create_table_a_source_ip.lastError().databaseText() + ", " + create_table_a_source_ip.lastError().driverText() + ")");
        if ( !create_table_a_source_port.exec() )
            throw QString("Error creating table x_a_source_port, error is (" + create_table_a_source_port.lastError().databaseText() + ", " + create_table_a_source_port.lastError().driverText() + ")");
        if ( !create_table_a_destination_ip.exec() )
            throw QString("Error creating table x_a_destination_ip, error is (" + create_table_a_destination_ip.lastError().databaseText() + ", " + create_table_a_destination_ip.lastError().driverText() + ")");
        if ( !create_table_a_destination_port.exec() )
            throw QString("Error creating table x_a_destination_port, error is (" + create_table_a_destination_port.lastError().databaseText() + ", " + create_table_a_destination_port.lastError().driverText() + ")");

    } catch (QString & msg) {
        qCritical() << msg;
        throw;
    } catch (const char * msg) {
        qCritical() << msg;
        throw;
    } catch (...) {
        // if we get to here then the error is of unknown type
        qCritical() << "Error of unknown type creating database tables";
        throw;
    }
    return 1;
}
