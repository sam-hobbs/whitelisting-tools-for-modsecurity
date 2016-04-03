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

#include "auditlogrecord.h"
#include <QString>
#include <QDebug>
#include <QRegularExpression>
#include <QRegularExpressionMatch>


AuditLogRecord::AuditLogRecord(DatabaseConfig *config) : responseHeaders(config), databaseConfig(config) {

}


void AuditLogRecord::importAuditLogHeader(QString A) {
    //qDebug() << "A";
    //qDebug().noquote() << A;

    //auditLogHeader = A;
    // TODO - use qsharedpointer instead of normal pointer for this?
    //delete auditLogHeader;
    auditLogHeader = new AuditLogHeader(A);
}

void AuditLogRecord::importRequestHeaders(QString B) {
    //qDebug() << "B";

    //requestHeaders = B;
    //delete requestHeaders;
    requestHeaders = new RequestHeaders(B);
}

void AuditLogRecord::importRequestBody(QString C) {
    //qDebug() << "C";
    requestBody = C;
}

void AuditLogRecord::importIntendedResponseHeaders(QString D) {
    //qDebug() << "D";
    intendedResponseHeaders = D;
}

void AuditLogRecord::importIntendedResponseBody(QString E) {
    //qDebug() << "E";
    intendedResponseBody = E;
}

void AuditLogRecord::importResponseHeaders(QString F) {
    //qDebug() << "F";
    //responseHeaders = F;
    //responseHeaders = new ResponseHeaders(F,databaseConfig);
    responseHeaders.extract(F);
}

void AuditLogRecord::importResponseBody(QString G) {
    //qDebug() << "G";
    responseBody = G;
}

void AuditLogRecord::importAuditLogTrailer(QString H) {
    //qDebug() << "H";
    auditLogTrailer = H;
}

void AuditLogRecord::importReducedMultipartRequestBody(QString I) {
    //qDebug() << "I";
    reducedMultipartRequestBody = I;
}

void AuditLogRecord::importMultipartFilesInformation(QString J) {
    //qDebug() << "J";
    multipartFilesInformation = J;
}

void AuditLogRecord::importMatchedRules(QString K) {
    //qDebug() << "K";
    matchedRules = K;
}

void AuditLogRecord::clear() {
    //qDebug() << "clearing record";

    //auditLogHeader.clear(); // A
    //requestHeaders.clear(); // B
    requestBody.clear(); // C
    intendedResponseHeaders.clear(); // D
    intendedResponseBody.clear(); // E
    //responseHeaders.clear(); // F
    responseBody.clear(); // G
    auditLogTrailer.clear(); // H
    reducedMultipartRequestBody.clear(); // I
    multipartFilesInformation.clear(); // J
    matchedRules.clear(); // K

    auditLogHeader->clear(); // A
    requestHeaders->clear(); // B
    //responseHeaders->clear(); // F
    responseHeaders.clear(); // F

    alreadyInDatabase = 0;
}

