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

#ifndef AUDITLOGRECORD_H
#define AUDITLOGRECORD_H

// data structure to hold a single log record

#include <QString>
#include "auditlogrecord_auditlogheader.h"
#include "auditlogrecord_requestheaders.h"
#include "auditlogrecord_responseheaders.h"

//class RequestHeaders {
//public:
//    RequestHeaders(QString data);
//    void clear();

//    QString completeString;

//    QString requestMethod;
//    QString uri;
//    QString httpVersion;
//    QString host;
//    QString connection;
//    QString accept;
//    QString userAgent;
//    QString dnt;
//    QString referrer;
//    QString acceptEncoding;
//    QString acceptLanguage;
//    QString cookie;
//    QString xRequestedWith;
//    QString contentType;
//    QString contentLength;
//    QString proxyConnection;
//    QString acceptCharset;
//    QString userAgentCPU;
//    QString xForwardedFor;
//    QString cacheControl;
//    QString via;
//    QString ifModifiedSince;
//    QString ifNoneMatch;
//    QString pragma;
//};

class AuditLogRecord {

public:
    void importAuditLogHeader(QString A);
    void importRequestHeaders(QString B);
    void importRequestBody(QString C);
    void importIntendedResponseHeaders(QString D);
    void importIntendedResponseBody(QString E);
    void importResponseHeaders(QString F);
    void importResponseBody(QString G);
    void importAuditLogTrailer(QString H);
    void importReducedMultipartRequestBody(QString I);
    void importMultipartFilesInformation(QString J);
    void importMatchedRules(QString K);

    void clear();

//    QString auditLogHeader; // A
//    QString requestHeaders; // B
    QString requestBody; // C
    QString intendedResponseHeaders; // D
    QString intendedResponseBody; // E
    QString responseHeaders; // F
    QString responseBody; // G
    QString auditLogTrailer; // H
    QString reducedMultipartRequestBody; // I
    QString multipartFilesInformation; // J
    QString matchedRules; // K


    AuditLogHeader * auditLogHeader;
    RequestHeaders * requestHeaders;

    bool alreadyInDatabase = 0;

};


#endif
