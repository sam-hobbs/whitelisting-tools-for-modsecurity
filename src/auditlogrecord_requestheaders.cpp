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

#include "auditlogrecord_requestheaders.h"
#include <QString>
#include <QDebug>
#include <QRegularExpression>
#include <QRegularExpressionMatch>


RequestHeaders::RequestHeaders (QString data) {
    completeString = data;

    QRegularExpression B_regex("^(\\w+)\\s(.*)\\s(HTTP\\/\\d\\.\\d)$",QRegularExpression::MultilineOption); // 1st match is request method, 2nd match is URI, 3rd match is HTTP version
    //QRegularExpression B_regex_host("^Host:(.*?)$");
    QRegularExpression B_regex_host("^Host:\\s*(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_connection("^Connection:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_accept("^Accept:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_useragent("^User-Agent:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_DNT("^DNT:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_referrer("^Referer:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_accept_encoding("^Accept-Encoding:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_accept_language("^Accept-Language:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_cookie("^Cookie:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_x_requested_with("^X-Requested-With:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_content_type("^Content-Type:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_content_length("^Content-Length:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_proxy_connection("^Proxy-Connection:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_accept_charset("^Accept-Charset:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_UA_CPU("^UA-CPU:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_x_forwarded_for("^X-Forwarded-For:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_cache_control("^Cache-Control:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_via("^Via:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_if_modified_since("^If-Modified-Since:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_if_none_match("^If-None-Match:(.*?)$",QRegularExpression::MultilineOption);
    QRegularExpression B_regex_pragma("^Pragma:(.*?)$",QRegularExpression::MultilineOption);

    QRegularExpressionMatch matches = B_regex.match(data);
    if (matches.hasMatch()) {

        requestMethod = matches.captured(1);
        uri = matches.captured(2);
        httpVersion = matches.captured(3);

    }

    matches = B_regex_host.match(data);
    if(matches.hasMatch()) {
        host = matches.captured(1);
    }

    matches = B_regex_connection.match(data);
    if(matches.hasMatch()) {
        connection = matches.captured(1);
    }

    matches = B_regex_accept.match(data);
    if(matches.hasMatch()) {
        accept = matches.captured(1);
    }

    matches = B_regex_useragent.match(data);
    if(matches.hasMatch()) {
        userAgent = matches.captured(1);
    }

    matches = B_regex_DNT.match(data);
    if(matches.hasMatch()) {
        dnt = matches.captured(1);
    }

    matches = B_regex_referrer.match(data);
    if(matches.hasMatch()) {
        referrer = matches.captured(1);
    }

    matches = B_regex_accept_encoding.match(data);
    if(matches.hasMatch()) {
        acceptEncoding = matches.captured(1);
    }

    matches = B_regex_accept_language.match(data);
    if(matches.hasMatch()) {
        acceptLanguage = matches.captured(1);
    }

    matches = B_regex_cookie.match(data);
    if(matches.hasMatch()) {
        cookie = matches.captured(1);
    }

    matches = B_regex_x_requested_with.match(data);
    if(matches.hasMatch()) {
        xRequestedWith = matches.captured(1);
    }

    matches = B_regex_content_type.match(data);
    if(matches.hasMatch()) {
        contentType = matches.captured(1);
    }

    matches = B_regex_content_length.match(data);
    if(matches.hasMatch()) {
        contentLength = matches.captured(1);
    }

    matches = B_regex_proxy_connection.match(data);
    if(matches.hasMatch()) {
        proxyConnection = matches.captured(1);
    }

    matches = B_regex_accept_charset.match(data);
    if(matches.hasMatch()) {
        acceptCharset = matches.captured(1);
    }

    matches = B_regex_UA_CPU.match(data);
    if(matches.hasMatch()) {
        userAgentCPU = matches.captured(1);
    }

    matches = B_regex_x_forwarded_for.match(data);
    if(matches.hasMatch()) {
        xForwardedFor = matches.captured(1);
    }

    matches = B_regex_cache_control.match(data);
    if(matches.hasMatch()) {
        cacheControl = matches.captured(1);
    }

    matches = B_regex_via.match(data);
    if(matches.hasMatch()) {
        via = matches.captured(1);
    }

    matches = B_regex_if_modified_since.match(data);
    if(matches.hasMatch()) {
        ifModifiedSince = matches.captured(1);
    }

    matches = B_regex_if_none_match.match(data);
    if(matches.hasMatch()) {
        ifNoneMatch = matches.captured(1);
    }

    matches = B_regex_pragma.match(data);
    if(matches.hasMatch()) {
        pragma = matches.captured(1);
    }

}

void RequestHeaders::clear() {

    completeString.clear();

    requestMethod.clear();
    uri.clear();
    httpVersion.clear();
    host.clear();
    connection.clear();
    accept.clear();
    userAgent.clear();
    dnt.clear();
    referrer.clear();
    acceptEncoding.clear();
    acceptLanguage.clear();
    cookie.clear();
    xRequestedWith.clear();
    contentType.clear();
    contentLength.clear();
    proxyConnection.clear();
    acceptCharset.clear();
    userAgentCPU.clear();
    xForwardedFor.clear();
    cacheControl.clear();
    via.clear();
    ifModifiedSince.clear();
    ifNoneMatch.clear();
    pragma.clear();

}
