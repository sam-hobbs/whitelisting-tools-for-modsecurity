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


#include "userdefinedheaderpart.h"

UserDefinedHeaderPart::UserDefinedHeaderPart(QString user_name, QString regexString) : name(user_name), regex(regexString,QRegularExpression::MultilineOption) {
    if (!regex.isValid())
        throw QString("Error in regular expression pattern supplied: ") + regex.pattern() + ", " + regex.errorString() + " at position " + QString::number(regex.patternErrorOffset()+1);
}

