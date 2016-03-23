# project file for ModSecurity Whitelister

TEMPLATE = app
TARGET = modsecurity-whitelister
QT += core sql
INCLUDEPATH += . src

# Input
CONFIG += c++11

HEADERS +=  src/auditlogdatabase.h \
    src/auditlogrecord.h

SOURCES +=  src/main.cpp \
    src/auditlogdatabase.cpp \
    src/auditlogrecord.cpp

