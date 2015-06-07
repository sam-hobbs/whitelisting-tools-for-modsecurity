bin_PROGRAMS = auditlog2db
auditlog2db_SOURCES = main.cpp prompt_inputs.cpp headerlines.cpp logchop.cpp help.cpp get_unordered_map.cpp get_unordered_map.h headerlines.h help.h logchop.h prompt_inputs.h

auditlog2db_LDADD = $(BOOST_REGEX_LIB) $(BOOST_FILESYSTEM_LIB) $(BOOST_SYSTEM_LIB)

AM_CXXFLAGS = $(BOOST_CPPFLAGS)
AM_LDFLAGS = $(BOOST_LDFLAGS)