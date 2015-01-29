#
#   This file is part of auditlog2db.
#
#   auditlog2db is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   auditlog2db is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with auditlog2db.  If not, see <http://www.gnu.org/licenses/>.
#

auditlog2db : headerlines_vector_pair.o main.o prompt_inputs.o logchop.o
	g++ -o auditlog2db prompt_inputs.o headerlines_vector_pair.o main.o logchop.o -lsqlite3 -lboost_regex

prompt_inputs.o : prompt_inputs.cpp prompt_inputs.h
	g++ -c -std=c++0x prompt_inputs.cpp
	
logchop.o : logchop.cpp logchop.h
	g++ -c -std=c++0x logchop.cpp

headerlines_vector_pair.o : headerlines_vector_pair.cpp headerlines_vector_pair.h
	g++ -c -std=c++0x headerlines_vector_pair.cpp

main.o : main.cpp
	g++ -c -std=c++0x main.cpp

# "clean" option for housekeeping. -f is force option (no prompt, ignore nonexistent files)
# clean defined as .PHONY in case there is a file named "clean" in the directory for some reason
.PHONY: clean
clean:
	-rm -f modsecurity
	-rm -f main.o
	-rm -f headerlines.o
	-rm -f prompt_inputs.o
	-rm -f logchop.o
	-rm -f headerlines_vector_pair.o
