#!/usr/bin/env python
#
# This script is designed to read an exported Sysmon config (using 
# "Sysmon.exe -c") and convert it back into a valid XML file that can be used 
# to re-install Sysmon.
#
# Note: Some information from the original config is not included in the 
# exported file and is therefore impossible to reconstruct.
# Examples include:
#   - Comments
#   - Rule names
# 
# IMPORTANT: As of 2019-06-12, there is a bug with Sysmon where it will only 
# dump the first onmatch collection within a rulegroup (i.e., per event type)
# For instance, the SwiftOnSecurity config has both 'onmatch="include"' and 
# 'onmatch="exclude"' groups for the FileCreateTime event, but the dumped 
# Sysmon config only lists the 'onmatch: include' rules.
#
# Disclaimer:
# While it is generally frowned upon (including by me) to hand code XML
# rather than using a library, this application was simple enough I didn't 
# want to add the extra hassle (or dependency) of an additional library.
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#==============================================================================


import re
import sys
import os

# Matches an event type header that precedes a collection of associated rules
EVENT_PATT = re.compile(" - (?P<event_type>.*?)\s*onmatch: (?P<match_condition>.*?)\s{3,}combine rules using '(?P<operator>.*)'")

# Matches an individual rule
RULE_PATT = re.compile("\t(?P<field>.*?)\s*filter: (?P<filter>.*?)\s{3,}value: '(?P<value>.*)'")



def write_header(output_file, header_info):
  with open(output_file, 'w') as out_file:
    out_file.writelines('<Sysmon schemaversion="4.21">\n')
    out_file.writelines('\t<HashAlgorithms>%s</HashAlgorithms>\n' % header_info['algorithms'].lower())
    
    if header_info['check_revocation']:
      out_file.writelines('\t<CheckRevocation/>\n')
    
    out_file.writelines('\t<EventFiltering>\n')



def write_rule_group(output_file, rule_config, rule_group):
  with open(output_file, 'a') as out_file:
    out_file.writelines('\t<RuleGroup name="" groupRelation="%s">\n' % rule_config['operator'].lower())
    out_file.writelines('\t\t<%s onmatch="%s">\n' % (rule_config['event_type'], rule_config['match_condition']))
    
    for rule in rule_group:
      out_file.writelines('\t\t\t<{0} condition="{1}">{2}</{0}>\n'.format(rule['field'], rule['filter'], rule['value']))

    out_file.writelines('\t\t</%s>\n' % rule_config['event_type'])
    out_file.writelines('\t</RuleGroup>\n\n')



def write_footer(output_file):
  with open(output_file, 'a') as out_file:
    out_file.writelines('\t</EventFiltering>\n')
    out_file.writelines('</Sysmon>')



def parse_file(input_file):
  output_file = os.path.splitext(input_file)[0] + '.xml'
  rule_group = []
  rule_config = None
  header_written = False
  
  header_info = {
    'check_revocation': False
  }
  
  with open(input_file, 'r') as in_file:
    for line in in_file.readlines():
      # The following operations are ordered by their likelihood of occurence 
      # (rules more frequently than event type headers, etc.) to minimize 
      # unnecessary checks for a minor performance improvement
      
      data = RULE_PATT.match(line)
      
      if data is not None:
        # Line is an event rule
        rule_group.append(data.groupdict())
      else:
        data = EVENT_PATT.match(line)
      
        if data is not None:
          # Line is a new event type header
          if not header_written:
            # First event type encounter; write the header
            write_header(output_file, header_info)
            header_written = True
          
          # Write out existing rule_group and re-initalize the rule list
          if rule_config is not None:
            write_rule_group(output_file, rule_config, rule_group)
          
          rule_group = []
          rule_config = data.groupdict()
          
        elif 'HashingAlgorithms:' in line:
          header_info['algorithms'] = line.split(':')[1].strip()
        elif 'CRL checking:' in line:
          header_info['check_revocation'] = 'enabled' in line
    
    write_footer(output_file)



def main():
  if len(sys.argv) == 2:
    input_file = sys.argv[1]
    parse_file(input_file)
  else:
    print('USAGE: %s <path to sysmon config export>' % sys.argv[0])


main()