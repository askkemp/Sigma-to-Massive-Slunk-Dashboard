#!/usr/bin/python
# Requires at least Python 3.9
__author__ = "Kemp Langhorne"
__copyright__ = "Copyright (C) 2023 AskKemp.com"
__license__ = "agpl-3.0"
__version__ = "1.0"

from sigma.rule import SigmaRule # https://github.com/SigmaHQ/pySigma
from sigma.pipelines.sysmon import sysmon_pipeline # https://github.com/SigmaHQ/pySigma-pipeline-sysmon
from sigma.backends.splunk import SplunkBackend # https://github.com/SigmaHQ/pySigma-backend-splunk
from sigma.collection import SigmaCollection
import sigma.exceptions as sigma_exceptions
from datetime import date
from pathlib import Path
import xml.etree.cElementTree as ET
import logging

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

#
## CONFIGURE ME
#
sigma_rule_folder = "/sigma/rules/windows/" # parent folder that contains Sigma yaml rules.
prepend_splunk_search = "(index=* AND (sourcetype=XmlWinEventLog OR sourcetype=WinEventLog))" # set to "" if nothing is wanted
append_splunk_search = """| bin _time span=1d | stats values(index) values(sourcetype) dc(host) as UniqueHosts count as TotalLogs by _time |eval HITS=if(isnull(UniqueHosts), "no", "YES")""" # set to "" if nothing is wanted
dashboard_name = "Sigma to Massive Slunk Dashboard - Windows"
dashboard_description = "Conversion of all Windows Sigma rules to Splunk Search Processing Language"





# Determine files to parse
if Path(sigma_rule_folder).is_dir(): # True if folder
    sigma_files_gen = Path(sigma_rule_folder).glob('**/*.yml')  # type generator object - is recursive
    files_on_disk = [x for x in sigma_files_gen if x.is_file()] # type pathlib.PosixPath
    logging.debug(f'Loaded {len(files_on_disk)} yaml files from {sigma_rule_folder}')
else:
    raise FileNotFoundError(f'No folder exists at {sigma_rule_folder}. Edit CONFIGURE ME section of this script and specify path to Sigma rules folder.')

#
## Build Splunk Dashboard XML with converted SIGMA rules
#

# Static section
root = ET.Element("form", version="1.1")
root_label = ET.SubElement(root, "label").text = dashboard_name
root_description = ET.SubElement(root, "description").text = dashboard_description

fieldset = ET.SubElement(root, "fieldset", submitButton="true")
globalTimePicker = ET.SubElement(fieldset, "input", type="time", token="globalTimePicker")
globalTimePicker_label = ET.SubElement(globalTimePicker, "label")
globalTimePicker_default = ET.SubElement(globalTimePicker, "default")
globalTimePicker_default_earliest = ET.SubElement(globalTimePicker_default, "earliest").text = "-24h@h"
globalTimePicker_default_latest = ET.SubElement(globalTimePicker_default, "latest").text = "now"
text_input = ET.SubElement(fieldset, "input", type="text", token="user_input_field_host")
text_input_label = ET.SubElement(text_input, "label").text = "Added to all searches like: host=<value>"
text_input_default = ET.SubElement(text_input, "default").text = "*"

# HTML
html_row = ET.SubElement(root, "row")
html= ET.SubElement(html_row, "html")
html_h1 = ET.SubElement(html, "h1").text="Sigma to Massive Slunk Dashboard"
html_ul = ET.SubElement(html, "ul")
html_li1 = ET.SubElement(html_ul, "li").text="This dashboard is generated the conversion too located at https://github.com/askkemp/Sigma-to-Massive-Slunk-Dashboard/ which converts all Windows Sigma rules to Splunk Search Processing Language. The Python script can be configured to change prepended and appended SPL. For example, if a specific index(s) or sourcetype(s) are desired."
html_li2 = ET.SubElement(html_ul, "li").text="Each search waits on the previous to finish. In other words, it runs serial."
html_li3 = ET.SubElement(html_ul, "li").text="The user input field with description \"Added to all searches like: host=<value>\" is simply a way to force a specific hostname on all searches which runs against the host field. If a search against all hosts is desired, then simply put a \"*\" in the field."
html_li4 = ET.SubElement(html_ul, "li").text="Dashboard generation date: " + str(date.today())
html_li5 = ET.SubElement(html_ul, "li").text="Number of rules loaded into conversion script: " + str(len(files_on_disk))

# Rule panels
row = ET.SubElement(root, "row")
panel = ET.SubElement(row, "panel")
panel_title = ET.SubElement(panel, "title").text = "Windows"

# Sigma setup
pipeline = sysmon_pipeline()
backend = SplunkBackend(pipeline)

# Dynamic section
fail_conversion_counter = 0 # tracks how many Sigma rules execpted which means they did not convert
symon_rule_counter = 0 # rule category
stock_windows_rule_counter = 0 # rule category
undefined_rule_counter = 0 # rule category
search_counter = 0 # used to force each search to wait on the one before it to finish
for sigma_file in files_on_disk:
    #logging.debug(f'Processing {sigma_file}')
    with sigma_file.open() as f:
        rule_file_name = sigma_file.stem
        sigma_obj = SigmaCollection.from_yaml(f)
        rule_name = sigma_obj.rules[0].title

        # It seems Sysmon rules have a logsource category and stock Windows channels have a logsource service
        if sigma_obj.rules[0].logsource.category:
            rule_type="Sysmon"
            symon_rule_counter = symon_rule_counter + 1
        elif sigma_obj.rules[0].logsource.service:
            rule_type="Stock Windows"
            stock_windows_rule_counter = stock_windows_rule_counter + 1
        else:
            rule_type="undefined"
            logging.error(f'undefined logsource: {sigma_file}')
            undefined_rule_counter = undefined_rule_counter + 1

        try:
            converted_query = backend.convert(sigma_obj)[0] # should only be one
        except sigma_exceptions.SigmaConditionError as e:
            logging.error(f'The following exception occured when processing {sigma_file}: {e}')
            fail_conversion_counter = fail_conversion_counter + 1
            continue
        except sigma_exceptions.SigmaFeatureNotSupportedByBackendError as e:
            logging.error(f'The following exception occured when processing {sigma_file}: {e}')
            fail_conversion_counter = fail_conversion_counter + 1
            continue

        # build dashboard xml for each yaml
        table = ET.SubElement(panel, "table")
        table_title = ET.SubElement(table, "title").text = rule_type + " | " + rule_file_name + " | " + rule_name

        # Set done token. The very first search depends on no previous search
        if search_counter == 0: # i.e. it is the first table in the dashboard
            search = ET.SubElement(table, "search")
            status_done = ET.SubElement(search, "done")
            depends_on_marker = ET.SubElement(status_done, "set", token="searchNum_"+str(search_counter)).text = "done"
            search_counter = search_counter + 1
        else:
            search = ET.SubElement(table, "search", depends=f'$searchNum_{search_counter-1}$')
            status_done = ET.SubElement(search, "done")
            depends_on_marker = ET.SubElement(status_done, "set", token="searchNum_"+str(search_counter)).text = "done"
            search_counter = search_counter + 1

        search_query = ET.SubElement(search, "query").text = prepend_splunk_search + " host=$user_input_field_host$ " + converted_query + " " + append_splunk_search
        search_earliest = ET.SubElement(search, "earliest").text = "$globalTimePicker.earliest$"
        search_latest = ET.SubElement(search, "latest").text = "$globalTimePicker.latest$"
        option_drilldown = ET.SubElement(table, "option", name="drilldown").text = "none"
        option_drilldown = ET.SubElement(table, "option", name="refresh.display").text = "progressbar"

# Added information to top HTML section of dashboard
html_li6 = ET.SubElement(html_ul, "li").text="Number of rules failing to convert: " + str(fail_conversion_counter) + " (see Python script debug error output)"
html_li7 = ET.SubElement(html_ul, "li").text="Total number of rules converted: " + str(search_counter)
html_li8 = ET.SubElement(html_ul, "li").text="|---- Sysmon: " + str(symon_rule_counter)
html_li9 = ET.SubElement(html_ul, "li").text="|---- Stock Windows channels: " + str(stock_windows_rule_counter)
html_li10 = ET.SubElement(html_ul, "li").text="|---- Unknown: " + str(undefined_rule_counter)


# Requires Python 3.9 for intent function
tree = ET.ElementTree(root)
ET.indent(tree, space="\t", level=0)

# ET.dump(tree) # dump to screen
logging.info("Writting dashboard.xml")
tree.write("dashboard.xml") # save to disk
