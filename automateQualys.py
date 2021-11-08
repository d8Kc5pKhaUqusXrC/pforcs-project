# import the pandas module
import pandas

# Open the CSV input file and read it into a dataframe.
dfQualysData = pandas.read_csv(
    'base.csv',  # Filename of the csv file to open
    header=3,  # Header descriptions are on row 4 (0 index)
    # nrows=8,
    usecols=[*range(0, 5), 6, 7, *range(10, 12), 15, 16, 31, 34],  # Only read in certain columns, rest are superfluous
    parse_dates=['First Detected', 'Last Detected']  # Set two columns to date format
)
# print("Number of rows in the file is", len(dfQualysData))

# For some reason, Qualys duplicates some vulnerabilities, so remove them
dfQualysData.drop_duplicates(['IP', 'Tracking Method', 'QID', 'Port'], keep='first', inplace=True)
# print("Number of rows after removing initial duplicates", len(dfQualysData))

# Some vulnerabilities are duplicated by the two Tracking Methods - QAGENT or IP,
# remove the first occurrence of these as it doesn't really matter which one.
dfQualysData.drop_duplicates(['IP', 'QID', 'Port'], keep='first', inplace=True)
# print("Number of rows after removing QAGENT/IP duplicates", len(dfQualysData))

# Loop through each row in the dataframe to finally end up with "clean" data.
for index, vulnerability in dfQualysData.iterrows():
    # We are only measured on vulnerabilities on Windows & Red Hat servers, i.e. not appliances, so remove then
    if "Windows" not in vulnerability['OS']:  # Not Windows
        if "Red Hat" not in vulnerability['OS']:  # Not Red Hat, so must be an appliance
            if "172.21.93.22" in vulnerability['IP']:
                # One server does not have a Qualys agent installed so OS identification is wrong
                # (It's actually Red Hat 6, so fix it)
                dfQualysData.loc[index, 'OS'] = "Red Hat Enterprise Linux Server 6.10"
            else:
                dfQualysData.drop(index, inplace=True)
# print("Number of rows after removing non-Windows / Red Hat OSs", len(dfQualysData))

# The KPIs for vulnerabilities is set to an average of less than 7 Severity 4s & 5s per server
# which are older then 30 days and 60 days

# Calculate the total number of unique IPs, i.e. the number of servers
numUniqueIPs = dfQualysData.IP.nunique()

# Calculate the total number of severity 4 & 5 vulnerabilities (useful later perhaps)
# as well as those which are older than 30 days (where "Last Detected" - "First Detected" is > 30 days)
numSeverity4sand5s = 0
numKPI30vulnerabilities = 0
numKPI60vulnerabilities = 0
for index, vulnerability in dfQualysData.iterrows():
    if vulnerability['Severity'] >= 4:
        numSeverity4sand5s = numSeverity4sand5s + 1
        if (vulnerability['Last Detected'] - vulnerability['First Detected']).days > 30:
            numKPI30vulnerabilities = numKPI30vulnerabilities + 1
            if (vulnerability['Last Detected'] - vulnerability['First Detected']).days > 60:
                # Be efficient: only check those we already know are > 30 days old
                numKPI60vulnerabilities = numKPI60vulnerabilities + 1

# print(numSeverity4sand5s)
# print(dfQualysData['Severity'].value_counts())

# print(numKPI30vulnerabilities)
# print(numKPI60vulnerabilities)
print("Severity 4 & 5 vulnerabilities older than 30 days:", numKPI30vulnerabilities, "- average per server:",
      round(numKPI30vulnerabilities / numUniqueIPs, 2))
print("Severity 4 & 5 vulnerabilities older than 60 days:", numKPI60vulnerabilities, "- average per server:",
      round(numKPI60vulnerabilities / numUniqueIPs, 2))


# dfQualysData.to_excel('output.xlsx', index=False)
