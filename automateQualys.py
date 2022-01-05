# import the required modules
import pandas
import matplotlib.pyplot as plt

# Open the CSV input file and read it into a dataframe.
dfQualysData = pandas.read_csv(
    "base.csv",  # Filename of the csv file to open
    header=3,  # Header descriptions are on row 4 (0 index)
    # nrows=8,
    usecols=[*range(0, 5), 6, 7, *range(10, 12), 15, 16, 31, 34],  # Only read in certain columns, rest are superfluous
    parse_dates=["First Detected", "Last Detected"]  # Set two columns to date format
)
# print("Number of rows in the file is", len(dfQualysData))

# For some reason, Qualys duplicates some vulnerabilities, so remove them
dfQualysData.drop_duplicates(["IP", "Tracking Method", "QID", "Port"], keep="first", inplace=True)
# print("Number of rows after removing initial duplicates", len(dfQualysData))

# Some vulnerabilities are duplicated by the two Tracking Methods - QAGENT or IP,
# remove the first occurrence of these as it doesn"t really matter which one.
dfQualysData.drop_duplicates(["IP", "QID", "Port"], keep="first", inplace=True)
# print("Number of rows after removing QAGENT/IP duplicates", len(dfQualysData))

# Loop through each row in the dataframe to finally end up with "clean" data.
for index, vulnerability in dfQualysData.iterrows():
    # We are only measured on vulnerabilities on Windows & Red Hat servers, i.e. not appliances, so remove then
    if "Windows" not in vulnerability["OS"]:  # Not Windows
        if "Red Hat" not in vulnerability["OS"]:  # Not Red Hat, so must be an appliance
            if "172.21.93.22" in vulnerability["IP"]:
                # One server does not have a Qualys agent installed so OS identification is wrong
                # (It"s actually Red Hat 6, so fix it)
                dfQualysData.loc[index, "OS"] = "Red Hat Enterprise Linux Server 6.10"
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
    if vulnerability["Severity"] >= 4:
        numSeverity4sand5s = numSeverity4sand5s + 1
        if (vulnerability["Last Detected"] - vulnerability["First Detected"]).days > 30:
            numKPI30vulnerabilities = numKPI30vulnerabilities + 1
            if (vulnerability["Last Detected"] - vulnerability["First Detected"]).days > 60:
                # Be efficient: only check those we already know are > 30 days old
                numKPI60vulnerabilities = numKPI60vulnerabilities + 1

# print(numSeverity4sand5s)
# print(dfQualysData["Severity"].value_counts())

# print(numKPI30vulnerabilities)
# print(numKPI60vulnerabilities)
print("Severity 4 & 5 vulnerabilities older than 30 days:", numKPI30vulnerabilities, "- average per server:",
      round(numKPI30vulnerabilities / numUniqueIPs, 2))
print("Severity 4 & 5 vulnerabilities older than 60 days:", numKPI60vulnerabilities, "- average per server:",
      round(numKPI60vulnerabilities / numUniqueIPs, 2))

# Assign each vulnerability to an owner. By default every vulnerability is the responsibility of the server owner.
# Add a column (Owner) and set every cell in that Column to "Server Owner.
dfQualysData["Owner"] = "Server Owner"
for index, vulnerability in dfQualysData.iterrows():
    vulnerability["Owner"] = "Server Owner"
    # Check if NetBIOS is blank first
    # https://stackoverflow.com/questions/42921854/how-to-check-if-a-particular-cell-in-pandas-dataframe-isnull
    # Anywhere the NetBIOS column contains CTX, SPS or DC, responsibility lies with Global Ops.
    if not pandas.isnull(vulnerability["NetBIOS"]) and ("CTX" in vulnerability["NetBIOS"] or
                                                "SPS" in vulnerability["NetBIOS"] or "DC" in vulnerability["NetBIOS"]):
        vulnerability["Owner"] = "Global Ops"
    elif "Red Hat Enterprise Linux Server 5" in vulnerability["OS"] or "Windows Server 2008" in vulnerability["OS"]:
        # RHEL 5 & Windows 2008 are End of Life, all vulnerabilities are risk accepted.
        vulnerability["Owner"] = "Risk Accepted"
    elif "VMware Tools" in vulnerability["Title"] or "IBM Spectrum Protect" in vulnerability["Title"]:
        # VMware & IBM Spectrum Protect are owned by Global Ops
        vulnerability["Owner"] = "Global Ops"
    elif "Red Hat Update" in vulnerability["Title"] or ("Security Update" in vulnerability["Title"] and
                                                "Microsoft" in vulnerability["Title"]):
        # Red Hat & Microsoft Updates are managed by Platform Ops - note RHEL 5 is already assigned as Risk Accepted
        vulnerability["Owner"] = "Platform Ops"
    elif "Oracle" in vulnerability["Title"]:
        # Oracle vulnerabilities are owned by the DBA Team
        vulnerability["Owner"] = "DBA Team"
    # Update the dataframe.
    # https://thispointer.com/pandas-6-different-ways-to-iterate-over-rows-in-a-dataframe-update-while-iterating-row-by-row/#iterate-and-update
    dfQualysData.at[index, "Owner"] = vulnerability["Owner"]

# Plot a Pie chart of the owners
owner_data = dfQualysData["Owner"].value_counts()
owner_data.plot.pie(autopct='%1.1f%%')
plt.title("Vulnerabilities by Owner")
plt.ylabel("")
plt.show()

# Output our result to an Excel file for further manual processing if necessary
dfQualysData.to_excel("output.xlsx", index=False)
