# pforcs-project

A project by Mark Brislane in part fulfillment of the Programming for Cybersecurity module as
part of the Postgraduate Certificate in Cybersecuity Operations in GMIT. This project automates
what the author does on a monthly basis while working with a Qualys report CSV file. The estimated
time saved as a result of this project is approx. half a day.

## Installation
None required

## Inputs
The current month's Qualys CSV report, named as base.csv, in the same directory as automateQualys.py

## Usage

```python
automateQualys.py
```

## Outputs
* Console: KPIs showing the ratio by server of vulnerabilities of severity 4 & 5 older than 30 days & 60 days respectively
* output.xlsx - a file which may be further processed manually
* A pie chart showing the number of Vulnerabilities by Owner

## References
I have included the references inline in the code