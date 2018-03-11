# AWS IAM Security Check

Python script for checking security in IAM across multiuple AWS accounts/profiles which involves:
1. Checks for multi-factor authentication
2. Checks for old access keys (greater than 90 days)
3. Checks for expired password (greater than 90 days)
4. Checks for users that never logged in after account creation
5. Checks for IAM accounts that have not been used for 90 day
6. Checks for IAM accounts with console access but have never logged in
7. Checks for disabled accounts

Pre-requisite:
1. AWS account with console access (Access ID & Key) and appropriate permissions.
2. AWS-CLI installed & configured to use the Access ID & Key.
3. Python 2.7
4. Boto library (pip install boto)

Environment: Linux, OSX

Usage: python aws_iam_security.py

Note: Uncomment lines in main function to send mail. Dont forget to write the value for company_name mentioned in the start of the script.
