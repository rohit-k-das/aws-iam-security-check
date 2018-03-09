import datetime
import time
import smtplib
import base64
import getpass
import os
from dateutil import parser
from boto import iam
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

#Username convention: first_name.last_name. If its something differnet like first_letter.lastname,etc. fill out the dirty name mapping dictionary below.
#ONLY FILL THIS OUT, IF YOU ARE GOING TO USE THE MAILING FUNCTION BELOW
Dirty_name_mapping = {

        }

mfa_non_compliant = {}
expired_password_user = {}
never_logged_in = {}
user_key_list = {}
users_not_accessed_account = {}
account_disabled = {}
never_accessed_account = {}
sender_email = {} #To be used to send mails

# To generate credential report from AWS
def generate_report(id):
    conn=iam.connection.IAMConnection(profile_name=id)
    try:
        conn.generate_credential_report()
        time.sleep(3)
    except:
        print "Report already created."

    cred_report = conn.get_credential_report()
    report = base64.b64decode(cred_report['get_credential_report_response']['get_credential_report_result']['content']).strip('\r').split('\n')

    return report,conn

def execute(id):
    report,conn = generate_report(id)
    number_of_rows = len(report) - 1
    key1_unused = []
    key2_unused = []

    # Timelimit of 90 days
    timeLimit = datetime.datetime.now() - datetime.timedelta(days=90)

    # Each row in the cred report is a user
    for i in range(1,number_of_rows):
        # Decipher the credential report from AWS
        row = report[i].split(',')
        user = row[0]
        mfa_status = row[7]
   	password_enabled = row[3]
        password_last_changed = row[5]
        password_last_used = row[4]
        key1_status = row[8]
        key1_last_used = row[10]
        key2_status = row[13]
        key2_last_used = row[15]
        last_activity = 'place_holder'

        # Map users to get better naming sense
        if "@" in user:
            username = user.split('@')[0].lower()
        else:
            username = user.lower()
        if username in Dirty_name_mapping:
            username =  Dirty_name_mapping[username].lower()

        # Check if root account has access keys
        if user == '<root_account>':
            if key1_status == 'true' or key2_status == 'true':
                print "ALERT: ROOT ACCOUNT FOR AWS ACCOUNT " + id.upper()  + " HAS ACCESS KEYS"
                if key1_last_used != 'N/A':
                    print key1_last_used
                if key2_last_used != 'N/A':
                    print key2_last_used
                print

        # Complinace check for AWS Accounts
        if user != '<root_account>':
        # USER WITH ACCESS KEY OLDER THAN 90 DAYS: Parsing based on information from credential report
            try:
                accessKeys=conn.get_all_access_keys(user)
                for key in accessKeys['list_access_keys_response']['list_access_keys_result']['access_key_metadata']:
                    if key['status']=='Active':
                        if parser.parse(key['create_date']).date() <= timeLimit.date():
                            if username not in user_key_list:
                                user_key_list[username] = {}
                            if id not in user_key_list[username]:
                                user_key_list[username][id] = []
                            user_key_list[username][id].append(key['access_key_id'])
            except:
                print user + " not present as credentials file doesn't match current IAM status."

    	    # MFA_NON-COMPLIANT: Parsing based on information from credential report
    	    if mfa_status == 'false' and password_enabled == 'true':
                if username not in mfa_non_compliant:
                    mfa_non_compliant[username] = []
                mfa_non_compliant[username].append(id)

            # Password Age greater than 90 days: Parsing based on information from credential report
            if password_enabled == 'true':
                if password_last_changed != 'N/A':
                    if parser.parse(password_last_changed).date() < timeLimit.date():
                        if username not in expired_password_user:
                            expired_password_user[username] = []
                        expired_password_user[username].append(id)
                else:
                    if user not in never_logged_in:
                        never_logged_in[username] = []
                    never_logged_in[username].append(id)

            # Last Activity greater than 90 days: Parsing based on information from credential report
            if password_enabled == 'true':
                if password_last_used != 'N/A' and password_last_used != 'no_information':
                    last_activity = password_last_used
                else:
                    if username not in never_logged_in:
                        never_logged_in[username] = []
                    never_logged_in[username].append(id)

            if key1_status == 'true':
                if key1_last_used != 'N/A':
                    if last_activity == 'place_holder' or parser.parse(last_activity).date() < parser.parse(key1_last_used).date():
                        last_activity = key1_last_used
                else:
                    key1_unused.append(user)

            if key2_status == 'true':
                if key2_last_used != 'N/A':
                    if last_activity == 'place_holder' or parser.parse(last_activity).date() < parser.parse(key2_last_used).date():
                        last_activity = key2_last_used
                else:
                    key2_unused.append(user)

            if last_activity != 'place_holder':
                if parser.parse(last_activity).date() < timeLimit.date():
                    if username not in users_not_accessed_account:
                        users_not_accessed_account[username] = []
                    days = str(datetime.datetime.utcnow().date() - parser.parse(last_activity).date()).split(',')[0]
                    users_not_accessed_account[username].append(id + ": " + days)

            # Disabled Accounts: Parsing based on information from credential report
            if password_enabled =='false':
                if key1_status == 'false' and key2_status == 'false':
                    if user not in account_disabled:
                        account_disabled[username] = []
                    account_disabled[username].append(id)
            else:
                if password_last_used == 'N/A' or password_last_used == 'no_information':
                    if key1_status == 'false' and key2_status == 'false':
        	        if username not in never_accessed_account:
                            never_accessed_account[username] = []
                        never_accessed_account[username].append(id)
    return

#Send mail to MFA non-compliant people
def mfa_email(user,accounts,company_name):
    #Assumption: Mail format is first_name.last_name@company_name.com. You would need to fill out the Dirty_name_mapping for users that don't follow the username naming sense of first_name.last_name
    if "." not in user:
        return True
    else:
        user = user + "@" + company_name + ".com"

    #Retain sender email and password to send mail
    if not sender_email:
        if len(sender_email) == 1:
            fromaddr = list(sender_email.keys())[0]
            password = sender_email[fromaddr]
        else:
            print "ERROR: More than 1 mail address and password mapping present in sender_email dictionary"
            print "Removing elements from sender_email"
            fromaddr = raw_input("Enter your email address: ")
            password = getpass.getpass()
            sender_email[fromaddr] = password
    else:
        fromaddr = raw_input("Enter your email address: ")
        password = getpass.getpass()
        sender_email[fromaddr] = password

    toaddr = user
    Subject = "AWS MFA Non-Compliant"
    header = "From:" + fromaddr + "\n" + "To:" + toaddr + "\n" + "Subject:" + Subject + "\n"
    msg = "\nDear " + user.split('.')[0].capitalize() + ",\n\n" \
        + "Your IAM account has Managment console access but MFA is disabled.\nPlease enable your MFA for the following accounts via direct login to those accounts: " + str(accounts) + ". " + "\n" \
        + "If you are not using the account, please email me so that i can disable the account.\n\n" \
        + "PS: If you have received this mail before please check the AWS account(s) mentioned in the mail. You might have got a repeat/similar mail but with different AWS account(s) id because the username in AWS accounts didn't follow a naming standard. If this mail is the same mail as the previous mail including the same AWS account mentioned in the previous mail, I apologize. \n\n" \
        + "Thanks,\n" +user.split('.')[0].capitalize()

    Body = header + msg
    s = smtplib.SMTP('smtp-mail.outlook.com',587)
    s.starttls()
    s.login(fromaddr,passwd)
    try:
        s.sendmail(fromaddr, toaddr, Body)
        s.quit()
        return True
    except Exception, e:
        if "Connection unexpectedly closed" in e.message:
            s.quit()
            return False

#Send mail to people whose access keys have been unchanged for more than 90 days
def access_key_email(user,accounts,company_name):
    #Assumption: Mail format is first_name.last_name@company_name.com. You would need to fill out the Dirty_name_mapping for users that don't follow the username naming sense of first_name.last_name
    if "." not in user:
        return True
    else:
        user =  user + "@" + company_name + ".com"

    #Retain sender email and password to send mail
    if sender_email:
        if len(sender_email) == 1:
            fromaddr = list(sender_email.keys())[0]
            password = sender_email[fromaddr]
        else:
            print "ERROR: More than 1 mail address and password mapping present in sender_email dictionary"
            print "Removing elements from sender_email"
            fromaddr = raw_input("Enter your email address: ")
            password = getpass.getpass()
            sender_email[fromaddr] = password
    else:
        fromaddr = raw_input("Enter your email address: ")
        password = getpass.getpass()
        sender_email[fromaddr] = password

    toaddr = user
    Subject = "Change AWS Access Key"
    header = "From:" + fromaddr + "\n" + "To:" + toaddr + "\n" + "Subject:" + Subject + "\n"
    msg = "\nDear " + user.split('.')[0].capitalize() + ",\n\n" \
    + "Your IAM account's access key for the below accounts has lived for more than 90 days.\nPlease destroy it and create a new one via direct login or the attached bash script 'rotate_aws_keys.txt' (Need to change the extention to sh and make it executable). If you are not using the account, please email me so that i can disable it.\n\n" + "Accounts:\n"
    for counter,account in enumerate(accounts):
        msg = msg + "\t" + str(counter + 1) + ". " + account.capitalize() + ": " + str(", ".join(accounts[account])) + "\n"

    Body = msg + "\n" + "Thanks,\n" + user.split('.')[0].capitalize()

    msg = MIMEMultipart()
    msg['From'] = fromaddr
    msg['To'] = toaddr
    msg['CC'] = ""
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = Subject
    msg.attach(MIMEText(Body))
    with open("rotate_aws_keys.txt", "rb") as fil:
        part = MIMEApplication(
            fil.read(),
            Name="rotate_aws_keys.txt"
            )
    part['Content-Disposition'] = 'attachment; filename="rotate_aws_keys.txt"'
    msg.attach(part)

    s = smtplib.SMTP('smtp-mail.outlook.com',587)
    s.starttls()
    s.login(fromaddr,passwd)
    try:
        s.sendmail(fromaddr, toaddr, msg.as_string())
        s.quit()
        return True
    except Exception, e:
        if "Connection unexpectedly closed" in e.message:
            s.quit()
            return False

#To do
#1. Send mail to never_logged_in users
#2. Send mail to password expired users
#3. Send mail to accounts that were created but do not have password or access_keys

#Get all AWS account profiles from aws credentials file
def get_profiles(cred_file):
    profiles = []
    try:
        with open(cred_file) as f:
            for line in f.readlines():
                if '[' in line:
                    line = line.replace('[','').replace(']','').strip('\n')
                    profiles.append(line)
    except Exception,e:
        print "Error:" +str(e)
    return profiles

#Get default home dir of user executing the script
def get_home_dir():
    current_user_id = os.getuid()
    with  open('/etc/passwd') as passwd_file:
        for line in passwd_file.readlines():
            field = line.split(':')
            if current_user_id == int(field[2]):
                home_dir = field[5]
    return home_dir

def main():
    home_dir = get_home_dir()
    cred_file_path = home_dir + '/.aws/credentials'

    #Checks if aws credential file exists and get all AWS account profiles
    if os.path.exists(cred_file_path):
        profiles = get_profiles(cred_file_path)
    else:
        cred_file_path = raw_input("Please enter credential files absolute path: ")
        profiles = get_profiles(cred_file_path)

    print '\t\t\t\t\t\t\t AWS COMPLIANCE REPORT'
    print '\t\t\t\t\t\t\t-----------------------\n\n'
    for id in profiles:
        execute(id)

    print "MFA_NON-COMPLIANT"
    print "-----------------"
    for counter,user in enumerate(mfa_non_compliant):
        print str(counter+1) +". " + user + ":" + str(mfa_non_compliant[user])
        #Uncomment to send mail
        #if not mfa_email(user,mfa_non_compliant[user]):
            #mfa_email(user,mfa_non_compliant[user])
    print

    print "Access Key NON-COMPLIANT"
    print "------------------------"
    for main_counter,user in enumerate(user_key_list):
        print str(main_counter+1) + ". " + user + ":"
        for counter,id in enumerate(user_key_list[user]):
            print  "\t" + str(counter+1) + ". " + id + ": " + str(user_key_list[user][id])
        #Uncomment to send mail
        #if not access_key_email(user,user_key_list[user]):
        #   access_key_email(user,user_key_list[user])
    print

    print "Password Expired"
    print "----------------"
    for counter,user in enumerate(expired_password_user):
        print str(counter+1) + ". " + user + ":" + str(expired_password_user[user])
    print

    print "Disabled Accounts"
    print "-----------------"
    for counter,user in enumerate(account_disabled):
        print str(counter+1) + ". " + user + ":" + str(account_disabled[user])
    print

    print "Not accessed account since 90 days"
    print "----------------------------------"
    for counter,user in enumerate(users_not_accessed_account):
        print str(counter+1) + ". " + user + ":" + str(users_not_accessed_account[user])
    print

    print "UI Access BUT Never Logged In"
    print "-----------------------------"
    for counter,user in enumerate(never_logged_in):
        print str(counter+1) + ". " + user + ":" + str(never_logged_in[user])
    print

    print "Never Accessed Account"
    print "----------------------"
    for counter,user in enumerate(never_accessed_account):
        print str(counter+1) + ". " + user + ":" + str(never_accessed_account[user])
    print

if __name__ == '__main__':
    main()

