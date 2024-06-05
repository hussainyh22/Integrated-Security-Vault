#Version 4.5 [01-Jul-2022]
# ************************************************************************
# *______________________________________________________________________*
# * Contact person  : Aditya , Prathamesh , Hussain                      *
# * Developer       : Aditya , Prathamesh , Hussain                      *
# * Title (english) : Integrated Security Vault                          *
# * Version         : 4.5                                                *
# * Related info    : Final Version                                      *
# *______________________________________________________________________*
# * DESCRIPTION : Menu Driven Program of a password manager              *
# *                                                                      *
# *                                                                      *
# ************************************************************************
# * Date     : 01.07.2022                  Type    : Change              *
# * Code     :                             Change  :                     *
# * Developer:                             Task No :                     *
# * Modification:                                                        *
# * Login master password storage                                        *
# ************************************************************************


import pandas as pd
import csv
from   cryptography.fernet import Fernet
import sqlite3 as sql
import datetime
#import sys

#Display options
pd.options.display.max_columns = None
pd.options.display.width = None


#**** Directory File path Setting
FilePath = "/Users/adit/PycharmProjects/pythonProject/Source_Code/"

#******* Function for Login User Validation
def Loginusercheck(conn,tbl,userid):
    cursor = conn.cursor()
    sqlite_Create_Table_query_U = "CREATE TABLE IF NOT EXISTS " + tbl + " (User_ID text NOT NULL,encPhrase TEXT NOT NULL,  Timestamp DATETIME NOT NULL )"
    cursor.execute(sqlite_Create_Table_query_U)


    df_ret = pd.read_sql_query("SELECT * from "+tbl, conn)
    Count_records = df_ret[(df_ret["User_ID"].str.upper() == userid.upper()) ]["User_ID"].count().squeeze()
    if Count_records >0:
        userid_exists = 1
    else:
        userid_exists = 0
    return userid_exists
#********


#******* Function for MasterPassword Validation
def MasterPass_Check(conn,tbl,user,password ):
    df_ret = pd.read_sql_query("SELECT * from "+tbl, conn)
    df_ret["Decrypted_Passphrase"] = df_ret['encPhrase'].astype(str).apply(lambda x1: str(f.decrypt(bytes(x1[2:-1], 'utf8'))))
    df_ret["Decrypted_Passphrase"] = df_ret["Decrypted_Passphrase"].astype(str).replace(to_replace=r"^b'|^b'", value='', regex=True)  # has a faltu problem of b" to check
    df_ret["Decrypted_Passphrase"] = df_ret["Decrypted_Passphrase"].astype(str).replace(to_replace=r'^b"', value='', regex=True)
    df_ret["Decrypted_Passphrase"] = df_ret["Decrypted_Passphrase"].astype(str).replace(to_replace=r'"$', value='', regex=True)
    df_ret["Decrypted_Passphrase"] = df_ret["Decrypted_Passphrase"].astype(str).replace(to_replace=r"'$", value='', regex=True)

    Count_records =df_ret[(df_ret["User_ID"].str.upper()== user.upper())  & (df_ret["Decrypted_Passphrase"].str.upper()== password.upper())]["User_ID"].count().squeeze()
    if Count_records >0:
        userpwd_exists = 1
    else:
        userpwd_exists = 0
    return userpwd_exists
#*************

#******* Function for Master Password storage
def signup(conn,tbl,user, password):
    cursor = conn.cursor()
    sqlite_Create_Table_query_U = "CREATE TABLE IF NOT EXISTS "+tbl+" (User_ID text NOT NULL,encPhrase TEXT NOT NULL,  Timestamp DATETIME NOT NULL )"
    cursor.execute(sqlite_Create_Table_query_U)
    Date_N = datetime.datetime.now().strftime("%Y-%m-%d").rstrip('0')
    encodedPwd = f.encrypt(password.encode())
    try:
        Str_insert  = "INSERT INTO "+ tbl + "(User_ID,  encPhrase,Timestamp) VALUES(?, ?, ?)"
        sqlite_insert_query = Str_insert
        cursor.execute(sqlite_insert_query, (user,encodedPwd,  Date_N ))
        cursor.close()
        sqliteConnection.commit()
        print("Record inserted successfully into User_Master table ", cursor.rowcount)
        sqliteConnection.close()
    except sql.Error as error:
        print("Failed to insert data into sqlite table", error)
    return


#******* Function for Retrieval of Data
def Ret_Pass(conn,tbl):
#    df_ret = pd.read_sql_query("SELECT * from PassMaster", conn)
    df_ret = pd.read_sql_query("SELECT * from "+tbl, conn)
    df_ret["Decrypted_Passphrase"] = df_ret['encPhrase'].astype(str).apply(lambda x1: str(f.decrypt(bytes(x1[2:-1], 'utf8'))))
    df_ret["Decrypted_Passphrase"] = df_ret["Decrypted_Passphrase"].astype(str).replace(to_replace=r"^b'|^b'", value='', regex=True)  # has a faltu problem of b" to check
    df_ret["Decrypted_Passphrase"] = df_ret["Decrypted_Passphrase"].astype(str).replace(to_replace=r'^b"', value='', regex=True)
    df_ret["Decrypted_Passphrase"] = df_ret["Decrypted_Passphrase"].astype(str).replace(to_replace=r'"$', value='', regex=True)
    df_ret["Decrypted_Passphrase"] = df_ret["Decrypted_Passphrase"].astype(str).replace(to_replace=r"'$", value='', regex=True)
    return df_ret

def Ret_Dictionary(conn, tbl):
    dict_ret = pd.read_sql_query("SELECT * from " + tbl, conn)
    dict_ret["Code"] = dict_ret['Code_E'].astype(str).apply(lambda x1: str(f.decrypt(bytes(x1[2:-1], 'utf8'))))
    dict_ret["Code"] = dict_ret["Code"].astype(str).replace(to_replace=r"^b'|^b'", value='', regex=True)
    dict_ret["Code"] = dict_ret["Code"].astype(str).replace(to_replace=r'^b"', value='', regex=True)
    dict_ret["Code"] = dict_ret["Code"].astype(str).replace(to_replace=r'"$', value='', regex=True)
    dict_ret["Code"] = dict_ret["Code"].astype(str).replace(to_replace=r"'$", value='', regex=True)
    dict_ret["Code"] = dict_ret["Code"].astype(int)

    dict_ret["Word"] = dict_ret['Word_E'].astype(str).apply(lambda x1: str(f.decrypt(bytes(x1[2:-1], 'utf8'))))
    dict_ret["Word"] = dict_ret["Word"].astype(str).replace(to_replace=r"^b'|^b'", value='', regex=True)
    dict_ret["Word"] = dict_ret["Word"].astype(str).replace(to_replace=r'^b"', value='', regex=True)
    dict_ret["Word"] = dict_ret["Word"].astype(str).replace(to_replace=r'"$', value='', regex=True)
    dict_ret["Word"] = dict_ret["Word"].astype(str).replace(to_replace=r"'$", value='', regex=True)
    return dict_ret



#******* Function for Insert  Data
def Insert_Pass (conn,tbl,Category_N, User_ID_N, Date_N, encPhrase):
    cursor = conn.cursor()
    sqlite_Create_Table_query_S = "CREATE TABLE IF NOT EXISTS "+tbl+" (Category text NOT NULL, User_ID text NOT NULL,  Timestamp DATETIME NOT NULL, encPhrase TEXT NOT NULL)"
    cursor.execute(sqlite_Create_Table_query_S)
    try:
        Str_insert  = "INSERT INTO "+ tbl + "(Category, User_ID, Timestamp, encPhrase) VALUES(?, ?, ?, ?)"
        sqlite_insert_query = Str_insert
        cursor.execute(sqlite_insert_query, (Category_N, User_ID_N, Date_N, encPhrase))
        cursor.close()
        sqliteConnection.commit()
        print("Record inserted successfully into PassMaster table ", cursor.rowcount)
        sqliteConnection.close()
    except sql.Error as error:
        print("Failed to insert data into sqlite table", error)
    return


#******* Function for Update  Data
def Update_Pass (conn,tbl,Category_N, User_ID_N, Date_N, encPhrase):
    cursor = conn.cursor()
    sqlite_Create_Table_query_S = "CREATE TABLE IF NOT EXISTS "+tbl+" (Category text NOT NULL, User_ID text NOT NULL,  Timestamp DATETIME NOT NULL, encPhrase TEXT NOT NULL)"
    cursor.execute(sqlite_Create_Table_query_S)

    try:
        Str_update  = "UPDATE " + tbl + " SET encPhrase = ?  WHERE Category = ? and User_ID =? and Timestamp=?"
        sqlite_Update_query = Str_update
        cursor.execute(sqlite_Update_query, (encPhrase, Category_N, User_ID_N, Date_N))
        cursor.close()
        sqliteConnection.commit()
        print("Record updated successfully into PassMaster table ", cursor.rowcount)
        sqliteConnection.close()
    except sql.Error as error:
        print("Failed to insert data into sqlite table", error)
    return



#@@@@@@ Encryption related block
with open('thekey.key', "rb") as mykey: #FilePath+
    key = mykey.read()
f = Fernet(key)


#************* ONLY FIRST TIME RUN [CODE BLOCK START] **********************
#One time Code for Encrypting Wordlist [not required for regular runs]

WordList  = pd.read_csv(FilePath+'Wordlist.txt', sep='\t', engine='python', quoting=csv.QUOTE_NONE, index_col=False, encoding='iso-8859-1', on_bad_lines ='warn')
WordList["Code"] = WordList["Code"].astype(str)
WordList['Code_E'] = WordList['Code'].astype(str).apply(lambda x1: f.encrypt(bytes(x1,'utf8')))
WordList['Code_2'] = WordList['Code_E'].astype(str).apply(lambda x1: str(f.decrypt(bytes(x1[2:-1],'utf8'))))
WordList['Code_3'] = WordList['Code_2'].astype(str).replace(to_replace=r"^b'|^b'", value='', regex=True)
WordList['Code_3'] = WordList['Code_3'].astype(str).replace(to_replace=r'^b"', value='', regex=True)
WordList['Code_3'] = WordList['Code_3'].astype(str).replace(to_replace=r'"$', value='', regex=True)
WordList['Code_3'] = WordList['Code_3'].astype(str).replace(to_replace=r"'$", value='', regex=True)

WordList['Word_E'] = WordList['Word'].astype(str).apply(lambda x1: f.encrypt(bytes(x1,'utf8')))
WordList['Word_2'] = WordList['Word_E'].astype(str).apply(lambda x1: str(f.decrypt(bytes(x1[2:-1],'utf8'))))
WordList['Word_3'] = WordList['Word_2'].astype(str).replace(to_replace=r"^b'|^b'", value='', regex=True)
WordList['Word_3'] = WordList['Word_3'].astype(str).replace(to_replace=r'^b"', value='', regex=True)
WordList['Word_3'] = WordList['Word_3'].astype(str).replace(to_replace=r'"$', value='', regex=True)
WordList['Word_3'] = WordList['Word_3'].astype(str).replace(to_replace=r"'$", value='', regex=True)

#Write an Encrypted Wordlist to Database [WordList_E = Encrypted]
sqliteConnection = sql.connect(FilePath + 'KJIT.db')
#WordList.to_sql('WordList', sqliteConnection,  if_exists='replace', index=False) - For validation only
WordList_E = WordList[['Code_E','Word_E']].copy()
WordList_E.to_sql('WordList_E', sqliteConnection,  if_exists='replace', index=False)
sqliteConnection.commit()
sqliteConnection.close()
#************* ONLY FIRST TIME RUN [CODE BLOCK END] **********************

# Login validation


login_name = input("\nPlease Enter your Login Id { Name } : ")
sqliteConnection = sql.connect(FilePath+'KJIT.db')
login_Validation = Loginusercheck(sqliteConnection,'User_Master',login_name)
if login_Validation>0 :
    # if name is found in directory then ask for Master password or generate a password first otherwise dont let the user into the while loop
    login_password = input("\nPlease Enter your Master-Password : ")
    #check for correct password
    check_password = MasterPass_Check(sqliteConnection,'User_Master', login_name, login_password)


    if check_password >0:

        print("\nLogin Successful.")
    else:
        print("\nPassword Incorrect, Exiting the program.")
        exit()
else:
    choice_Login = input ("\nDo you want to sign up? Type { yes or no } : ")
    if choice_Login.lower() == 'no':
        exit()
    elif choice_Login.lower() == 'yes':
        login_password = input("\nPlease Enter your Master Password.")
        signup(sqliteConnection, 'User_Master', login_name, login_password)
    else:
        exit()




#******************** Main Program Starts here

while True:

    n = input("\nHey there ! Please enter your choice to perform the desired operation \n\n1 Store an existing Password \n2 "
              "Generate a password/passphrase\n3 Retrieve a password\n4 Calculate the strength of the password\n5 Exit the program \n\nEnter : ")

    if n == '1':  # Store a password


        sqliteConnection = sql.connect(FilePath+'KJIT.db')
        Existing_PassMaster_1 = Ret_Pass(sqliteConnection,'PassMaster')

        print("Entered into choice 1 ")
        info                = str(input("Enter the category against which the password will be stored : "))

        Date_N = datetime.datetime.now().strftime("%Y-%m-%d").rstrip('0')
        Count_records =Existing_PassMaster_1[(Existing_PassMaster_1["User_ID"].str.upper()== login_name.upper())  & (Existing_PassMaster_1["Category"].str.upper()== info.upper())]["User_ID"].count().squeeze()

        if Count_records >0:
            response1 = input(
                "This Category of password already exists in our database. \nDo you want overwrite this ? {yes or no} ")
            if response1 == 'yes':
                #print("performs the function of overwriting the password though some code")
                category_password = str(input("Enter the password which needs to be  stored : "))
                category_password_E = f.encrypt(category_password.encode())
                sqliteConnection = sql.connect(FilePath + 'KJIT.db')
                Update_Pass(sqliteConnection, 'PassMaster', info.upper(), login_name.upper(), Date_N, category_password_E)

            elif response1 == 'no':
                print("Please Create a new category and re-enter. Choose Option 1  ")


        else :
            category_password = str(input("Enter the password which needs to be  stored : "))
            category_password_E = f.encrypt(category_password.encode())
            sqliteConnection = sql.connect(FilePath + 'KJIT.db')
            Insert_Pass(sqliteConnection, 'PassMaster', info.upper(), login_name.upper(), Date_N, category_password_E)


    elif n == '2':  # Generate a password

        # df = pd.read_csv(FilePath+'Wordlist.txt', sep='\t',
        #                  engine='python',
        #                  quoting=csv.QUOTE_NONE, index_col=False, encoding='iso-8859-1', on_bad_lines='warn')



        import random
        import string

        choice = int(input("\n Type 1 for generating a password or Type 2 for generating a phrase : "))

        if choice == 1:
            lower = string.ascii_lowercase
            caps = string.ascii_uppercase
            numbers = string.digits
            symbols = string.punctuation

            print("Welcome to the PyPassword Generator!")
            nr_lower = int(input("How many lowercase letters would you like in your password? : "))
            nr_caps = int(input("How many uppercase letters would you like in your password? : "))
            nr_symbols = int(input("How many symbols would you like? : "))
            nr_numbers = int(input("How many numbers would you like : "))

            part1 = []
            # random letters

            for i in range(0, nr_lower):
                a = lower[random.randint(0, len(lower) - 1)]
                part1.append(a)

            for i in range(0, nr_caps):
                a = caps[random.randint(0, len(caps) - 1)]

                part1.append(a)

            # random symbols
            for j in range(0, nr_symbols):
                b = symbols[random.randint(0, len(symbols) - 1)]
                part1.append(b)
            # random numbers

            for k in range(0, nr_numbers):
                c = numbers[random.randint(0, len(numbers) - 1)]
                part1.append(c)

            random.shuffle(part1)
            passcode = ""
            for l in part1:
                passcode += l

            print("\nHere is your Password!\n\n--> ", passcode, " <--")
            encCode = f.encrypt(passcode.encode())
            decCode = f.decrypt(encCode).decode()

            #print(encCode, "\n",decCode)
            # password code

            #write the password to the Db
            Date_N          = datetime.datetime.now().strftime("%Y-%m-%d").rstrip('0')
            response2   = input("\n Do you want to Update the Database? {yes or no} ")

            if response2.upper() == 'YES':
                Category_N = str(input("Enter the category against which the password will be stored : "))
                sqliteConnection =sql.connect(FilePath+'KJIT.db')
                #Read current password master
                Existing_Pass = Ret_Pass(sqliteConnection,"PassMaster")
                #print(Existing_Pass[["User_ID",'Category','Decrypted_Passphrase',"Timestamp"]] )
                Count_records = Existing_Pass[(Existing_Pass["User_ID"].str.upper() == login_name.upper()) & (Existing_Pass["Category"].str.upper() == Category_N.upper())]["User_ID"].count().squeeze()

                if Count_records >0:
                    response1 = input(
                        "This Category of password already exists in our database. \nDo you want overwrite this ? {yes or no} ")
                    if response1 == 'yes':
                        print("performs the function of overwriting the password though some code")
                        sqliteConnection = sql.connect(FilePath + 'KJIT.db')
                        Update_Pass(sqliteConnection, 'PassMaster', Category_N.upper(), login_name.upper(), Date_N, encCode)
                    elif response1 == 'no':
                        print("Please Create a new category and re-enter. Choose Option 1  ")
                else:
                    sqliteConnection = sql.connect(FilePath + 'KJIT.db')
                    Insert_Pass(sqliteConnection, 'PassMaster', Category_N.upper(), login_name.upper(), Date_N, encCode)





        elif choice == 2:

            n = int(input("\n Enter the number of words in the passphrase : "))
            dlist = list()
            directory = {}
            phrase = str()
            a = str()

            for x in range(n):

                for i in range(5):
                    a += str(random.randint(1, 6))  # randomly generate 5 digit number.
                rdigit = a
                a = str()
                dlist.append(rdigit)

            print(dlist)

            sqliteConnection = sql.connect(FilePath + 'KJIT.db')
            Word_List = Ret_Dictionary(sqliteConnection, 'WordList_E')

            for a in dlist:
                phrase = phrase + " " + Word_List["Word"][Word_List["Code"] == int(a)].squeeze()

            phrase = phrase.strip()
            encPhrase = f.encrypt(phrase.encode())
            decPhrase = f.decrypt(encPhrase).decode()

            print("\nHere is your Passphrase!\n\n--> ", phrase, " <--")

            #write the passphrase to the Db
            Date_N          = datetime.datetime.now().strftime("%Y-%m-%d").rstrip('0')
            response2   = input("\n Do you want to Update the Database? {yes or no} ")

            if response2.upper() == 'YES':
                Category_N = str(input("Enter the category against which the password will be stored : "))
                sqliteConnection =sql.connect(FilePath+'KJIT.db')
                #Read current password master
                Existing_Pass = Ret_Pass(sqliteConnection,"PassMaster")
                #print(Existing_Pass[["User_ID",'Category','Decrypted_Passphrase',"Timestamp"]] )
                Count_records = Existing_Pass[(Existing_Pass["User_ID"].str.upper() == login_name.upper()) & (Existing_Pass["Category"].str.upper() == Category_N.upper())]["User_ID"].count().squeeze()

                if Count_records >0:
                    response1 = input(
                        "This Category of password already exists in our database. \nDo you want overwrite this ? {yes or no} ")
                    if response1 == 'yes':
                        print("performs the function of overwriting the password though some code")
                        sqliteConnection = sql.connect(FilePath + 'KJIT.db')
                        Update_Pass(sqliteConnection, 'PassMaster', Category_N.upper(), login_name.upper(), Date_N, encPhrase)
                    elif response1 == 'no':
                        print("Please Create a new category and re-enter. Choose Option 1  ")
                else:
                    sqliteConnection = sql.connect(FilePath + 'KJIT.db')
                    Insert_Pass(sqliteConnection, 'PassMaster', Category_N.upper(), login_name.upper(), Date_N, encPhrase)


        else:
            print("Enter a vaild choice.")




    elif n == '3':# Retrieve a password
        print("Entered into choice 3 ")
        Disp_Table = pd.DataFrame()
        Date_N          = datetime.datetime.now().strftime("%Y-%m-%d").rstrip('0')
        Category_N  =  str(input("Enter the category against which the password might have got stored : "))

        # Retrieve  password from  the Db
        sqliteConnection = sql.connect(FilePath+'KJIT.db')
        #Read current password master
        Existing_PassMaster = Ret_Pass(sqliteConnection,'PassMaster')
        #print (Existing_PassMaster)
        #print(Existing_PassMaster[["User_ID",'Category','Decrypted_Passphrase',"Timestamp"]] )
        #print ("Rows",Existing_PassMaster['encPhrase'].count().squeeze())
        count_records2 = Existing_PassMaster[(Existing_PassMaster["User_ID"].str.upper() == login_name.upper()) & (Existing_PassMaster["Category"].str.upper() == Category_N.upper())]["User_ID"].count().squeeze()
        if count_records2>0:
            Disp_Table =Existing_PassMaster[(Existing_PassMaster["User_ID"].str.upper() == login_name.upper()) & (Existing_PassMaster["Category"].str.upper() == Category_N.upper())]
            print (Disp_Table[["User_ID",'Category','Decrypted_Passphrase',"Timestamp"]])
        else:
            print ("No Stored passwprds")
        #print("Record Retrieved successfully from PassMaster table ", Existing_PassMaster['encPhrase'].count().squeeze())




    elif n == '4':
        from math import log2
        import string


        def entropy(password):
            R = 0
            L = len(password)
            if any(i in string.digits for i in password):
                R += 10
            if any(i in string.ascii_lowercase for i in password):
                R += 26
            if any(i in string.ascii_uppercase for i in password):
                R += 26
            if any(i in string.punctuation for i in password):
                R += 32
            # print(R)
            E = L * log2(R)
            G = int(2 ** ((E) - 1))  # average entropy
            T = int(G / (10 ** 11))
            print("\nEntropy : ", E)

            # Password strength
            if E < 15:
                print("\nC'mon think about a better one, this is Extremely Weak")
            elif 15 <= E < 30:
                print("\nMeh! This is a Weak password! ")
            elif 30 <= E < 55:
                print("\nYay ! This password is Strong!")
            elif E >= 55:
                print("\nWow , This password is Extremely Strong ! ")

            print("\nNumber of guesses : ", G)
            # taking computer does 100 billion guesses a second
            if T < 60:
                print("\nIt will take", T, " just secs ")
            if 60 <= T < 3600:
                print("\nIt will take just ", int(T / 60), "minutes")
            if 3600 <= T < 86400:
                print("\nIt will take just ", int(T / 3600), "hours")
            if 86400 <= T < 2592000:
                print("\nIt will take about ", int(T / (86400)), "days")
            if 2592000 <= T < 31104000:
                print("\nIt will take a about", int(T / (2592000)), "months")
            if T >= 31104000:
                t = T / (31104000)
                if t < 10**3:
                    print("\nIt will take a mammoth", int(t), " years !!")
                if 10 ** 3 <= t < 10 ** 6:
                    print("\nIt will take a mammoth", int(t / 10 ** 3), "thousand years !!")
                if 10 ** 6 <= t < 10 ** 9:
                    print("\nIt will take a mammoth ", int(t / 10 ** 6), "million years !!!")
                if 10 ** 9 <= t < 10 ** 12:
                    print("\nIt will take a mammoth ", int(t / 10 ** 9), "billion years !!!!")
                if 10 ** 12 <= t < 10 ** 15:
                    print("\nIt will take a mammoth ", int(t / 10 ** 12), "trillion years !!!!!")
                if t >= 10 ** 15:
                    print("\nIt will take a mammoth ", int(t / 10 ** 15), "quadrillion years !!!!!")


        code = input("\nEnter the password to check its strength ! : ")
        entropy(code)

    else:
        break
