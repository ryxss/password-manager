import secrets, string, hashlib, csv, os, getpass
import encrypt

__session = {'userLoggedIn' : 0, 'plainUserName': None, 'safeUserName' : None, 'dataFile' : None, 'hash': None}
parentDir = os.path.dirname(__file__)
storageDir = os.path.join(parentDir, "../.user/")
if not os.path.exists(storageDir):
    os.makedirs(storageDir)
userFile = os.path.join(storageDir, "loggedUsers.csv")

def __set_session(userName=None, passHash=None, loggedIn=1):
    if loggedIn == 1 and userName != None:
        __session['plainUserName'] = userName
        __session['safeUserName'] = encrypt.encrypt(userName, userName)
        __session['userLoggedIn'] = 1
        __session['dataFile'] = os.path.join(storageDir, __session['safeUserName']+".csv") 
        __session['hash'] = passHash

    else:
        __session['plainUserName'] = None
        __session['safeUserName'] = None
        __session['userLoggedIn'] = 0
        __session['dataFile'] = None
        __session['hash'] = None

def logUserProfile(userName, userPassword):   
    with open(userFile, 'a+', newline='') as loggedUsers:
        safeUserPassword = hashlib.blake2b(userPassword.encode(encoding='ascii')).hexdigest()
        logUsers = csv.writer(loggedUsers, delimiter = ' ',quotechar = '|')
        __set_session(userName, safeUserPassword);
        logUsers.writerow([__session['safeUserName'], safeUserPassword])
    return 1

def checkUserNameAvail(userName):
    try:
        if userName == "" : return -1
        safeUserName = encrypt.encrypt(userName, userName)
        with open(userFile, newline='') as loggedUsers:
            checkProfiles = csv.reader(loggedUsers, delimiter = ' ', quotechar='|')
            for row in checkProfiles:
                if row[0] == safeUserName:
                    return 0
        return 1
    except FileNotFoundError:
        return 2

def handleUserAction(returning=1):
    def processPasswordSave():
        saveStatus = input('Would you like to save the password?(Y/N) ').lower()
        if saveStatus == 'n':
            print("Password was not saved.")   
        elif saveStatus == 'y':
            passkeyword = input('Determine a keyword for the password that will help you recognize it later: ') or "deafault"
            if savePassword(password, passkeyword) == 1:
                print(f'Password saved with the keyword {passkeyword}!')
            else:
                print("Saving failed. Try again.")      
        else:
            raise InputError    

    try: 
        prompt = "\nCreate a new password(1), add an existing password to profile(2) or access existing passwords(3)," \
        "export passwords(4), help, or exit(9): "
        if returning != 1:
            print(prompt)
        userActionMode = input("Action: ")
        if userActionMode == '3':
            displaySavedPasswords()
        elif userActionMode == '2':    
            password = input('Enter the password: ')
            processPasswordSave()
        elif userActionMode == '1':    
            password = createPassword()
            print("Password created!")
            print(password)
            processPasswordSave()
        elif userActionMode == "help":
            print(prompt)
        elif userActionMode == '9':
            logout()
        else:
            raise InputError
        
    except (InputError, ValueError):
        print('Please choose one of the available options or enter help!')

def checkUserProfile(inputName, inputPass):
    safeName = encrypt.encrypt(inputName, inputName)
    try:
        with open(userFile, newline='') as loggedUsers:
            checkProfiles = csv.reader(loggedUsers, delimiter = ' ', quotechar='|')
            encodedPass = str(inputPass).encode(encoding='ascii')
            passHash = hashlib.blake2b(encodedPass).hexdigest()
            for creds in checkProfiles:
                if creds[0] == safeName and creds[1] == passHash:
                    __set_session(inputName, passHash)
                    return 1
                elif (creds[0] != safeName and creds[1] == passHash) or (creds[0] == safeName and creds[1] != passHash):
                    return 2  
        return 0               
    except FileNotFoundError:
        return 3

#This is perfect dont change   
def createPassword():
    specialSymbols = '@$%&*_-#'
    tries = 0
    while tries < 2:
        try:
            codeLen = input('How many characters? (default = 16): ') or 16
            if 0 < int(codeLen) <= 10000:
                tries = 0
                break
            else:
                print('Password length can not be negative or exceed 10_000 (Recommended: 16).')
                tries += 1
        except ValueError:
            print("Length is a positive integer > 0. Using 16.")
            codeLen = 16
    if tries == 2:
        print('Try again later.')
        return 0
    
    useSym = input('Would you like to use special symbols in the password?(Y/n): ') or 'y'
            
    useSym = useSym.lower()
    
    if useSym == 'n':
        x = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(codeLen))
    else:
        x = ''.join(secrets.choice(string.ascii_letters + string.digits + str(specialSymbols)) for i in range(codeLen))
    return str(x)

def savePassword(password, passkeyword):
    try:
        saveFile = open(__session['dataFile'], 'a+', newline='')
    except FileNotFoundError:
        pass
    try:
        encodedPassword = str(password.encode(encoding='ascii'))
        safekeyword = encrypt.encrypt(passkeyword, __session["hash"])
        passwordEncrypted = encrypt.encrypt(encodedPassword, __session["hash"]) 
        saver = csv.writer(saveFile, delimiter = ' ',quotechar = '|')
        saver.writerow([__session['safeUserName'], safekeyword, passwordEncrypted])
        saveFile.close()
        return 1
    except Error:
        return 0
    

def displaySavedPasswords():
    try:
        passwordFile = open(__session['dataFile'], newline = '')
        checkSavedPasswords = csv.reader(passwordFile, delimiter = ' ', quotechar = '|')
        print(f"\nDisplaying passwords saved for {__session['plainUserName']}")
        for row in checkSavedPasswords:
            if row[0] == __session['safeUserName']:
                decryptedPassword = encrypt.decrypt(str(row[2]), __session["hash"])
                #if pw starts with a b', it will be stored as b'b'.... so this is necessary for clean output
                decryptedPassword = decryptedPassword[2:-1] if decryptedPassword.startswith("b'") else decryptedPassword
                decryptedKeyword = encrypt.decrypt(str(row[1]), __session["hash"])
                print(f'Keyword: {decryptedKeyword}  Password: {decryptedPassword}')
        else:
            print(f'\nNo passwords found for {__session["plainUserName"]}.')
        passwordFile.close()
    except FileNotFoundError:
        print(f'\nNo password file found for {__session["plainUserName"]}. Was it deleted?')

def exportPasswords():
    if __session["userLoggedIn"] == 0:
        print("You must be logged in to export passwords.")
        return
    print(f"""To export your saved passwords, you can save the csv file named {__session['safeUsername']}.csv 
          in the .user directory\n""")
    print(f"After moving your passwords, simply clone password-manager again and use the same username and password\n")
    print(f"or note down your hashKey to decrypt your file using encrypt.decrypt('fileContents', hashKey)\n")
    print(f"hashkey: {__session['hash']}")          

class Error(Exception):
    pass

class InputError(Error):
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message 

def removeCacheFileorDirectory(cache):
    try:
        if not os.path.isdir(cache):
            os.remove(cache)
        else:
            files = os.listdir(cache)
            if len(files) != 0:
                for file in files:
                    filePath = os.path.join(cache, file)
                    removeCacheFileorDirectory(filePath)
            os.rmdir(cache)
    except FileNotFoundError:
        return

def logout():
    print("Logging out ...")
    __set_session(loggedIn=0)
    removeCacheFileorDirectory(os.path.join(parentDir, "__pycache__"))
    print("Successfully logged out!")

def login():
    userName = str(input('Enter your username: '))
    userPasword = getpass.getpass(prompt="Enter your password: ")
    userCheck = checkUserProfile(userName, userPasword)
    if userCheck == 0:
        print('No user found under the the given credentials.')
    elif userCheck == 1:
        print(f'Welcome back {userName}.')
        handleUserAction()
    elif userCheck == 2:
        print('Invalid username or password.')
    elif userCheck == 3:
        print("No user has been registered yet.")

def signUp():
    userName = str(input('Enter your username: '))
    userNameGood = checkUserNameAvail(userName)
    if userNameGood == -1:
        print("Empty usernames are not ideal. Restart.")
    elif userNameGood == 0:
        print("Looks like you've already been here. Username taken. Try login.")
    elif userNameGood == 1 or userNameGood == 2:
        print('Before you proceed, note the password you set. You can not recover saved passwords without your master password.\n')
        userPassword = getpass.getpass(prompt='Enter a password: ')    
        userPassConf= getpass.getpass(prompt='Confirm master password: ')
        if userPassword != userPassConf:
            print("Passwords don't match. Restart.")
        else:
            userCreated = logUserProfile(userName, userPassword)
            if userCreated == 1:
                print(f"User Created Successfully. Logging in as {userName}.\n")
                handleUserAction(0)

def userHelp():
    commandActions = {'login' : 'Log in to your existing account.', 
                    'create-account/createacc' : 'Create a new account.',
                    'logout' : 'Log out of current profile', 
                    'commands/help' : 'Displays a list of commands.', 
                    'create-password' : 'Create a password. If you are not signed into an account, password wont be saved.',
                    '--exit/--quit' : 'Exit the program',
                    'export': 'Export passwords saved with your current profile.'}

    for c,a in commandActions.items():
        print(f'{c} -> {a}')

def unregUserPassword():
    tempPassword = createPassword()
    print(tempPassword)

def inputStream():
    print()
    userInput = str(input("$ ")).lower()
    if userInput == "login":
        login()
    elif userInput == "create-account" or userInput == "createacc" or userInput == "signup":
        signUp()
    elif userInput == "logout":
        logout()
    elif userInput == "commands" or userInput == "help":
        userHelp()
    elif userInput == "create-password":
        unregUserPassword()
    elif userInput == "exit" or userInput == "quit" or userInput=='9':
        exit()
    elif userInput == "export":
        exportPasswords()
    else:
        print("Invalid command. Enter help/commands to get a complete list of commands.")

#PROGRAM ENTERS HERE

print('Welcome to password-manager. Enter help or commands for help.')
while True:
    if __session['userLoggedIn'] == 1:
        handleUserAction()
    else:
        inputStream()
