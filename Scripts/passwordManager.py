import secrets, string, hashlib, csv, os, getpass
import encrypt

__session = {'userLoggedIn' : 0, 'plainUserName': None, 'safeUserName' : None, 'dataFile' : None}
storageDir = os.path.join(os.path.dirname(__file__), "../.user/")
userFile = os.path.join(storageDir, "loggedUsers.csv")

def __set_session(userName=None, loggedIn=1):
    if loggedIn == 1 and userName != None:
        __session['plainUserName'] = userName
        __session['safeUserName'] = encrypt.encrypt(userName, userName)
        __session['userLoggedIn'] = 1
        __session['dataFile'] = os.path.join(storageDir, __session['safeUserName']+".csv") 
    else:
        __session['plainUserName'] = None
        __session['safeUserName'] = None
        __session['userLoggedIn'] = 0
        __session['dataFile'] = None

def logUserProfile(userName, userPassword):
    __set_session(userName);
    safeUserPassword = hashlib.blake2b(userPassword.encode(encoding='ascii')).hexdigest()
    loggedUsers = open(userFile, 'a', newline='')
    logUsers = csv.writer(loggedUsers, delimiter = ' ',quotechar = '|')
    logUsers.writerow([__session['safeUserName'], safeUserPassword])
    loggedUsers.close()
    return 1

def checkUserNameAvail(userName):
    try:
        if userName == "" : return -1
        safeUserName = encrypt.encrypt(userName, userName)
        loggedUsers = open(userFile, newline='')
        checkProfiles = csv.reader(loggedUsers, delimiter = ' ', quotechar='|')
        for row in checkProfiles:
            if row[0] == safeUserName:
                return 0
        return 1
    except FileNotFoundError:
        return 2

def handleUserAction(returning=1):
    try: 
        if returning == 1:
            prompt = "Create a new password(1), add an existing password to profile(2) or access existing passwords(3) or exit(9): "
        else: 
            prompt = "Create a new password(1), add an existing password to profile(2) or exit(9): "
        
        userActionMode = int(input(prompt))
        if userActionMode == 3:
            displaySavedPasswords()
            return
        elif userActionMode == 2:
            password = input('Enter the password: ')
        elif userActionMode == 1:
            password = createPassword()
            print("Password created!")
            print(password)
            saveStatus = input('Would you like to save the password?(Y/N) ').lower()
            if saveStatus == 'n':
                print("Password was not saved.")
                return
        elif userActionMode == 9:
            return logout()
        else:
            print("Please pick one of the given options.")
            return   
        passkeyword = input('Determine a keyword for the password that will help you recognize it later: ')
        if savePassword(password, passkeyword) == 1:
            print(f'Password saved with the keyword {passkeyword}!')
            return
        else:
            print("Saving failed. Try again.")
            return
    except (InputError, ValueError):
        print('Please choose one of the available options!')

def checkUserProfile(inputName, inputPass):
    safeName = encrypt.encrypt(inputName, inputName)
    try:
        loggedUsers = open(userFile, newline='')
        checkProfiles = csv.reader(loggedUsers, delimiter = ' ', quotechar='|')
        encodedPass = inputPass.encode(encoding='ascii')
        passHash = hashlib.blake2b(encodedPass).hexdigest()
        for creds in checkProfiles:
            if creds[0] == safeName and creds[1] == passHash:
                __set_session(inputName)
                return 1
            elif (creds[0] != safeName and creds[1] == passHash) or (creds[0] == safeName and creds[1] != passHash):
                return 2
        return 0               
    except FileNotFoundError:
        return 3

#This is perfect dont change for the love of love       
def createPassword():
    specialSymbols = '@$%&*_-#'
    tries = 0
    while tries < 3:
        try:
            codeLen = int(input('What length would you like your password to be? '))
            if codeLen > 10000:
                print('The length of the password can not exceed 10_000.')
                raise ValueError
            tries = 0
            break
        except ValueError:
            print('Please enter a valid value.(Recommended: 16)')
            tries += 1
        if tries == 3:
            print('Try again later.')
            return 0
    while tries < 3:
        try:
            useSym = input('Would you like to use special symbols in the password?(Y/N) ')
            tries = 0
            break
        except ValueError:
            print('Please choose one of the given options.')
            tries += 1
        if tries == 3:
            print('Try again later.')
            return
    useSym = useSym.lower()
    if useSym == 'y':
        x = ''.join(secrets.choice(string.ascii_letters + string.digits + str(specialSymbols)) for i in range(codeLen))
    elif useSym == 'n':
        x = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(codeLen))
    else:
        raise InputError(useSym, 'Invalid input')
    return x

def  savePassword(password, passkeyword):
    try:
        saveFile = open(__session['dataFile'], 'a+', newline='')
    except FileNotFoundError:
        pass
    try:
        encodedPassword = password.encode(encoding='ascii')
        safekeyword = encrypt.encrypt(passkeyword, __session["safeUserName"])
        passwordEncrypted = encrypt.encrypt(str(encodedPassword), safekeyword) 
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
        print(f"Displaying passwords saved for {__session['plainUserName']}")
        for row in checkSavedPasswords:
            if row[0] == __session['safeUserName']:
                decryptedPassword = encrypt.decrypt(row[2], row[1])
                decryptedKeyword = encrypt.decrypt(row[1], row[0])
                print(f'Keyword: {decryptedKeyword}  Password: {decryptedPassword}')
                x = 1
            else:
                x = 2
        if x == 2:
            print(f'No passwords found for {__session["plainUserName"]}.')
    except FileNotFoundError:
        print(f'No passwords found for {__session["plainUserName"]}.')            

class Error(Exception):
    pass

class InputError(Error):
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message 

def logout():
    print("Logging out ...")
    __set_session(loggedIn=0)
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
        print("Looks like you've already been here. Username taken. Try log-in.")
    elif userNameGood == 1 or userNameGood == 2:
        print('Before you proceed, note the password you set. You can not recover saved passwords without your master password.')
        userPassword = getpass.getpass(prompt='Enter a password: ')    
        userPassConf= getpass.getpass(prompt='Confirm master password: ')
        if userPassword != userPassConf:
            print("Passwords don't match. Restart.")
            return -1
        userCreated = logUserProfile(userName, userPassword)
        if userCreated == 1:
            print(f"User Created Successfully. Logging in as {userName}.")
            __set_session(userName)
            handleUserAction(0)

def userHelp():
    commandActions = {'login' : 'Log in to your existing account.', 
                    'create-account/createacc' : 'Create a new account.',
                    'logout' : 'Log out of current profile', 
                    '--commands/--help' : 'Displays a list of commands.', 
                    'create-password' : 'Create a password. If you are not signed into an account, password wont be saved.',
                    '--exit/--quit' : 'Exit the program'}
    for c,a in commandActions.items():
        print(f'{c} -> {a}')

def unregUserPassword():
    tempPassword = createPassword()
    print(tempPassword)

print('Welcome to password-manager. Enter --help or --commands for help.')

def inputStream():
    print()
    userInput = str(input("$ "))
    if userInput == 'login':
        login()
    elif userInput == 'create-account' or userInput == 'createacc':
        signUp()
    elif userInput == 'logout':
        logout()
    elif userInput == '--commands' or userInput == '--help':
        userHelp()
    elif userInput == 'create-password':
        unregUserPassword()
    elif userInput == 'exit' or userInput == 'quit':
        exit()
    else:
        print('Invalid command. Enter --help/--commands to get a complete list of commands.')

while True:
    if __session['userLoggedIn'] == 1:
        handleUserAction()
    else:
        inputStream()
