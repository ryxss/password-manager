import secrets, string, hashlib, csv
import encrypt

def userProfile(userName, userPassword):
    safeUserPassword = hashlib.blake2b(userPassword.encode(encoding='ascii')).hexdigest()
    registerNewUser = checkUserNameAvail(userName)
    if registerNewUser == 0:
        return 0
    else:
        loggedUsers = open('loggedusers.csv', 'a', newline='')
        logUsers = csv.writer(loggedUsers, delimiter = ' ',quotechar = '|')
        logUsers.writerow([userName, safeUserPassword])
        print(f'Welcome {userName}!')

def checkUserNameAvail(userName):
    try:
        loggedUsers = open('loggedusers.csv', newline='')
        checkProfiles = csv.reader(loggedUsers, delimiter = ' ', quotechar='|')
        for row in checkProfiles:
            if row[0] == userName:
                print('The username is already taken!')
                return 0
            else:
                pass
    except FileNotFoundError:
        pass

def NewUserAction(inputName):
    try:
        userActionMode = int(input('Create a new password(1), add an existing password to profile(2): '))
        if userActionMode == 1:
            password = createPassword()
            print(password)
            saveStatus = input('Would you like to save the password?(Y/N) ').lower()
            encodedPassword = password.encode(encoding='ascii')
            savePassword(saveStatus, encodedPassword, inputName)
            return 0

        elif userActionMode == 2:
            saveStatus = 'y'
            password = input('Enter the password: ')
            print(password)
            encodedPassword = password.encode(encoding='ascii')
            savePassword(saveStatus, encodedPassword, inputName)
            return 0
    except (InputError, ValueError):
        print('Please choose one of the available options!')

def ReturningUserAction(inputName):
    try:
        userActionMode = int(input('Create a new password(1), add an existing password to profile(2) or access existing passwords(3): '))
        if userActionMode == 1:
            password = createPassword()
            print(password)
            saveStatus = input('Would you like to save the password?(Y/N) ').lower()
            encodedPassword = password.encode(encoding='ascii')
            savePassword(saveStatus, encodedPassword, inputName)
            return 0

        elif userActionMode == 2:
            saveStatus = 'y'
            password = input('Enter the password: ')
            print(password)
            encodedPassword = password.encode(encoding='ascii')
            savePassword(saveStatus, encodedPassword, inputName)
            return 0

        elif userActionMode == 3:
            displaySavedPasswords(inputName)

    except (InputError, ValueError):
        print('Please choose one of the available options!')

def checkUserProfile(inputName, inputPass):
    try:
        loggedUsers = open('loggedusers.csv', newline='')
        checkProfiles = csv.reader(loggedUsers, delimiter = ' ', quotechar='|')
        x = 0
        encodedPass = inputPass.encode(encoding='ascii')
        passHash = hashlib.blake2b(encodedPass).hexdigest()
        for row in checkProfiles:
            creds = row
            if creds[0] == inputName and creds[1] == passHash:
                x = 1
                break
            elif (creds[0] != inputName and creds[1] == passHash) or (creds[0] == inputName and creds[1] != passHash):
                x = 2
        return x               
    except FileNotFoundError:
        print('No user profile has been created yet!')
            
def createPassword():
    specialSymbols = '@$%&*_-#'
    tries = 0
    while tries < 3:
        try:
            codeLen = int(input('What length would you like your password to be? '))
            if codeLen > 10000:
                print('The length of the password can not exceed 10000.')
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

def  savePassword(saveStatus, password, userName):
    if saveStatus == 'y':
        keyword = input('Determine a keyword for the password that will help you recognize it later: ')
        passwordEncrypted = encrypt.encrypt(str(password),keyword)
        passwordFile = open('passwords.csv', 'a', newline='')
        passwordWriter = csv.writer(passwordFile, delimiter = ' ',quotechar = '|')
        passwordWriter.writerow((userName, keyword, passwordEncrypted))
        print(f'Passwrod saved with the keyword {keyword}!')
    elif saveStatus == 'n':
        print('Password was not saved.')
    else:
        print('Please choose one of the available options')

def displaySavedPasswords(userName):
    try:
        passwordFile = open('passwords.csv', newline = '')
        checkSavedPasswords = csv.reader(passwordFile, delimiter = ' ', quotechar = '|')
        for row in checkSavedPasswords:
            if row[0] == userName:
                decryptedPassword = encrypt.decrypt(row[2],row[1])
                print(f'Keyword: {row[1]}  Password: {decryptedPassword}')
                x = 1
            else:
                x = 2
        if x == 2:
            print(f'No passwords found for {userName}.')
    except FileNotFoundError:
        print(f'No passwords found for {userName}.')            

class Error(Exception):
    pass

class InputError(Error):
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message 

def login():
    userName = str(input('Enter your username: '))
    userPasword = str(input('Enter your password: '))
    userCheck = checkUserProfile(userName, userPasword)
    if userCheck == 0:
        print('No user found under the the given credentials.')
    elif userCheck == 1:
        print(f'Welcome back {userName}.')
        ReturningUserAction(userName)
    elif userCheck == 2:
        print('Invalid username or password.')

def signUp():
    userName = str(input('Enter your username: '))
    userPassword = str(input('Enter your password: '))
    userCreated = userProfile(userName, userPassword)
    if userCreated == 0:
        pass
    else:
        NewUserAction(userName)

def userHelp():
    commandActions = {'log-in' : 'Log in to your existing account.', 
                    'create-account' : 'Create a new account.', 
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
    userInput = str(input())
    if userInput == 'log-in':
        login()
    elif userInput == 'create-account':
       signUp()
    elif userInput == '--commands' or userInput == '--help':
        userHelp()
    elif userInput == 'create-password':
        unregUserPassword()
    elif userInput == '--exit' or userInput == '--quit':
        exit()
    else:
        print('Invalid command. Enter --help/--commands to get a complete list of commands.')

while True:
    inputStream()
