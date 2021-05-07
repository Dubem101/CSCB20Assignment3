import sqlite3
import hashlib
import os
from functools import wraps
from flask import Flask, session, redirect, url_for, request, escape, render_template, g, flash

DATABASE = './assignment3.db'

# Web App Config
app = Flask(__name__, static_url_path='/static')

# new sessions are invalid if the server is stopped
# os.urandom(12) to create new session each time
app.secret_key = b'@fE@zOsCa^oCxp8DN00b'

# CONSTANTS
# for feedback
NUM_QUESTIONS = 4

# for password hashing
salt = "$gz2-;d'a"

# Integer Codes for Assignments
MISSING = -2
NOT_INPUTTED = -1
COMPLETED = "completed"

# More constants for assignments
MAX_MARK = 100
GRADE_INPUT_SUFFIX = "-grade"

# Account Credential constants
HASH_ITR = 100000
MIN_PASSWORD_LENGTH = 8
MIN_USERNAME_LENGTH = 6

account_type = {
    'STUDENT': "Student",
    'INSTRUCTOR': "Instructor"
}

# Remark request constants
remark_status = {
    'OPEN': "Open",
    'RESOLVED': "Resolved"
}

# Form constants
form_key_names = {
    'FULL_NAME': "full_name",
    'FIRST_NAME': "firstname",
    'LAST_NAME': "lastname",
    'PASSWORD': "password",
    'PASSWORD1': "password1",
    'PASSWORD2': "password2",

    'GRADE': "grade",
    'ASSIGNMENT1': "assign1",
    'ASSIGNMENT2': "assign2",
    'ASSIGNMENT3': "assign3",
    'ASSIGNMENT4': "assign4",
    'MIDTERM': "midterm",
    'FINAL': "final",

    'QUESTION': "question",
    'INSTRUCTOR_NO': "instr_no",

    'REMARK_ASSESS': 'remark_assess',
    'REMARK_EXPL': 'remark_expl',

    'STUDENT_NO': "stud_no"
}

form_name_to_assessment = {
    form_key_names['ASSIGNMENT1']: 'Assignment1',
    form_key_names['ASSIGNMENT2']: 'Assignment2',
    form_key_names['ASSIGNMENT3']: 'Assignment3',
    form_key_names['ASSIGNMENT4']: 'Assignment4',
    form_key_names['MIDTERM']: 'Midterm',
    form_key_names['FINAL']: 'Final',
}

session_key_names = {
    'USERNAME': "username",
    'ACCOUNT_TYPE': "accountType"
}


# Database functions
# functions get_db, make_dicts, close_connection, query_db are taken from here
# https://flask.palletsprojects.com/en/1.1.x/patterns/sqlite3/
# Official flask documentation


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))

# calls to get db will be automatically closed at end of request


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

# Other helpers
# function login_required inspired from here
# https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/#login-required-decorator


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session_key_names['USERNAME'] not in session:
            flash('Need to sign in to access this site', 'error')
            return redirect(url_for('root'))
        return f(*args, **kwargs)
    return decorated_function


def type_required(accountType):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if (accountType != account_type['INSTRUCTOR'] and accountType != account_type['STUDENT']) or accountType != session[session_key_names['ACCOUNT_TYPE']]:
                flash('You need to be an ' + accountType, 'error')
                return redirect(url_for('root'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# Server side function for converting integer codes for assignments to the actual grade


def intgrade_to_grade(grade_val):
    if grade_val == MISSING:
        return 'Missing'
    elif grade_val == NOT_INPUTTED:
        return 'Not inputted'
    else:
        return grade_val

# Server side function for converting form input for assignments to integers
# Data received from dictionary 'form', for evaluation 'assessment'
# Used for inputting grades to be stored as integers in the database


def input_to_grade(grade_val, form, assessment):
    if grade_val == COMPLETED:
        # we have to look at the actual number, based on assessment
        return int(form[assessment + GRADE_INPUT_SUFFIX])
    elif int(grade_val) == MISSING or int(grade_val) == NOT_INPUTTED:
        return int(grade_val)
    return None


# Helper function to check all form arguments are not null


def form_data_null(form):
    return any(value is None or value == "" for value in form)


# Request Handlers

# Login
@app.route("/", methods=['GET', 'POST'])
def root():
    if request.method == "POST":
        user_name = request.form[session_key_names['USERNAME']]
        password_candidate = request.form[form_key_names['PASSWORD']]

        # Check if username is in the db
        user = query_db("SELECT * FROM AccountCredentials WHERE Username = :user",
                        {'user': user_name}, one=True)

        if user is not None and user["Username"] == user_name:
            # HASH_ITR iterations of the sha256 secure hash
            hashed_pass = hashlib.pbkdf2_hmac(
                'sha256', password_candidate.encode('utf-8'), salt.encode('utf-8'), HASH_ITR)

            # Verify password
            if hashed_pass == user["Password"]:
                # log in
                session[session_key_names['USERNAME']] = user_name
                session[session_key_names['ACCOUNT_TYPE']
                        ] = user["AccountType"]
                flash('Logged in!', 'success')
                return redirect(url_for('home'))
            else:
                return render_template("index.html", error="Invalid password")
        return render_template("index.html", error="Cannot find username, did you make an account?")
    elif session_key_names['USERNAME'] in session:
        # When typed in and logged in, redirect to home
        return redirect(url_for('home'))
    elif request.method == "GET":
        return render_template("index.html")


@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        account = request.form[session_key_names['ACCOUNT_TYPE']]
        first_name = request.form[form_key_names['FIRST_NAME']]
        last_name = request.form[form_key_names['LAST_NAME']]
        user_name = request.form[session_key_names['USERNAME']]
        password_candidate = request.form[form_key_names['PASSWORD1']]
        password_repeat = request.form[form_key_names['PASSWORD2']]

        # Backend form validation
        if account != account_type['INSTRUCTOR'] and account != account_type['STUDENT']:
            return render_template("register.html", error="Must be a Student or Instructor")

        if any(not c.isalnum() for c in first_name):
            return render_template("register.html", error="First name contains non-alphabetical characters")

        if any(not c.isalpha() for c in last_name):
            return render_template("register.html", error="Last name contains non-alphabetical characters")

        # Let front-end form pattern handle no spaces or special characters
        if len(password_candidate) < MIN_USERNAME_LENGTH:
            return render_template("register.html", error="Username less than " + str(MIN_USERNAME_LENGTH) + " characters")

        if password_candidate != password_repeat:
            return render_template("register.html", error="Passwords do not match")

        if len(password_candidate) < MIN_PASSWORD_LENGTH:
            return render_template("register.html", error="Password less than " + str(MIN_PASSWORD_LENGTH) + " characters")

        db = get_db()
        db.row_factory = make_dicts
        # check if the username already exists
        user = query_db("SELECT * FROM AccountCredentials WHERE Username = :user",
                        {'user': user_name}, one=True)
        if user is None:
            # HASH_ITR iterations of the sha256 secure hash
            hashed_pass = hashlib.pbkdf2_hmac(
                'sha256', password_candidate.encode('utf-8'), salt.encode('utf-8'), HASH_ITR)
            cur = db.cursor()
            cur.execute("""INSERT INTO
            AccountCredentials
            (Username,
            Password,
            AccountNumber,
            AccountType,
            FirstName,
            LastName)
            VALUES(?, ?, ?, ?, ?, ?)""",
                        (user_name.strip(),
                         hashed_pass,
                         # Account number is auto increment, so give it nothing
                         None,
                         account,
                         first_name.strip(),
                         last_name.strip()))

            # save changes
            db.commit()

            if account == account_type['STUDENT']:
                # Make grades row if its a student

                # Get newly made AccountNumber
                result = query_db("SELECT AccountNumber FROM AccountCredentials WHERE Username = :user",
                                  {'user': user_name}, one=True)

                cur.execute("""INSERT INTO
                StudentGrades
                (AccountNumber,
                Assignment1,
                Assignment2,
                Assignment3,
                Assignment4,
                Midterm,
                Final)
                VALUES(?, ?, ?, ?, ?, ?, ?)""",
                            (result["AccountNumber"],
                             NOT_INPUTTED,
                             NOT_INPUTTED,
                             NOT_INPUTTED,
                             NOT_INPUTTED,
                             NOT_INPUTTED,
                             NOT_INPUTTED))

                # save changes
                db.commit()

            cur.close()

            # automatically log in
            session[session_key_names['USERNAME']] = user_name
            session[session_key_names['ACCOUNT_TYPE']] = account
            flash('Logged in!', 'success')
            return redirect(url_for('home'))
        else:
            return render_template("register.html", error="Username taken")
    elif session_key_names['USERNAME'] in session:
        # if already logged in, redirect to home
        return redirect(url_for('home'))
    elif request.method == "GET":
        return render_template("register.html")


@ app.route("/signout")
@ login_required
def signout():
    # clear the session dictionary of all data
    session.clear()
    flash('Successfully logged out', 'success')
    return redirect(url_for('root'))


@ app.route("/home")
@ login_required
def home():
    return render_template("home.html")


@ app.route("/calendar")
@ login_required
def calendar():
    return render_template("calendar.html")


@ app.route("/assignments")
@ login_required
def assignments():
    return render_template("assignments.html")


@ app.route("/weekly")
@ login_required
def weekly():
    return render_template("weekly.html")


@ app.route("/links")
@ login_required
def links():
    return render_template("links.html")


@ app.route("/dashboard")
@ login_required
def dashboard():
    result = query_db("SELECT * FROM AccountCredentials as a WHERE a.Username = :uname",
                      {'uname': session[session_key_names['USERNAME']]}, one=True)

    if result is None:
        # redirect to home
        flash('Cannot find this user', 'error')
        return redirect(url_for('root'))

    get_response = {form_key_names['FULL_NAME']
        : result["FirstName"] + " " + result["LastName"]}
    return render_template("dashboard.html", get_response=get_response)


@ app.route("/grades")
@ login_required
def grades():
    if session[session_key_names['ACCOUNT_TYPE']] == account_type['INSTRUCTOR']:
        # Get all the grades
        grade_list = query_db("""SELECT *
                            FROM StudentGrades g, AccountCredentials a
                            WHERE a.AccountNumber = g.AccountNumber
                            AND a.AccountType = 'Student'
                            ORDER BY a.LastName""",
                              [], one=False)

        # list empty
        if not grade_list:
            flash('No grades', 'msg')
            return redirect(url_for('dashboard'))

        return render_template("grades.html", grades=grade_list, columns=form_name_to_assessment.values())
    elif session[session_key_names['ACCOUNT_TYPE']] == account_type['STUDENT']:
        # Get all the grades for this student
        grade_row = query_db("""SELECT *
                            FROM StudentGrades g, AccountCredentials a
                            WHERE a.AccountNumber = g.AccountNumber
                            AND a.Username = :user""",
                             {'user': session[session_key_names['USERNAME']]}, one=True)

        # No row
        if grade_row is None:
            flash('No grades for you', 'msg')
            return redirect(url_for('dashboard'))

        return render_template("grades.html", grade=grade_row, columns=form_name_to_assessment.values())


@ app.route("/remarkform/<string:assessment>", methods=['GET', 'POST'])
@ login_required
@ type_required(account_type['STUDENT'])
def remarkform(assessment):
    if assessment is None:
        flash('No assessment, did you type that link in?', 'msg')
        return redirect(url_for('dashboard'))

    db = get_db()
    db.row_factory = make_dicts

    # Make sure assessment is a valid evaluation in our database
    # Getting column information
    cur = db.cursor()
    result = cur.execute("PRAGMA table_info(StudentGrades)", []).fetchall()

    # Valid assessment (column exists in studentgrades, exclude AccountNumber)
    if any(('name', assessment) in row.items() for row in result) and assessment != "AccountNumber":
        if request.method == "GET":
            # Get grade for display
            grade = query_db("""SELECT * FROM StudentGrades as grades, AccountCredentials as a
                        WHERE a.Username = :user
                        AND grades.AccountNumber = a.AccountNumber""",
                             {'user': session[session_key_names['USERNAME']]}, one=True)

            return render_template("remarkform.html", assessment=assessment, grade=intgrade_to_grade(grade[assessment]))
        elif request.method == "POST":
            evaluation = assessment
            explanation = request.form[form_key_names['REMARK_EXPL']]

            # Got to make sure we don't have a open request for this mark already
            result = query_db("""SELECT * FROM Remark as r, AccountCredentials as a
                            WHERE a.Username = ?
                            AND r.AccountNumber = a.AccountNumber
                            AND r.Status = ?
                            AND r.Evaluation = ?""",
                              (session[session_key_names['USERNAME']], remark_status['OPEN'], evaluation), one=True)

            if result is None:
                # Now we can add this as an open request
                # Get our account number
                acct_no = query_db("SELECT AccountNumber FROM AccountCredentials WHERE Username = :user",
                                   {'user': session[session_key_names['USERNAME']]}, one=True)

                cur = db.cursor()
                cur.execute("""INSERT INTO 
                Remark 
                (AccountNumber,
                Evaluation,
                Explanation,
                Status)
                VALUES(?, ?, ?, ?)""",
                            (acct_no['AccountNumber'],
                             evaluation,
                             explanation,
                             remark_status['OPEN']))

                # save changes
                db.commit()

                flash('Successfully submitted remark request form', 'success')
            else:
                flash(
                    'An open remark request already exists from you for this assessment', 'error')
    else:
        flash('Invalid assessment name', 'error')
    # Return to grades in every case
    return redirect(url_for('grades'))


@ app.route("/remarks", methods=['GET', 'POST'])
@ login_required
def remarks():
    if request.method == "GET":
        if session[session_key_names['ACCOUNT_TYPE']] == account_type['INSTRUCTOR']:
            # Get all the remarks
            remark_list = query_db("""SELECT a.FirstName, a.LastName, r.AccountNumber, r.Evaluation, r.Explanation, r.Status
                                    FROM Remark r, AccountCredentials a 
                                    WHERE a.AccountNumber = r.AccountNumber
                                    ORDER BY a.LastName""",
                                   [], one=False)

            # list empty
            if not remark_list:
                flash('No remark requests', 'msg')
                return redirect(url_for('dashboard'))

            return render_template("remarks.html", remarks=remark_list)
        elif session[session_key_names['ACCOUNT_TYPE']] == account_type['STUDENT']:
            # Get all the remarks for this student
            remark_list = query_db("""SELECT a.FirstName, a.LastName, r.AccountNumber, r.Evaluation, r.Explanation, r.Status
                                    FROM Remark r, AccountCredentials a 
                                    WHERE a.Username = :user
                                    AND a.AccountNumber = r.AccountNumber
                                   """,
                                   {'user': session[session_key_names['USERNAME']]}, one=False)

            # list empty
            if not remark_list:
                flash("You don't have any remark requests", 'msg')
                return redirect(url_for('dashboard'))

            return render_template("remarks.html", remarks=remark_list)
    elif request.method == "POST" and session[session_key_names['ACCOUNT_TYPE']] == account_type['INSTRUCTOR']:
        # Instructor resolving a remark request, redirected to change editgrades
        form = {}
        form[form_key_names['STUDENT_NO']
             ] = request.form[form_key_names['STUDENT_NO']]
        form[form_key_names['REMARK_ASSESS']
             ] = request.form[form_key_names['REMARK_ASSESS']]

        if form_data_null([form[form_key_names['STUDENT_NO']], form[form_key_names['REMARK_ASSESS']]]): 
            flash('Student number or remark assessment is empty', 'error')
            return redirect(url_for('remarks'))

        # check if this student number exists in account credentials
        student = query_db("SELECT AccountNumber FROM AccountCredentials WHERE AccountNumber = :acctno",
                           {'acctno': request.form[form_key_names['STUDENT_NO']]}, one=True)

        # resolve request button (POST) wouldn't display unless the request stats was Open
        # but just to make sure
        open_request = query_db("""SELECT * FROM Remark r
                                    WHERE r.AccountNumber = ? 
                                    AND r.Evaluation = ?""",
                                (form[form_key_names['STUDENT_NO']], form[form_key_names['REMARK_ASSESS']]), one=True)

        if student is not None and open_request["Status"] == remark_status['OPEN']:
            db = get_db()
            db.row_factory = make_dicts

            cur = db.cursor()
            cur.execute("""UPDATE
                    Remark
                    SET  
                        Status = ?
                    WHERE AccountNumber = ?
                    AND Evaluation = ?""",
                        (remark_status['RESOLVED'],
                         form[form_key_names['STUDENT_NO']],
                         form[form_key_names['REMARK_ASSESS']]))

            # save changes
            db.commit()

            # Go to edit grades page for student
            flash('Successfully resolved remark request, you can change the mark for ' +
                  form[form_key_names['REMARK_ASSESS']] + ' here', 'success')
            return redirect(url_for('editgrades', accountno=form[form_key_names['STUDENT_NO']]))

        # Return to dashboard
        # Only one case can happen at a time
        flash_message = ""
        if student is None:
            flash_message = "Can't find this student"

        if open_request != remark_status['OPEN']:
            flash_message = "Remark request isn't open"

        flash(flash_message, 'error')
        return redirect(url_for('dashboard'))
    # Student tries to POST
    flash("You aren't an instructor", 'msg')
    return redirect(url_for('dashboard'))


@ app.route("/feedback", methods=['GET', 'POST'])
@ login_required
def feedback():
    if request.method == "GET":
        if session[session_key_names['ACCOUNT_TYPE']] == account_type['INSTRUCTOR']:
            db = get_db()
            db.row_factory = make_dicts

            # Get all the feedback for this instructor, based on username
            # Columns returned aren't named, have to do a2.FirstName and so on

            # Dynamic string to project for all the questions
            f_dot_num_q = ""
            for i in range(1, NUM_QUESTIONS + 1):
                f_dot_num_q += ", f.Q" + str(i)

            feedback_list = query_db("""SELECT a2.FirstName, a2.LastName""" + f_dot_num_q + """ 
                                    FROM Feedback f, AccountCredentials a1, AccountCredentials a2 
                                    WHERE a1.Username = :user 
                                    AND f.InstructorNumber = a1.AccountNumber 
                                    AND f.AccountNumber = a2.AccountNumber""",
                                     {'user': session[session_key_names['USERNAME']]}, one=False)

           # Get all feedback questions from question bank
            QUESTIONS = query_db("SELECT * FROM QuestionBank",
                                 [], one=False)

            # Convert to usable dictionary
            questions_dict = {}
            for question in QUESTIONS:
                questions_dict[question['QuestionNumber']
                               ] = question['QuestionText']

            # list empty
            if not feedback_list:
                flash('No feedback for this instructor', 'msg')
                return redirect(url_for('dashboard'))

            return render_template("feedback.html", feedback=feedback_list, QUESTIONS=questions_dict, NUM_Q=NUM_QUESTIONS)
        elif session[session_key_names['ACCOUNT_TYPE']] == account_type['STUDENT']:
            # Get instructor info to send to dropdowns
            instrs = query_db("SELECT * FROM AccountCredentials WHERE AccountType = 'Instructor'",
                              [], one=False)

            instructor_dict = {}
            for instructor in instrs:
                instructor_dict[instructor['AccountNumber']
                                ] = instructor['FirstName'] + " " + instructor['LastName']

            # Get all feedback questions from question bank
            QUESTIONS = query_db("SELECT * FROM QuestionBank",
                                 [], one=False)

            questions_dict = {}
            for question in QUESTIONS:
                questions_dict[question['QuestionNumber']
                               ] = question['QuestionText']

            return render_template("feedback.html", instructors=instructor_dict, QUESTIONS=questions_dict)
    elif request.method == "POST" and session[session_key_names['ACCOUNT_TYPE']] == account_type['STUDENT']:
        form = [None] * (2 + NUM_QUESTIONS)
        # first entry reserved for AccountNumber
        # second entry reserved for InstructorNumber
        # refer to given Instructor number

        # Check instructor number is non-empty
        if request.form[form_key_names['INSTRUCTOR_NO']] == "":
            flash('Empty instructor number', 'error')
            return redirect(url_for('dashboard'))

        form[1] = request.form[form_key_names['INSTRUCTOR_NO']]
        # loop from 1 to NUM_QUESTIONS
        for i in range(1, NUM_QUESTIONS + 1):
            # start filling array at 2
            form[i + 1] = request.form[form_key_names['QUESTION'] + str(i)]

        # check if this instructor number exists in account credentials
        instr = query_db("SELECT AccountNumber FROM AccountCredentials WHERE AccountNumber = :acctno",
                         {'acctno': form[1]}, one=True)

        # check that there isn't already a response from this student to this instructor
        existing_feedback = query_db("""SELECT * FROM AccountCredentials a, Feedback f 
                                    WHERE f.InstructorNumber = ? 
                                    AND a.Username = ? 
                                    AND f.AccountNumber = a.AccountNumber""",
                                     (form[1], session[session_key_names['USERNAME']]), one=True)

        if instr is not None and existing_feedback is None:
            # get student account number from username
            result = query_db("SELECT AccountNumber FROM AccountCredentials WHERE Username = :user",
                              {'user': session[session_key_names['USERNAME']]}, one=True)

            form[0] = result['AccountNumber']

            db = get_db()
            db.row_factory = make_dicts

            # Dynamic string to insert for all the questions
            q_num = ""
            question_mark_num = ""
            for i in range(1, NUM_QUESTIONS + 1):
                q_num += ", Q" + str(i)
                question_mark_num += ", ?"

            cur = db.cursor()
            cur.execute("""INSERT INTO 
            Feedback 
            (AccountNumber,
            InstructorNumber""" + q_num + """)
            VALUES(?, ?""" + question_mark_num + ")", form)

            # save changes
            db.commit()

            # Return to dashboard
            flash('Successfully submitted feedback form', 'success')
            return redirect(url_for('dashboard'))

        # Return to dashboard
        # Only one or the other
        flash_message = ""
        if instr is None:
            flash_message = "Can't find this instructor"

        if existing_feedback is not None:
            flash_message = "You already submitted feedback for this instructor"

        flash(flash_message, 'error')
        return redirect(url_for('dashboard'))


@ app.route("/editgrades/<int:accountno>", methods=['GET', 'POST'])
@ login_required
@ type_required(account_type['INSTRUCTOR'])
def editgrades(accountno):
    if accountno is None:
        flash('No account number, did you type that link in?', 'msg')
        return redirect(url_for('dashboard'))

    if request.method == "POST":
        # Row should already exist in the database
        db = get_db()
        db.row_factory = make_dicts

        # we get the data as strings, change to integer
        assign1 = input_to_grade(
            request.form[form_key_names['ASSIGNMENT1']], request.form, form_key_names['ASSIGNMENT1'])
        assign2 = input_to_grade(
            request.form[form_key_names['ASSIGNMENT2']], request.form, form_key_names['ASSIGNMENT2'])
        assign3 = input_to_grade(
            request.form[form_key_names['ASSIGNMENT3']], request.form, form_key_names['ASSIGNMENT3'])
        assign4 = input_to_grade(
            request.form[form_key_names['ASSIGNMENT4']], request.form, form_key_names['ASSIGNMENT4'])
        midterm = input_to_grade(
            request.form[form_key_names['MIDTERM']], request.form, form_key_names['MIDTERM'])
        final = input_to_grade(
            request.form[form_key_names['FINAL']], request.form, form_key_names['FINAL'])

        form_tuple = (assign1,
                      assign2,
                      assign3,
                      assign4,
                      midterm,
                      final)

        if form_data_null(form_tuple): 
            flash('Empty grades in form', 'error')
            return redirect(url_for('grades'))

        # Invalid entries
        if max(form_tuple) > MAX_MARK or min(form_tuple) < MISSING:
            return render_template('editgrades.html', error="Invalid marks entered")

        # Edit grades form is initiated with the previous values, so just change the row
        # Make sure this account number exists in the AccountCredentials
        result = query_db("SELECT AccountNumber FROM AccountCredentials WHERE AccountNumber = :acctno",
                          {'acctno': accountno}, one=True)

        if result is not None:
            cur = db.cursor()
            cur.execute("""UPDATE
                    StudentGrades
                    SET  
                        Assignment1 = ?,
                        Assignment2 = ?,
                        Assignment3 = ?,
                        Assignment4 = ?,
                        Midterm = ?,
                        Final = ?
                    WHERE AccountNumber = ?""",
                        (assign1,
                         assign2,
                         assign3,
                         assign4,
                         midterm,
                         final,
                         accountno))

            # save changes
            db.commit()

            # Return to dashboard
            flash('Successfully inputted marks', 'success')
            return redirect(url_for('grades'))
        else:
            # Return to dashboard
            flash('Cannot find this student account', 'error')
            return redirect(url_for('grades'))
    elif request.method == "GET":
        # Populate form with old data
        result = query_db("""SELECT * FROM StudentGrades as grades, AccountCredentials as a
                        WHERE a.AccountNumber = :acctno
                        AND grades.AccountNumber = a.AccountNumber""",
                          {'acctno': accountno}, one=True)

        if result is not None:
            form = {form_key_names['ASSIGNMENT1']: result["Assignment1"], form_key_names['ASSIGNMENT2']: result["Assignment2"], form_key_names['ASSIGNMENT3']: result["Assignment3"],
                    form_key_names['ASSIGNMENT4']: result["Assignment4"], form_key_names['MIDTERM']: result["Midterm"], form_key_names['FINAL']: result["Final"],
                    form_key_names['FULL_NAME']: result["LastName"] + ", " + result["FirstName"]}

            return render_template("editgrades.html", form=form)
        else:
            # Invalid accountNo
            flash('Cannot find this student account', 'error')
            return redirect(url_for('dashboard'))


if __name__ == "__main__":
    app.run(debug=True)
