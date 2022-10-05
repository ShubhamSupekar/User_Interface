package main

import (
	"database/sql"
	"net/http"
	"text/template"
	"unicode"

	_ "github.com/lib/pq"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var tpl *template.Template

type User struct {
	Username  string
	Firstname string
	Lastname  string
	Password  string
}

func init() {
	var err error
	db, err = sql.Open("postgres", "postgres://shubham:3232@localhost/app?sslmode=disable")
	if err != nil {
		panic(err)
	}

	if err = db.Ping(); err != nil {
		panic(err)
	}
	tpl = template.Must(template.ParseGlob("templates/*.html"))
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/login", login)
	http.HandleFunc("/loginAuth", loginAuth)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/signupAuth", signupAuth)
	http.ListenAndServe(":8080", nil)
}



//login
func login(w http.ResponseWriter, r *http.Request) {
	if alreadyLoggedIn(r) == true {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "login.html", nil)
}
func loginAuth(w http.ResponseWriter, r *http.Request) {
	u := r.FormValue("username")
	p := r.FormValue("password")
	var hash string
	row := db.QueryRow("SELECT  pass FROM users WHERE username = $1", u)
	err := row.Scan(&hash)
	if err != nil {
		tpl.ExecuteTemplate(w, "login.html", "Username Not Registred")
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(p))
	if err != nil {
		tpl.ExecuteTemplate(w, "login.html", "Incorrect Password")
		return
	}
	sID := uuid.NewV4()
	co := &http.Cookie{
		Name:  "session",
		Value: sID.String(),
	}
	http.SetCookie(w, co)
	_, err = db.Exec("INSERT INTO sessions (uname, uid) VALUES ($1, $2)", u, co.Value)
	if err != nil {
		tpl.ExecuteTemplate(w, "login.html", "Internal server error")
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}



//signup
func signup(w http.ResponseWriter, r *http.Request) {
	tpl.ExecuteTemplate(w, "signup.html", nil)
}
func signupAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	if alreadyLoggedIn(r) == true {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	//get form values
	us := User{}
	u := r.FormValue("username")
	//checking username criteria
	var nameLength bool
	if 5 <= len(u) && len(u) <= 50 {
		nameLength = true
	}
	row := db.QueryRow("SELECT * FROM users WHERE username = $1", u)
	error := row.Scan(&u)
	if error != sql.ErrNoRows {
		tpl.ExecuteTemplate(w, "signup.html", "Username has been taken choose another one")
		return
	}

	f := r.FormValue("firstname")
	var nameAlphanumericFirst = true
	var nameAlphanumericLast = true
	for _, char := range f {
		if !unicode.IsLetter(char) == true {
			nameAlphanumericFirst = false
		}
	}
	l := r.FormValue("lastname")
	for _, char := range l {
		if !unicode.IsLetter(char) == true {
			nameAlphanumericLast = false
		}
	}
	p := r.FormValue("password")
	//checking password criteria
	var Lower, Upper, Number, Symbol, Length, Nospace bool
	Nospace = true
	for _, char := range p {
		switch {
		case unicode.IsLower(char):
			Lower = true
		case unicode.IsUpper(char):
			Upper = true
		case unicode.IsNumber(char):
			Number = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			Symbol = true
		case unicode.IsSpace(int32(char)):
			Nospace = false
		}
	}
	if 11 < len(p) && len(p) < 60 {
		Length = true
	}
	if !Length || !Upper || !Lower || !nameAlphanumericFirst || !nameAlphanumericLast || !nameLength || !Symbol || !Nospace || !Number {
		tpl.ExecuteTemplate(w, "signup.html", "Check username and password criteria")
		return
	}
	us.Firstname = f
	us.Lastname = l
	us.Username = u
	bs, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	us.Password = string(bs)
	//validate from values
	if us.Firstname == "" || us.Lastname == "" || us.Username == "" || us.Password == "" {
		http.Error(w, http.StatusText(400), http.StatusBadRequest)
		return
	}
	sID := uuid.NewV4()
	co := &http.Cookie{
		Name:  "session",
		Value: sID.String(),
	}
	http.SetCookie(w, co)
	_, err1 := db.Exec("INSERT INTO users (username, fname, lname, pass) VALUES ($1, $2, $3, $4)", us.Username, us.Firstname, us.Lastname, us.Password)
	_, err2 := db.Exec("INSERT INTO sessions (uname, uid) VALUES ($1, $2)", us.Username, co.Value)
	if err1 != nil && err2 != nil {
		http.Error(w, http.StatusText(500), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}


func alreadyLoggedIn(r *http.Request) bool {
	_, err := r.Cookie("session")
	if err == nil {
		return true
	}
	return false
}


func index(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	if alreadyLoggedIn(r) == false {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	c, _ := r.Cookie("session")
	// var val string
	var U User
	row := db.QueryRow("SELECT  uname FROM sessions WHERE uid = $1", c.Value)
	err := row.Scan(&U.Username)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// row1 := db.QueryRow("SELECT  fname FROM users WHERE username = $1", val)
	row1 := db.QueryRow("SELECT fname, lname FROM users WHERE username = $1", U.Username)
	err = row1.Scan(&U.Firstname,&U.Lastname)
	if err == sql.ErrNoRows {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "index.html", U)
}



//logout
func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	if alreadyLoggedIn(r) == false {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	c, _ := r.Cookie("session")
	val := c.Value
	if val == "" {
		http.Error(w, http.StatusText(400), http.StatusBadRequest)
		return
	}
	_, err := db.Exec("DELETE FROM sessions WHERE uid=$1;", val)
	if err != nil {
		http.Error(w, http.StatusText(500), http.StatusInternalServerError)
		return
	}
	c = &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(w, c)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
