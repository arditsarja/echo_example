package main

import (
	"encoding/json"
	"fmt"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/labstack/gommon/log"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"

)

type Cat struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Dog struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Hamster struct {
	Name string`json:"name"`
	Type string `json:"type"`
}

type JwtClaims struct {
	Name string `json:"name"`
	jwt.StandardClaims
}

var output = "Hello from echo asdf gooooo\nName here&ltinput type='text' placeholder='Hello'/&gt"
var output2 = "Hello motherfucker"

func addCat(context echo.Context) error {
	cat := Cat{}
	defer context.Request().Body.Close()

	b, err := ioutil.ReadAll(context.Request().Body)
	if err != nil {
		log.Printf("Failed reading the request body for add cats: %s", err)
		return context.String(http.StatusInternalServerError, "")
	}
	err = json.Unmarshal(b, &cat)
	if err != nil {
		log.Printf("Failed unmarshal the request body: %s", err)
		return context.String(http.StatusInternalServerError, "")
	}
	log.Printf("This s your cat: %#v", cat)
	return context.String(http.StatusOK, "we got your cat: %#v")
}

func addDog(context echo.Context) error {
	dog := Dog{}
	defer context.Request().Body.Close()

	err := json.NewDecoder(context.Request().Body).Decode(&dog)
	if err != nil {
		log.Printf("Failed reading the request body for add dogs: %s", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	log.Printf("This s your dog: %#v", dog)
	return context.String(http.StatusOK, "we got your dog: %#v")
}
func addHamster(context echo.Context) error {
	hamster := Hamster{}

	err := context.Bind(&hamster)
	if err != nil {
		log.Printf("Failed reading the request body for add hamster: %s", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	log.Printf("This s your hamster: %#v", hamster)
	return context.String(http.StatusOK, "we got your hamster: %#v")

}

func sayHi(context echo.Context) error {
	return context.String(http.StatusOK, output)
}
func getCat(context echo.Context) error {
	catName := context.QueryParam("name")
	catType := context.QueryParam("type")

	dataType := context.Param("data")

	if dataType == "string" {
		return context.String(http.StatusOK, fmt.Sprintf("Your cat name is: %s and her type is %s", catName, catType))
	}
	if dataType == "json" {
		return context.JSON(http.StatusOK, map[string]string{
			"name": catName,
			"type": catType,
		})
	}
	return context.JSON(http.StatusBadRequest, map[string]string{
		"error": "You ned to choose a datatype",
	})
}
func mainAdmin(context echo.Context) error {
	return context.String(http.StatusOK, output)
}
func mainCoocie(context echo.Context) error {
	return context.String(http.StatusOK, "you are on the not yet on the secret cookie")
}
func mainJwt(context echo.Context) error {
	user := context.Get("user")
	token := user.(*jwt.Token)

	claims := token.Claims.(jwt.MapClaims)

	log.Printf("User Name: ", claims["name"], "User ID: ", claims["jti"])
	return context.String(http.StatusOK, "you are on the mainJwt")
}

func login(context echo.Context) error {
	username := context.QueryParam("username")
	password := context.QueryParam("password")
	if username == "jack" && password == "1234" {
		cookie := &http.Cookie{}
		//this is same
		//cookie := new(http.Cookie)
		cookie.Name = "sessionID"
		cookie.Value = "some_string"
		cookie.Expires = time.Now().Add(48 * time.Hour)
		context.SetCookie(cookie)
		token, err := createJwtToken()
		if err != nil {
			log.Printf("Error Creating jwt Token: %v", err)
			return context.String(http.StatusInternalServerError, "something went wrong")
		}
		jwtCookie := &http.Cookie{}

		jwtCookie.Name = "JWTCookie"
		jwtCookie.Value = token
		jwtCookie.Expires = time.Now().Add(48 * time.Hour)
		context.SetCookie(jwtCookie)
		return context.JSON(http.StatusOK, map[string]string{
			"message": "You were logget in",
			"token":   token,
		})
	}
	return context.String(http.StatusUnauthorized, "Your password or username is not correct")

}

func createJwtToken() (string, error) {
	claims := JwtClaims{
		"jack",
		jwt.StandardClaims{
			Id:        "main_user_id",
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
	}
	rawToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	token, err := rawToken.SignedString([]byte("mySecret"))

	if err != nil {
		return "", err
	}
	return token, nil

}

func checkCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(context echo.Context) error {
		cookie, err := context.Cookie("sessionID")

		if err != nil {
			if strings.Contains(err.Error(), "named cookie not present") {
				return context.String(http.StatusUnauthorized, "You don't have any cookie")
			}
			log.Printf("%v", err)
			return err
		}
		if cookie.Value == "some_string" {
			return next(context)
		}
		return context.String(http.StatusUnauthorized, "You don't have the right cookie")
	}
}

////////////////////////// middlewares //////////////////////////

func ServerHeader(next echo.HandlerFunc) echo.HandlerFunc {
	return func(context echo.Context) error {
		context.Response().Header().Set(echo.HeaderServer, "BlueBot/1.0")
		context.Response().Header().Set("notReallyHeader", "thisHasNoMeaning")
		return next(context)
	}
}

func main() {

	fmt.Printf("Ardit")

	e := echo.New()
	e.Use(ServerHeader)
	//g := e.Group("/admin",middleware.Logger())
	adminGroup := e.Group("/admin")
	cookieGroup := e.Group("/cookie")
	jwtGroup := e.Group("/jwt")

	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		Root:"../static",
	}))


	jwtGroup.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		SigningMethod: "HS512",
		SigningKey:    []byte("mySecret"),
		//heq si autorizim auth bear dhe ve ne header my dealder dhe ne vent te bear bendos iLoveDogs
		//TokenLookup:"header:MyHeader",
		//AuthScheme:"iLoveDogs",
		TokenLookup: "cookie:JWTCookie",
	}))
	cookieGroup.Use(checkCookie)


	adminGroup.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "[${time_rfc3339}] ${status} ${host}${path} ${latency_human} \n",
	}))
	adminGroup.Use(middleware.BasicAuth(func(username string, password string, context echo.Context) (bool, error) {
		//check in db
		if username == "jack" && password == "1234" {
			return true, nil
		}
		return false, nil
	}))

	adminGroup.GET("/main", mainAdmin)
	cookieGroup.GET("/main", mainCoocie)
	jwtGroup.GET("/main", mainJwt)

	e.GET("/yello", sayHi)
	e.GET("/login", login)
	e.GET("/cats/:data", getCat)
	e.POST("/cats", addCat)
	e.POST("/dogs", addDog)
	e.POST("/hamster", addHamster)
	e.Start(":8000")
}