// +build ignore

// this code is based on https://github.com/markbates/goth/blob/master/examples/main.go

package main

import (
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/gplus"
	"github.com/markbates/goth/providers/lastfm"
	"github.com/markbates/goth/providers/linkedin"
	"github.com/markbates/goth/providers/spotify"
	"github.com/markbates/goth/providers/twitch"
	"github.com/markbates/goth/providers/twitter"
	"github.com/oov/gothic"
)

func main() {
	const BaseURL = "http://localhost:8000"
	goth.UseProviders(
		twitter.New(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), BaseURL+"/auth/twitter/callback"),
		facebook.New(os.Getenv("FACEBOOK_KEY"), os.Getenv("FACEBOOK_SECRET"), BaseURL+"/auth/facebook/callback"),
		gplus.New(os.Getenv("GPLUS_KEY"), os.Getenv("GPLUS_SECRET"), BaseURL+"/auth/gplus/callback"),
		github.New(os.Getenv("GITHUB_KEY"), os.Getenv("GITHUB_SECRET"), BaseURL+"/auth/github/callback"),
		spotify.New(os.Getenv("SPOTIFY_KEY"), os.Getenv("SPOTIFY_SECRET"), BaseURL+"/auth/spotify/callback"),
		linkedin.New(os.Getenv("LINKEDIN_KEY"), os.Getenv("LINKEDIN_SECRET"), BaseURL+"/auth/linkedin/callback"),
		lastfm.New(os.Getenv("LASTFM_KEY"), os.Getenv("LASTFM_SECRET"), BaseURL+"/auth/lastfm/callback"),
		twitch.New(os.Getenv("TWITCH_KEY"), os.Getenv("TWITCH_SECRET"), BaseURL+"/auth/twitch/callback"),
	)

	tpl := template.New("")
	template.Must(tpl.New("index.html").Parse(`
<p><a href="/auth/twitter">Log in with Twitter</a></p>
<p><a href="/auth/facebook">Log in with Facebook</a></p>
<p><a href="/auth/gplus">Log in with GPlus</a></p>
<p><a href="/auth/github">Log in with Github</a></p>
<p><a href="/auth/spotify">Log in with Spotify</a></p>
<p><a href="/auth/lastfm">Log in with LastFM</a></p>
<p><a href="/auth/twitch">Log in with Twitch</a></p>
`))
	template.Must(tpl.New("user.html").Parse(`
<p>Name: {{.Name}}</p>
<p>Email: {{.Email}}</p>
<p>NickName: {{.NickName}}</p>
<p>Location: {{.Location}}</p>
<p>AvatarURL: {{.AvatarURL}} <img src="{{.AvatarURL}}"></p>
<p>Description: {{.Description}}</p>
<p>UserID: {{.UserID}}</p>
<p>AccessToken: {{.AccessToken}}</p>
`))

	r := gin.Default()
	r.SetHTMLTemplate(tpl)
	r.GET("/auth/:provider", func(c *gin.Context) {
		err := gothic.BeginAuth(c.Param("provider"), c.Writer, c.Request)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
	})
	r.GET("/auth/:provider/callback", func(c *gin.Context) {
		user, err := gothic.CompleteAuth(c.Param("provider"), c.Writer, c.Request)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		c.HTML(http.StatusOK, "user.html", user)
	})
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})
	log.Fatal(r.Run(":8000"))
}
