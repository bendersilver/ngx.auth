package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bendersilver/glog"
	"github.com/dchest/uniuri"
	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
)

const ttl = time.Hour * 24
const cookieName = "X-Auth"

var rdb *redis.Client
var ctx = context.Background()

func chekHash(h http.Header, q url.Values) error {
	dt, err := strconv.ParseInt(q.Get("auth_date"), 10, 64)
	if err != nil {
		return fmt.Errorf("no valid auth_date. %v", err)
	}
	if time.Now().UTC().Unix()-dt > 60*60*3 {
		return fmt.Errorf("hash expired")
	}

	var strs []string
	for k := range q {
		switch k {
		case "id", "auth_date", "first_name", "last_name", "username", "photo_url":
			strs = append(strs, fmt.Sprintf("%s=%s", k, q.Get(k)))
		}
	}
	sort.Strings(strs)
	sha := sha256.New()
	sha.Write([]byte(h.Get("X-Token")))
	hm := hmac.New(sha256.New, sha.Sum(nil))
	hm.Write([]byte(strings.Join(strs, "\n")))
	if q.Get("hash") == hex.EncodeToString(hm.Sum(nil)) {
		if rdb.Exists(ctx, q.Get("hash")).Val() == 1 {
			return fmt.Errorf("hash used")
		}
		return rdb.Set(ctx, q.Get("hash"), true, time.Hour*4).Err()
	}
	return fmt.Errorf("not valid hash")
}

func root(dir string) string {
	args := strings.Split(dir, "/")
	if len(args) > 1 {
		return args[1]
	}
	return "/"
}

func main() {
	glog.Info("start")
	opt, err := redis.ParseURL(os.Getenv("RDB_URL"))
	if err != nil {
		glog.Fatal(err)
	}
	rdb = redis.NewClient(opt)

	var s http.Server
	s.Addr = os.Getenv("HOST")
	s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uri, err := url.Parse(r.Header.Get("X-Uri"))
		if err != nil {
			glog.Error(err)
			w.WriteHeader(401)
			return
		}

		var uid string
		var dir = root(uri.Path)
		if uri.Query().Has("hash") {
			err = chekHash(r.Header, uri.Query())
			if err == nil {
				uid = uniuri.NewLen(128)
				err = rdb.Set(ctx, strings.Join([]string{r.Header.Get("X-Project"), dir, uid}, ":"), true, ttl).Err()
			}
			w.Header().Set("X-Redirect", uri.Path)
		} else if uri.Query().Has("tk") {
			// проверка строки
		} else {
			uid = r.Header.Get(cookieName)
			if uid == "" {
				var ck *http.Cookie
				ck, err = r.Cookie(cookieName)
				if err == nil {
					uid = ck.Value
				}
			}
			if uid != "" {
				err = rdb.Expire(ctx, strings.Join([]string{r.Header.Get("X-Project"), dir, uid}, ":"), ttl).Err()
			}
		}
		if err != nil {
			glog.Error(err)
			w.WriteHeader(401)
		} else {

			c := &http.Cookie{
				Name:     cookieName,
				Value:    uid,
				Path:     dir,
				Expires:  time.Now().Add(time.Hour * 24),
				Secure:   true,
				SameSite: http.SameSiteDefaultMode,
			}
			http.SetCookie(w, c)
			w.WriteHeader(200)
		}
	})
	glog.Critical(s.ListenAndServe())
}

func init() {
	if err := godotenv.Load(); err != nil {
		glog.Fatal(err)
	}
	for _, k := range []string{"RDB_URL", "HOST"} {
		if _, ok := os.LookupEnv(k); !ok {
			glog.Fatal("set environment variable", k)
		}
	}
}
