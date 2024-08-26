package main

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"reflect"
	"strconv"
	"strings"

	"gldap/db"

	"github.com/dbarney/ldap"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

//go:embed db/schema.sql
var ddl string

// DC stands for Domain Component. for example this would
// be the company url: example.com
type DC map[string]OU
type OU map[string]NC
type NC map[string]interface{}

func main() {
	ctx := context.Background()
	content, err := ioutil.ReadFile("storage.yaml")
	if err != nil {
		panic(err)
	}
	d := map[string]DC{}
	err = yaml.Unmarshal(content, &d)
	if err != nil {
		panic(err)
	}

	directory, err := sql.Open("sqlite3", "./directory.sqlite")
	if err != nil {
		panic(err)
	}

	// create tables
	if _, err := directory.ExecContext(ctx, ddl); err != nil {
		fmt.Println("sqlite err:", err)
	}

	queries := db.New(directory)

	// Now I need to populate the data I have read in
	fmt.Println("starting localhost:3389")
	s := ldap.NewServer()
	handler := ldapHandler{
		data: d,
		db:   queries,
	}
	s.BindFunc("", handler)
	s.SearchFunc("", handler)
	s.EnforceLDAP = true
	if err := s.ListenAndServe("localhost:3389"); err != nil {
		log.Fatal("LDAP Server Failed: %s", err.Error())
	}
}

type ldapHandler struct {
	data map[string]DC
	db   *db.Queries
}

func (h ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	ctx := context.Background()
	// DN cn=user,un=group,on=example,on=com  # can be anything
	// we need to split these out into their own strings
	split := strings.Split(bindDN, ",")
	components := map[string][]string{}

	for i := len(split) - 1; i >= 0; i-- {
		kvs := strings.Split(split[i], "=")
		if len(kvs) != 2 {
			return ldap.LDAPResultInvalidCredentials, nil
		}
		components[kvs[0]] = append(components[kvs[0]], kvs[1])
	}

	commonName := strings.Join(reverse(components["cn"]), ".")
	orgName := strings.Join(reverse(components["ou"]), ".")
	domainName := strings.Join(reverse(components["dc"]), ".")

	entry, err := h.db.FindOne(ctx, db.FindOneParams{
		Name:         commonName,
		Organization: orgName,
		Domain:       domainName,
	})
	if err != nil {
		fmt.Println("didn't find entry", err)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	attrs := map[string]interface{}{}

	err = json.Unmarshal([]byte(entry.Attributes), &attrs)
	if err != nil {
		fmt.Println("unable to parse attributes", err)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	if bindSimplePw == attrs["password"] {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}

func (h ldapHandler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	ctx := context.Background()
	/*
		//fmt.Println("BaseDN:", searchReq.BaseDN)
		fmt.Println("Scope:", ldap.ScopeMap[searchReq.Scope])
		fmt.Println("Deref:", ldap.DerefMap[searchReq.DerefAliases])
		fmt.Println("SizeLimit:", searchReq.SizeLimit)
		fmt.Println("TimeLimit:", searchReq.TimeLimit)
		fmt.Println("Types Only:", searchReq.TypesOnly)
		//fmt.Println("Filter:", searchReq.Filter)
		//fmt.Println("Attributes:", searchReq.Attributes)
		fmt.Println("Controls:", searchReq.Controls)
		fmt.Println("")
	*/
	split := strings.Split(searchReq.BaseDN, ",")
	components := map[string][]string{}

	for i := len(split) - 1; i >= 0; i-- {
		kvs := strings.Split(split[i], "=")
		if len(kvs) != 2 {
			return ldap.ServerSearchResult{[]*ldap.Entry{}, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
		}
		components[kvs[0]] = append(components[kvs[0]], kvs[1])
	}

	commonName := strings.Join(reverse(components["cn"]), ".")
	orgName := strings.Join(reverse(components["ou"]), ".")
	domainName := strings.Join(reverse(components["dc"]), ".")

	if commonName == "" {
		commonName = "%"
	}

	if orgName == "" {
		orgName = "%"
	}

	results, err := h.db.Search(ctx, db.SearchParams{
		Name:         commonName,
		Organization: orgName,
		Domain:       domainName,
	})
	if err != nil {
		return ldap.ServerSearchResult{[]*ldap.Entry{}, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
	}

	entries := []*ldap.Entry{}

	for _, result := range results {

		entry := &ldap.Entry{"cn=" + result.Name + "," + searchReq.BaseDN, []*ldap.EntryAttribute{}}
		values := map[string]interface{}{}
		err = json.Unmarshal([]byte(result.Attributes), &values)
		if err != nil {
			fmt.Println("unable to parse attributes", err)
		}
		if len(searchReq.Attributes) != -1 {
			for k, v := range values {
				entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{k, toSlice(v)})
			}
		} else {
			for _, name := range searchReq.Attributes {
				value, ok := values[name]
				if !ok {
					continue
				}
				entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{name, toSlice(value)})
			}
		}
		entries = append(entries, entry)
	}
	return ldap.ServerSearchResult{entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

func toSlice(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []string:
		return val
	case []interface{}:
		s := []string{}
		for _, value := range val {
			s = append(s, toSlice(value)...)
		}
		return s
	case int:
		return []string{strconv.Itoa(val)}
	case bool:
		if val {
			return []string{"true"}
		}
		return []string{"false"}
	default:
		fmt.Println("what am i?", reflect.TypeOf(val).String())
		return []string{}
	}
}
func reverse(s []string) []string {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}
