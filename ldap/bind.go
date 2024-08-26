package ldap

/*
	Implements the Search request / response according to
	https://datatracker.ietf.org/doc/html/rfc4511#section-4.5
*/

// SearchReq is defined in https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1
/*
SearchRequest ::= [APPLICATION 3] SEQUENCE {
             baseObject      LDAPDN,
             scope           ENUMERATED {
                  baseObject              (0),
                  singleLevel             (1),
                  wholeSubtree            (2),
                  ...  },
             derefAliases    ENUMERATED {
                  neverDerefAliases       (0),
                  derefInSearching        (1),
                  derefFindingBaseObj     (2),
                  derefAlways             (3) },
             sizeLimit       INTEGER (0 ..  maxInt),
             timeLimit       INTEGER (0 ..  maxInt),
             typesOnly       BOOLEAN,
             filter          Filter,
             attributes      AttributeSelection }
*/
type SearchReq struct {
	BaseObject   string
	Scope        Scope
	DerefAliases DerefAliases
	SizeLimit    uint
	TimeLimit    uint
	TypesOnly    bool
	Filter       Filter
	Attributes   []Attrubute
}

type Scope int

const (
	BaseObject Scope = iota
	SingleLevel
	WholeSubtree
)

type DerefAliases int

const (
	NeverDerefAlises DerefAliases = iota
	DerefInSearching
	DerefFindingBaseObj
	DerefAlways
)

type Filter string
type Attribute string
type SearchReply struct {
}
